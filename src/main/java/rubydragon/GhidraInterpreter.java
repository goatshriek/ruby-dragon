// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2021-2022 Joel E. Anderson
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package rubydragon;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.List;

import org.jdom.JDOMException;

import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Disposable;

/**
 * An interpreter that users can use interactively.
 *
 * This class provides a common base that all interpreters should implement in
 * order to fit in to the overall system. It provides a common wrapper around
 * the language-specific internals of a given language environment.
 *
 * Interpreters that also support scripts should inherit from
 * ScriptableGhidraInterpreter instead.
 */
public abstract class GhidraInterpreter implements Disposable {

	public void autoImportClasses(PrintWriter output, PrintWriter errOut) {
		DragonPlugin parentPlugin = getParentPlugin();
		boolean preloadEnabled = parentPlugin != null && parentPlugin.isAutoImportEnabled();
		if (preloadEnabled) {
			long startTime = System.currentTimeMillis();
			output.append("starting auto-import...\n");
			output.flush();

			String loadError = null;
			try {
				DragonPlugin.forEachAutoImport((packageName, className) -> {
					importClass(packageName, className);
				});
			} catch (JDOMException | IOException e) {
				loadError = "could not auto-import classes: " + e.getMessage() + "\n";
			}

			if (loadError != null) {
				errOut.append(loadError);
				errOut.flush();
			}
			long endTime = System.currentTimeMillis();
			double importTime = (endTime - startTime) / 1000.0;
			output.append(String.format("auto-imported finished (%.3f seconds)\n", importTime));
			output.flush();
		} else {
			output.append("auto-import disabled.\n");
			output.flush();
		}
	}

	/**
	 * Cleans up all resources for this intepreter.
	 */
	public abstract void dispose();

	/**
	 * Get a list of completions for the given command prefix.
	 *
	 * @param cmd The command to try to complete.
	 *
	 * @return A list of possible code completions.
	 */
	public abstract List<CodeCompletion> getCompletions(String cmd);

	public String getCurrentAddressName() {
		return "currentAddress";
	}

	public String getCurrentAPIName() {
		return "currentAPI";
	}

	public String getCurrentHighlightName() {
		return "currentHighlight";
	}

	public String getCurrentLocationName() {
		return "currentLocation";
	}

	public String getCurrentProgramName() {
		return "currentProgram";
	}

	public String getCurrentSelectionName() {
		return "currentSelection";
	}

	public abstract DragonPlugin getParentPlugin();

	/**
	 * Get the version of this interpreter.
	 *
	 * @return A string with the version of the interpreter.
	 */
	public abstract String getVersion();

	public abstract void importClass(String packageName, String className);

	public abstract void initInteractiveInterpreter();

	public void initInteractiveInterpreterWithProgress(PrintWriter output, PrintWriter errOut) {
		long startTime = System.currentTimeMillis();
		output.append("starting " + getVersion() + "\n");
		output.flush();
		initInteractiveInterpreter();
		autoImportClasses(output, errOut);
		long endTime = System.currentTimeMillis();
		double loadTime = (endTime - startTime) / 1000.0;
		output.append(String.format("startup finished (%.3f seconds)\n", loadTime));
		output.flush();
	}

	/**
	 * Sets the error output stream for this interpreter.
	 *
	 * @param errOut The new error output stream to use for the interpreter.
	 */
	public abstract void setErrWriter(PrintWriter errOut);

	/**
	 * Sets the input stream for this interpreter.
	 *
	 * @param input The new input stream to use for the interpreter.
	 */
	public abstract void setInput(InputStream input);

	/**
	 * Sets the output stream for this interpreter.
	 *
	 * @param output The new output stream to use for the interpreter.
	 */
	public abstract void setOutWriter(PrintWriter output);

	/**
	 * Sets the input, output, and error streams for this interpreter to those of
	 * the provided console.
	 *
	 * @param console The console to tie the interpreter streams to.
	 */
	public void setStreams(InterpreterConsole console) {
		setInput(console.getStdin());
		setOutWriter(console.getOutWriter());
		setErrWriter(console.getErrWriter());
	}

	/**
	 * Adds or updates the variable with the given name to the given value in the
	 * interpreter.
	 *
	 * @param name  The name of the variable to create or update.
	 * @param value The value of the variable to add.
	 */
	public abstract void setVariable(String name, Object value);

	/**
	 * Starts an interactive session with the current input/output/error streams.
	 */
	public abstract void startInteractiveSession();

	/**
	 * Updates the current address in the interpreter.
	 *
	 * @param address The new current address in the program.
	 */
	public void updateAddress(Address address) {
		setVariable(getCurrentAddressName(), address);
	}

	/**
	 * Updates the highlighted selection pointed to by the current_highlight
	 * variable.
	 *
	 * @param sel The new highlighted selection.
	 */
	public void updateHighlight(ProgramSelection sel) {
		if (sel != null) {
			setVariable(getCurrentHighlightName(), sel);
		}
	}

	/**
	 * Updates the location in the current location variable as well as the address
	 * in the current address variable.
	 *
	 * @param loc The new location in the program.
	 */
	public void updateLocation(ProgramLocation loc) {
		if (loc != null) {
			setVariable(getCurrentLocationName(), loc);
			updateAddress(loc.getAddress());
		}
	}

	/**
	 * Updates the current program in current program to the one provided.
	 *
	 * @param program The new current program.
	 */
	public void updateProgram(Program program) {
		if (program != null) {
			setVariable(getCurrentProgramName(), program);
			setVariable(getCurrentAPIName(), new FlatProgramAPI(program));
		}
	}

	/**
	 * Updates the selection pointed to by the current selection variable.
	 *
	 * @param sel The new selection.
	 */
	public void updateSelection(ProgramSelection sel) {
		setVariable(getCurrentSelectionName(), sel);
	}
}
