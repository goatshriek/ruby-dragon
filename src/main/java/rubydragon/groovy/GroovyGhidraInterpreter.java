// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2022 Joel E. Anderson
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

package rubydragon.groovy;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import org.codehaus.groovy.control.CompilerConfiguration;

import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import groovy.lang.GroovyRuntimeException;
import groovy.lang.GroovyShell;
import rubydragon.ScriptableGhidraInterpreter;

/**
 * A Kotlin intepreter for Ghidra.
 */
public class GroovyGhidraInterpreter extends ScriptableGhidraInterpreter {

	private Thread replThread;
	private GroovyShell shell;
	private InputStream inStream;
	private BufferedReader replReader;
	private OutputStream outStream;
	private PrintWriter outWriter;
	private OutputStream errStream;
	private PrintWriter errWriter;
	private boolean disposed = false;

	private Runnable inputThread = () -> {
		while (!disposed) {
			String snippet = "";
			try {
				snippet = replReader.readLine();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			try {
				Object result = shell.evaluate(snippet);
				outWriter.println(result.toString());
				outWriter.flush();
			} catch (GroovyRuntimeException e) {
				errWriter.println(e.getMessage());
				errWriter.flush();
			}
		}

		shell = null;
	};

	/**
	 * Creates a new Groovy interpreter.
	 */
	public GroovyGhidraInterpreter() {
		this(false);
	}

	/**
	 * Creates a new Groovy interpreter.
	 *
	 * @param scriptable
	 */
	public GroovyGhidraInterpreter(boolean scriptable) {
		if (scriptable) {
			createScriptableShell();
		} else {
			createShell();
		}
		replThread = new Thread(inputThread);
	}

	/**
	 * Creates a new interpreter, and ties the given streams to the new interpreter.
	 *
	 * @param in  The input stream to use for the interpeter.
	 * @param out The output stream to use for the interpreter.
	 * @param err The error stream to use for the interpreter.
	 */
	public GroovyGhidraInterpreter(InputStream in, OutputStream out, OutputStream err) {
		inStream = in;
		outStream = out;
		errStream = err;

		setInput(inStream);
		setOutWriter(new PrintWriter(outStream));
		setErrWriter(new PrintWriter(errStream));

		createShell();
		replThread = new Thread(inputThread);
	}

	/**
	 * Creates a new interpreter, and ties the streams for the provided console to
	 * the new interpreter.
	 *
	 * @param console The console to bind to the interpreter streams.
	 */
	public GroovyGhidraInterpreter(InterpreterConsole console) {
		this(console.getStdin(), console.getStdOut(), console.getStdErr());
	}

	/**
	 * Creates a new Groovy intepreter for scripts.
	 */
	private void createScriptableShell() {
		CompilerConfiguration config = new CompilerConfiguration();
		config.setScriptBaseClass(GroovyScript.class.getName());
		shell = new GroovyShell(config);
	}

	/**
	 * Creates a new Groovy interpreter for interactive sessions.
	 */
	private void createShell() {
		CompilerConfiguration config = new CompilerConfiguration();
		config.setScriptBaseClass(FlatProgramAPI.class.getName());
		shell = new GroovyShell();
	}

	/**
	 * Should end the interpreter and release all resources.
	 */
	@Override
	public void dispose() {
		disposed = true;
	}

	/**
	 * Get a list of completions for the given command prefix.
	 *
	 * Currently not implemented, and will always return an empty list.
	 *
	 * @param cmd The beginning of a command to try to complete.
	 *
	 * @return A list of possible code completions.
	 */
	public List<CodeCompletion> getCompletions(String cmd) {
		return new ArrayList<CodeCompletion>();
	}

	/**
	 * Resets this interpreter.
	 */
	public void reset() {
		createShell();
	}

	@Override
	public void runScript(GhidraScript script, String[] scriptArguments, GhidraState scriptState)
			throws IllegalArgumentException, FileNotFoundException, IOException {
		loadState(scriptState);
		shell.run(script.getSourceFile().getFile(true), scriptArguments);
		updateState(scriptState);
	}

	/**
	 * Sets the error output stream for this interpreter.
	 */
	@Override
	public void setErrWriter(PrintWriter errOut) {
		errWriter = errOut;
	}

	/**
	 * Sets the input stream for this interpreter.
	 */
	@Override
	public void setInput(InputStream input) {
		replReader = new BufferedReader(new InputStreamReader(input));
	}

	/**
	 * Sets the output stream for this interpreter.
	 */
	@Override
	public void setOutWriter(PrintWriter output) {
		outWriter = output;
	}

	/**
	 * Starts an interactive session with the current input/output/error streams.
	 */
	@Override
	public void startInteractiveSession() {
		replThread.start();
	}

	/**
	 * Updates the current address pointed to by the "currentAddress" binding in the
	 * interpreter.
	 *
	 * @param address The new current address in the program.
	 */
	@Override
	public void updateAddress(Address address) {
		if (address != null) {
			shell.setVariable("currentAddress", address);
		}
	}

	/**
	 * Updates the highlighted selection pointed to by the "currentHighlight"
	 * variable.
	 *
	 * @param sel The new highlighted selection.
	 */
	@Override
	public void updateHighlight(ProgramSelection sel) {
		if (sel != null) {
			shell.setVariable("currentHighlight", sel);
		}
	}

	/**
	 * Updates the location in the "currentLocation" variable as well as the address
	 * in the "ghidra/current-address" variable.
	 *
	 * @param loc The new location in the program.
	 */
	@Override
	public void updateLocation(ProgramLocation loc) {
		if (loc != null) {
			shell.setVariable("currentLocation", loc);
			updateAddress(loc.getAddress());
		}
	}

	/**
	 * Updates the program pointed to by the "currentProgram" binding.
	 *
	 * @param program The new current program.
	 */
	@Override
	public void updateProgram(Program program) {
		if (program != null) {
			shell.setVariable("currentProgram", program);
			shell.setVariable("currentAPI", new FlatProgramAPI(program));
		}
	}

	/**
	 * Updates the selection pointed to by the "currentSelection" binding.
	 *
	 * @param sel The new selection.
	 */
	@Override
	public void updateSelection(ProgramSelection sel) {
		if (sel != null) {
			shell.setVariable("currentSelection", sel);
		}
	}

	/**
	 * Updates a state with the current selection/location/etc. variables from the
	 * interpreter.
	 *
	 * @param scriptState The state to update.
	 */
	@Override
	public void updateState(GhidraState scriptState) {
		Program currentProgram = (Program) shell.getVariable("currentProgram");
		scriptState.setCurrentProgram(currentProgram);

		ProgramLocation programLoc = (ProgramLocation) shell.getVariable("currentLocation");
		scriptState.setCurrentLocation(programLoc);

		Address addr = (Address) shell.getVariable("currentAddress");
		scriptState.setCurrentAddress(addr);

		ProgramSelection highlight = (ProgramSelection) shell.getVariable("currentHighlight");
		scriptState.setCurrentHighlight(highlight);

		ProgramSelection sel = (ProgramSelection) shell.getVariable("currentSelection");
		scriptState.setCurrentSelection(sel);
	}

}
