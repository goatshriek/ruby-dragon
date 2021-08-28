// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2021 Joel E. Anderson
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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;

import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Disposable;

/**
 * An interpreter that users can use interactively as well as to run custom
 * scripts.
 */
public abstract class GhidraInterpreter implements Disposable {

	/**
	 * Cleans up all resources for this intepreter.
	 */
	public abstract void dispose();

	/**
	 * Loads a provided GhidraState into the interpreter.
	 *
	 * @param state The state to load.
	 */
	public void loadState(GhidraState state) {
		updateHighlight(state.getCurrentHighlight());
		updateLocation(state.getCurrentLocation());
		updateSelection(state.getCurrentSelection());
		updateProgram(state.getCurrentProgram());

		// this has to happen after the location update
		// since it clobbers the current address right now
		updateAddress(state.getCurrentAddress());
	}

	/**
	 * Runs the given script with the arguments and state provided.
	 *
	 * The provided state is loaded into the interpreter at the beginning of
	 * execution, and the values of the globals are then exported back into the
	 * state after it completes.
	 *
	 * If the script cannot be found but the script is not running in headless mode,
	 * the user will be prompted to ignore the error, which will cause the function
	 * to simply continue instead of throwing an IllegalArgumentException.
	 *
	 * @throws IllegalArgumentException if the script does not exist
	 * @throws IOException              if the script could not be read
	 * @throws FileNotFoundException    if the script file wasn't found
	 *
	 * @param script          The script to run.
	 *
	 * @param scriptArguments The arguments to pass to the script.
	 *
	 * @param scriptState     The script to load before the script runs, and update
	 *                        after the script finishes.
	 */
	public abstract void runScript(GhidraScript script, String[] scriptArguments, GhidraState scriptState)
			throws IllegalArgumentException, FileNotFoundException, IOException;

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
	 * Starts an interactive session with the current input/output/error streams.
	 */
	public abstract void startInteractiveSession();

	/**
	 * Updates the current address in the interpreter.
	 *
	 * @param address The new current address in the program.
	 */
	public abstract void updateAddress(Address address);

	/**
	 * Updates the highlighted selection pointed to by the current_highlight
	 * variable.
	 *
	 * @param sel The new highlighted selection.
	 */
	public abstract void updateHighlight(ProgramSelection sel);

	/**
	 * Updates the location in the current location variable as well as the address
	 * in the current address variable.
	 *
	 * @param loc The new location in the program.
	 */
	public abstract void updateLocation(ProgramLocation loc);

	/**
	 * Updates the current program in current program to the one provided.
	 *
	 * @param program The new current program.
	 */
	public abstract void updateProgram(Program program);

	/**
	 * Updates the selection pointed to by the current selection variable.
	 *
	 * @param sel The new selection.
	 */
	public abstract void updateSelection(ProgramSelection sel);

	/**
	 * Updates a state with the current selection/location/etc. variables from the
	 * interpreter.
	 *
	 * This is intended to be called after a call to runScript, to make sure that
	 * any updates made to these variables during execution are reflected in the end
	 * state.
	 *
	 * @param scriptState The state to update.
	 */
	public abstract void updateState(GhidraState scriptState);
}
