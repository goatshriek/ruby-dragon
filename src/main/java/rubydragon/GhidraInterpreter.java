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

import java.io.InputStream;
import java.io.PrintWriter;
import java.util.List;

import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
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
}
