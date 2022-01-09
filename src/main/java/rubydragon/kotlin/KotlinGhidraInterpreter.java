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

package rubydragon.kotlin;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import javax.script.SimpleScriptContext;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import rubydragon.GhidraInterpreter;

/**
 * A Kotlin intepreter for Ghidra.
 */
public class KotlinGhidraInterpreter extends GhidraInterpreter {
	private Thread replThread;
	private ScriptEngine engine;
	private BufferedReader replReader;
	private SimpleScriptContext context;

	/**
	 * Creates a new interpreter, with no input stream or REPL thread.
	 */
	public KotlinGhidraInterpreter() {
		// needed to avoid dll loading issues on Windows
		System.setProperty("idea.io.use.nio2", "true");

		context = new SimpleScriptContext();

		// ScriptEngineFactory factory = new KotlinJsr223JvmLocalScriptEngineFactory();
		// engine = factory.getScriptEngine();
		ScriptEngineManager scriptManager = new ScriptEngineManager();
		engine = scriptManager.getEngineByExtension("kts");
		engine.setContext(context);

		replThread = new Thread(() -> {
			while (true) {
				try {
					engine.eval(replReader.readLine());
				} catch (ScriptException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Creates a new interpreter, and ties the streams for the provided console to
	 * the new interpreter.
	 *
	 * @param console The console to bind to the interpreter streams.
	 */
	public KotlinGhidraInterpreter(InterpreterConsole console) {
		this();
		setStreams(console);
	}

	/**
	 * Should end the interpreter and release all resources. Currently does nothing.
	 */
	@Override
	public void dispose() {
		// do nothing
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
	 */
	@Override
	public void runScript(GhidraScript script, String[] scriptArguments, GhidraState scriptState)
			throws IllegalArgumentException, FileNotFoundException, IOException {
		ResourceFile scriptFile = script.getSourceFile();
		loadState(scriptState);

		// TODO implement

		updateState(scriptState);
	}

	/**
	 * Sets the error output stream for this interpreter.
	 */
	@Override
	public void setErrWriter(PrintWriter errOut) {
		context.setErrorWriter(errOut);
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
		context.setWriter(output);
	}

	/**
	 * Starts an interactive session with the current input/output/error streams.
	 */
	@Override
	public void startInteractiveSession() {
		replThread.start();
	}

	/**
	 * Updates the current address pointed to by the "ghidra/current-address"
	 * binding in the interpreter.
	 *
	 * @param address The new current address in the program.
	 */
	@Override
	public void updateAddress(Address address) {
		// TODO implement
	}

	/**
	 * Updates the highlighted selection pointed to by the
	 * "ghidra/current-highlight" variable.
	 *
	 * @param sel The new highlighted selection.
	 */
	@Override
	public void updateHighlight(ProgramSelection sel) {
		// TODO implement
	}

	/**
	 * Updates the location in the "ghidra/current-location" variable as well as the
	 * address in the "ghidra/current-address" variable.
	 *
	 * @param loc The new location in the program.
	 */
	@Override
	public void updateLocation(ProgramLocation loc) {
		// TODO implement
		if (loc != null) {
			updateAddress(loc.getAddress());
		}
	}

	/**
	 * Updates the program pointed to by the "ghidra/current-program" binding.
	 *
	 * @param program The new current program.
	 */
	@Override
	public void updateProgram(Program program) {
		engine.put("currentProgram", program);
	}

	/**
	 * Updates the selection pointed to by the "ghidra/current-selection" binding.
	 *
	 * @param sel The new selection.
	 */
	@Override
	public void updateSelection(ProgramSelection sel) {
		// TODO implement
	}

	/**
	 * Updates a state with the current selection/location/etc. variables from the
	 * interpreter.
	 *
	 * @param scriptState The state to update.
	 */
	@Override
	public void updateState(GhidraState scriptState) {
		// TODO implement
	}

}
