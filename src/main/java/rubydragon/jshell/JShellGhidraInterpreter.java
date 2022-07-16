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

package rubydragon.jshell;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import jdk.jshell.JShell;
import jdk.jshell.Snippet;
import jdk.jshell.SnippetEvent;
import jdk.jshell.execution.LocalExecutionControlProvider;
import rubydragon.GhidraInterpreter;

/**
 * A Kotlin intepreter for Ghidra.
 */
public class JShellGhidraInterpreter extends GhidraInterpreter {
	public static AtomicInteger counter = new AtomicInteger();
	public static ConcurrentHashMap<Integer, Object> variables = new ConcurrentHashMap<Integer, Object>();

	private Thread replThread;
	private BufferedReader replReader;
	private JShell jshell;

	/**
	 * Creates a new interpreter, and ties the streams for the provided console to
	 * the new interpreter.
	 *
	 * @param console The console to bind to the interpreter streams.
	 */
	public JShellGhidraInterpreter(InterpreterConsole console) {
		JShell.Builder builder = JShell.builder();
		builder.out(new PrintStream(console.getStdOut()));
		// builder.in(console.getStdin());
		builder.err(new PrintStream(console.getStdErr()));
		builder.executionEngine(new LocalExecutionControlProvider(), new HashMap<String, String>());
		jshell = builder.build();

		jshell.eval("ghidra.program.model.address.Address currentAddress = null;");

		setStreams(console);

		replThread = new Thread(() -> {
			while (replReader != null) {
				try {
					System.out.println("started eval");
					List<SnippetEvent> events = jshell.eval(replReader.readLine());
					System.out.println("eval returned");

					for (SnippetEvent e : events) {
						StringBuilder sb = new StringBuilder();
						if (e.causeSnippet() == null) {
							// We have a snippet creation event
							switch (e.status()) {
							case VALID:
								sb.append("Successful ");
								break;
							case RECOVERABLE_DEFINED:
								sb.append("With unresolved references ");
								break;
							case RECOVERABLE_NOT_DEFINED:
								sb.append("Possibly reparable, failed  ");
								break;
							case REJECTED:
								sb.append("Failed ");
								break;
							}
							if (e.previousStatus() == Snippet.Status.NONEXISTENT) {
								sb.append("addition");
							} else {
								sb.append("modification");
							}
							sb.append(" of ");
							sb.append(e.snippet().source());
							System.out.println(sb);
							console.getOutWriter().print(sb);
							if (e.value() != null) {
								console.getOutWriter().printf("Value is: %s\n", e.value());
							}
							console.getOutWriter().flush();
						}
					}
				} catch (IllegalStateException e) {
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
	 * Should end the interpreter and release all resources.
	 */
	@Override
	public void dispose() {
		replReader = null;
	}

	/**
	 * Does nothing, since this interpeter is only for interactive sessions and
	 * doesn't support scripts.
	 *
	 * This is a sign that the parent class should probably be refactored so that a
	 * nullsub like this doesn't need to exist.
	 *
	 * @param script          The script to run.
	 *
	 * @param scriptArguments The arguments to pass to the script.
	 *
	 * @param scriptState     The script to load before the script runs, and update
	 *                        after the script finishes.
	 */
	@Override
	public void runScript(GhidraScript script, String[] scriptArguments, GhidraState scriptState) {
		return;
	}

	/**
	 * Sets the error output stream for this interpreter.
	 */
	@Override
	public void setErrWriter(PrintWriter errOut) {
		return;
	}

	/**
	 * Sets the input stream for this interpreter.
	 */
	@Override
	public void setInput(InputStream input) {
		System.out.println("input set");
		replReader = new BufferedReader(new InputStreamReader(input));
	}

	/**
	 * Sets the output stream for this interpreter.
	 */
	@Override
	public void setOutWriter(PrintWriter output) {
		return;
	}

	/**
	 * Starts an interactive session with the current input/output/error streams.
	 */
	@Override
	public void startInteractiveSession() {
		replThread.start();
		System.out.println("repl started");
	}

	/**
	 * Updates the current address pointed to by the "currentAddress" binding in the
	 * interpreter.
	 *
	 * @param address The new current address in the program.
	 */
	@Override
	public void updateAddress(Address address) {
		System.out.println("current address updated!");
		if (address != null) {
			Integer varId = counter.incrementAndGet();
			variables.put(varId, address);
			String command = String.format("currentAddress = (%s) %s.variables.get(%d)", Address.class.getName(),
					this.getClass().getName(), varId);
			jshell.eval(command);
			variables.remove(varId);
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
		// if (sel != null) {
		// engine.put("currentHighlight", sel);
		// }
		return;
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
			// engine.put("currentLocation", loc);
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
//		if (program != null) {
//			engine.put("currentProgram", program);
//		}
		return;
	}

	/**
	 * Updates the selection pointed to by the "currentSelection" binding.
	 *
	 * @param sel The new selection.
	 */
	@Override
	public void updateSelection(ProgramSelection sel) {
//		if (sel != null) {
//			engine.put("currentSelection", sel);
//		}
		return;
	}

	/**
	 * Updates a state with the current selection/location/etc. variables from the
	 * interpreter.
	 *
	 * Ignored because this interpreter doesn't do scripts.
	 *
	 * @param scriptState The state to update.
	 */
	@Override
	public void updateState(GhidraState scriptState) {
		return;
	}

}
