// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2022-2023 Joel E. Anderson
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
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import jdk.jshell.JShell;
import jdk.jshell.SnippetEvent;
import jdk.jshell.SourceCodeAnalysis;
import jdk.jshell.execution.LocalExecutionControlProvider;
import rubydragon.DragonPlugin;
import rubydragon.GhidraInterpreter;

/**
 * A Java interpreter for Ghidra, based on JShell.
 */
public class JShellGhidraInterpreter extends GhidraInterpreter {
	// simple structure to store both the type and value in a single map entry
	private record Variable(Class<?> type, Object value) {
	}

	private Map<String, Variable> setVariables = new HashMap<String, Variable>();

	public static AtomicInteger counter = new AtomicInteger();
	public static ConcurrentHashMap<Integer, Object> variables = new ConcurrentHashMap<Integer, Object>();

	private Thread replThread;
	private JShell jshell;
	private InputStream inStream;
	private BufferedReader replReader;
	private OutputStream outStream;
	private PrintWriter outWriter;
	private OutputStream errStream;
	private PrintWriter errWriter;
	private DragonPlugin parentPlugin;
	private boolean disposed = false;

	private Runnable replLoop = () -> {
		initInteractiveInterpreterWithProgress(outWriter, errWriter);

		while (!disposed) {
			try {
				StringBuilder completeSnippet = new StringBuilder();
				SourceCodeAnalysis analyzer = jshell.sourceCodeAnalysis();
				SourceCodeAnalysis.CompletionInfo ci;
				SourceCodeAnalysis.Completeness c;
				do {
					String snippet = replReader.readLine();
					completeSnippet.append(snippet);
					ci = analyzer.analyzeCompletion(completeSnippet.toString());
					c = ci.completeness();
				} while (c != SourceCodeAnalysis.Completeness.COMPLETE && c != SourceCodeAnalysis.Completeness.UNKNOWN);
				List<SnippetEvent> events = jshell.eval(completeSnippet.toString());
				for (SnippetEvent e : events) {
					handleSnippetEvent(e);
				}
			} catch (IllegalStateException | IOException e) {
				// if these occur, we just keep going
				// the user is expected to reset the interpreter if it gets truly stuck
				continue;
			}
			outWriter.flush();
			errWriter.flush();
		}

		jshell.close();
	};

	/**
	 * Creates a new interpreter, and ties the given streams to the new interpreter.
	 *
	 * @param in           The input stream to use for the interpeter.
	 * @param out          The output stream to use for the interpreter.
	 * @param err          The error stream to use for the interpreter.
	 * @param parentPlugin The DragonPlugin instance owning this interpreter.
	 */
	public JShellGhidraInterpreter(InputStream in, OutputStream out, OutputStream err, DragonPlugin parentPlugin) {
		inStream = in;
		outStream = out;
		errStream = err;
		this.parentPlugin = parentPlugin;

		setInput(inStream);
		setOutWriter(new PrintWriter(outStream));
		setErrWriter(new PrintWriter(errStream));

		replThread = new Thread(replLoop);
	}

	/**
	 * Creates a new interpreter, and ties the streams for the provided console to
	 * the new interpreter.
	 *
	 * @param console      The console to bind to the interpreter streams.
	 * @param parentPlugin The DragonPlugin instance owning this interpreter.
	 */
	public JShellGhidraInterpreter(InterpreterConsole console, DragonPlugin parentPlugin) {
		this(console.getStdin(), console.getStdOut(), console.getStdErr(), parentPlugin);
	}

	/**
	 * Creates a new JShell interpreter, and declares the internal variables.
	 *
	 * @since 3.1.0
	 */
	@Override
	public void initInteractiveInterpreter() {
		PrintStream outPrintStream = new PrintStream(outStream);
		PrintStream errPrintStream = new PrintStream(errStream);

		JShell.Builder builder = JShell.builder();
		builder.out(outPrintStream);
		builder.err(errPrintStream);
		builder.executionEngine(new LocalExecutionControlProvider(), new HashMap<String, String>());
		jshell = builder.build();

		// declare the built-in variables
		jshell.eval(String.format("%s currentAddress = null;", Address.class.getName()));
		jshell.eval(String.format("%s currentAPI = null;", FlatProgramAPI.class.getName()));
		jshell.eval(String.format("%s currentHighlight = null;", ProgramSelection.class.getName()));
		jshell.eval(String.format("%s currentLocation = null;", ProgramLocation.class.getName()));
		jshell.eval(String.format("%s currentProgram = null;", Program.class.getName()));
		jshell.eval(String.format("%s currentSelection = null;", ProgramSelection.class.getName()));

		// set any variables that were provided before creation
		setVariables.forEach((name, var) -> {
			setVariableInJShell(name, var.type, var.value);
		});
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
	 * @param cmd The beginning of a command to try to complete.
	 *
	 * @return A list of possible code completions.
	 */
	public List<CodeCompletion> getCompletions(String cmd) {
		List<CodeCompletion> result = new ArrayList<CodeCompletion>();
		int[] anchor = new int[1];
		List<SourceCodeAnalysis.Suggestion> suggestions;

		SourceCodeAnalysis analyzer = jshell.sourceCodeAnalysis();
		suggestions = analyzer.completionSuggestions(cmd, cmd.length(), anchor);
		for (SourceCodeAnalysis.Suggestion s : suggestions) {
			String c = s.continuation();

			int commonLength = cmd.length() - anchor[0];
			String added = "";
			if (cmd.substring(anchor[0]).equals(c.substring(0, commonLength))) {
				added = c.substring(commonLength);
			}
			CodeCompletion completion = new CodeCompletion(c, added, null);
			result.add(completion);
		}

		return result;
	}

	/**
	 * The DragonPlugin that this interpreter is attached to.
	 *
	 * @return The owning plugin of this interpreter.
	 *
	 * @since 3.1.0
	 */
	@Override
	public DragonPlugin getParentPlugin() {
		return parentPlugin;
	}

	/**
	 * Get the version of Java this JShell supports.
	 *
	 * @return A string with the version of the interpreter.
	 *
	 * @since 3.1.0
	 */
	@Override
	public String getVersion() {
		return "JShell " + Runtime.version().toString();
	}

	/**
	 * Prints a status message to the console for the given event.
	 *
	 * @param e The SnippetEvent to report a status for.
	 */
	private void handleSnippetEvent(SnippetEvent e) {
		if (e.causeSnippet() == null) {
			switch (e.status()) {
			case RECOVERABLE_DEFINED:
				errWriter.println("jshell snippet failed: RECOVERABLE_DEFINED");
				break;
			case RECOVERABLE_NOT_DEFINED:
				errWriter.println("jshell snippet failed: RECOVERABLE_NOT_DEFINED");
				break;
			case REJECTED:
				errWriter.println("jshell snippet failed");
				break;
			default:
				if (e.value() != null) {
					outWriter.println(e.value());
				}
				break;
			}
		}
	}

	/**
	 * Imports a given class into the interpreter.
	 *
	 * @param packageName The name of the package the class is in.
	 * @param className   The name of the class to import.
	 *
	 * @since 3.1.0
	 */
	@Override
	public void importClass(String packageName, String className) {
		if (jshell != null) {
			String importStatement = "import " + className + ";";
			jshell.eval(importStatement);
		}
	}

	/**
	 * Interrupts this interpreter.
	 */
	public void interrupt() {
		jshell.stop();
	}

	/**
	 * Resets this interpreter.
	 */
	public void reset() {
		jshell.close();
		initInteractiveInterpreter();
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
	 * Adds or updates the variable with the given name to the given value in the
	 * interpreter.
	 *
	 * @param name  The name of the variable to create or update.
	 * @param value The value of the variable to add.
	 *
	 * @since 3.1.0
	 */
	public void setVariable(String name, Object value) {
		setVariable(name, value.getClass(), value);
	}

	/**
	 * Sets an existing variable with the given name to the given value and class.
	 *
	 * @param name  The name of the variable.
	 * @param type  The type of the variable.
	 * @param value The new value of the variable.
	 */
	private void setVariable(String name, Class<?> type, Object value) {
		setVariables.put(name, new Variable(type, value));

		if (jshell != null) {
			setVariableInJShell(name, type, value);
		}
	}

	/**
	 * Sets an existing variable with the given name to the given value and class.
	 * This method assumes that the interpreter has already been created.
	 *
	 * @param name  The name of the variable.
	 * @param type  The type of the variable.
	 * @param value The new value of the variable.
	 */
	private void setVariableInJShell(String name, Class<?> type, Object value) {
		Integer varId = counter.incrementAndGet();
		variables.put(varId, value);
		String command = String.format("%s = (%s) %s.variables.get(%d)", name, type.getName(),
				this.getClass().getName(), varId);
		jshell.eval(command);
		variables.remove(varId);
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
			setVariable(getCurrentAddressName(), Address.class, address);
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
			setVariable(getCurrentHighlightName(), ProgramSelection.class, sel);
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
			setVariable(getCurrentLocationName(), ProgramLocation.class, loc);
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
			setVariable(getCurrentProgramName(), Program.class, program);
			setVariable(getCurrentAPIName(), FlatProgramAPI.class, new FlatProgramAPI(program));
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
			setVariable(getCurrentSelectionName(), ProgramSelection.class, sel);
		}
	}

}
