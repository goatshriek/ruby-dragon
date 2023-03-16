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

package rubydragon.groovy;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.apache.groovy.groovysh.Groovysh;
import org.apache.groovy.groovysh.util.DefaultCommandsRegistrar;
import org.apache.groovy.groovysh.util.XmlCommandRegistrar;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.codehaus.groovy.control.customizers.ImportCustomizer;
import org.codehaus.groovy.tools.shell.IO;
import org.jdom.JDOMException;

import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import groovy.lang.Binding;
import groovy.lang.Closure;
import groovy.lang.GroovyShell;
import rubydragon.DragonPlugin;
import rubydragon.ScriptableGhidraInterpreter;

/**
 * A Groovy intepreter for Ghidra.
 */
public class GroovyGhidraInterpreter extends ScriptableGhidraInterpreter {

	private Thread replThread;
	private Groovysh interactiveShell;
	private Binding interactiveBinding;
	private GroovyShell scriptShell;
	private InputStream inStream;
	private BufferedReader replReader;
	private OutputStream outStream;
	private PrintWriter outWriter;
	private OutputStream errStream;
	private PrintWriter errWriter;
	private boolean disposed = false;
	private DragonPlugin parentPlugin;

	private Runnable replLoop = () -> {
		while (!disposed) {
			interactiveShell.run("");
		}
	};

	/**
	 * Creates a new Groovy interpreter.
	 */
	public GroovyGhidraInterpreter() {
		replThread = new Thread(replLoop);
		parentPlugin = null;
	}

	/**
	 * Creates a new interpreter, and ties the given streams to the new interpreter.
	 *
	 * @param in  The input stream to use for the interpeter.
	 * @param out The output stream to use for the interpreter.
	 * @param err The error stream to use for the interpreter.
	 */
	public GroovyGhidraInterpreter(InputStream in, OutputStream out, OutputStream err, DragonPlugin plugin) {
		inStream = in;
		outStream = out;
		errStream = err;
		parentPlugin = plugin;

		setInput(inStream);
		setOutWriter(new PrintWriter(outStream));
		setErrWriter(new PrintWriter(errStream));

		createInteractiveShell(in, out, err);
		replThread = new Thread(replLoop);
	}

	/**
	 * Creates a new interpreter, and ties the streams for the provided console to
	 * the new interpreter.
	 *
	 * @param console The console to bind to the interpreter streams.
	 * @param plugin  The DragonPlugin instance owning this interpreter.
	 */
	public GroovyGhidraInterpreter(InterpreterConsole console, DragonPlugin plugin) {
		this(console.getStdin(), console.getStdOut(), console.getStdErr(), plugin);
	}

	/**
	 * Creates a new Groovy shell to run scripts.
	 */
	private void createScriptableShell() {
		scriptShell = new GroovyShell();
	}

	/**
	 * Creates a new Groovy interpreter for interactive sessions.
	 */
	private void createInteractiveShell(InputStream in, OutputStream out, OutputStream err) {
		ClassLoader classLoader = Thread.currentThread().getContextClassLoader();

		// this is the default registrar closure from the groovy source
		@SuppressWarnings({ "serial", "rawtypes" })
		Closure registrar = new Closure(null) {
			@SuppressWarnings("unused")
			public void doCall(Groovysh shell) {
				URL xmlCommandResource = getClass().getResource("commands.xml");
				if (xmlCommandResource != null) {
					XmlCommandRegistrar r = new XmlCommandRegistrar(shell, classLoader);
					r.register(xmlCommandResource);
				} else {
					new DefaultCommandsRegistrar(shell).register();
				}
			}
		};
		IO shellIo = new IO(in, out, err);
		interactiveBinding = new Binding();
		CompilerConfiguration cc = new CompilerConfiguration();

		// load the preload imports if enabled
		boolean preloadEnabled = parentPlugin != null && parentPlugin.isAutoImportEnabled();
		if (preloadEnabled) {
			ImportCustomizer ic = new ImportCustomizer();
			try {
				DragonPlugin.forEachAutoImport((packageName, className) -> {
					ic.addImport(className, packageName + "." + className);
				});
			} catch (JDOMException | IOException e) {
				errWriter.append("could not load auto-import classes: " + e.getMessage() + "\n");
			}
			cc.addCompilationCustomizers(ic);
		}

		interactiveShell = new Groovysh(classLoader, interactiveBinding, shellIo, registrar, cc);
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
	 * Loads a provided GhidraState into the script interpreter.
	 *
	 * @param state The state to load.
	 */
	@Override
	public void loadState(GhidraState state) {
		// we overload this to make sure that the state is loaded into the script
		// interpreter instead of the interactive one
		scriptShell.setVariable("currentHighlight", state.getCurrentHighlight());
		scriptShell.setVariable("currentLocation", state.getCurrentLocation());
		scriptShell.setVariable("currentSelection", state.getCurrentSelection());
		scriptShell.setVariable("currentProgram", state.getCurrentProgram());
		scriptShell.setVariable("currentAddress", state.getCurrentAddress());
	}

	/**
	 * Resets this interpreter.
	 */
	public void reset() {
		createInteractiveShell(inStream, outStream, errStream);
	}

	@Override
	public void runScript(GhidraScript script, String[] scriptArguments, GhidraState scriptState)
			throws IllegalArgumentException, FileNotFoundException, IOException {
		createScriptableShell();
		scriptShell.setVariable("script", script);
		loadState(scriptState);
		scriptShell.run(script.getSourceFile().getFile(true), scriptArguments);
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
			interactiveBinding.setVariable("currentAddress", address);
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
			interactiveBinding.setVariable("currentHighlight", sel);
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
			interactiveBinding.setVariable("currentLocation", loc);
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
			interactiveBinding.setVariable("currentProgram", program);
			interactiveBinding.setVariable("currentAPI", new FlatProgramAPI(program));
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
			interactiveBinding.setVariable("currentSelection", sel);
		}
	}

	/**
	 * Updates a state with the current selection/location/etc. variables from the
	 * script interpreter.
	 *
	 * @param scriptState The state to update.
	 */
	@Override
	public void updateState(GhidraState scriptState) {
		Program currentProgram = (Program) scriptShell.getVariable("currentProgram");
		scriptState.setCurrentProgram(currentProgram);

		ProgramLocation programLoc = (ProgramLocation) scriptShell.getVariable("currentLocation");
		scriptState.setCurrentLocation(programLoc);

		Address addr = (Address) scriptShell.getVariable("currentAddress");
		scriptState.setCurrentAddress(addr);

		ProgramSelection highlight = (ProgramSelection) scriptShell.getVariable("currentHighlight");
		scriptState.setCurrentHighlight(highlight);

		ProgramSelection sel = (ProgramSelection) scriptShell.getVariable("currentSelection");
		scriptState.setCurrentSelection(sel);
	}

}
