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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import groovy.lang.Binding;
import groovy.lang.Closure;
import groovy.lang.GroovyShell;
import groovy.lang.GroovySystem;
import rubydragon.DragonPlugin;
import rubydragon.ScriptableGhidraInterpreter;

/**
 * A Groovy interpreter for Ghidra.
 */
public class GroovyGhidraInterpreter extends ScriptableGhidraInterpreter {

	private Map<String, Object> setVariables = new HashMap<String, Object>();
	private Thread replThread;
	private Groovysh interactiveShell;
	private Binding interactiveBinding;
	private GroovyShell scriptShell;
	private InputStream inStream;
	private OutputStream outStream;
	private OutputStream errStream;
	private PrintWriter outWriter;
	private PrintWriter errWriter;
	private boolean disposed = false;
	private DragonPlugin parentPlugin;

	private Runnable replLoop = () -> {
		initInteractiveInterpreterWithProgress(outWriter, errWriter);

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
		interactiveBinding = null;
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
	 * Does nothing, as automatic imports are handled in initInteractiveInterpreter
	 * more efficiently. This function is overridden so that the default
	 * implementation is not used.
	 *
	 * @since 3.1.0
	 */
	@Override
	public void autoImportClasses(PrintWriter output, PrintWriter errOut) {
		return;
	}

	/**
	 * Creates a new Groovy shell to run scripts.
	 */
	private void createScriptableShell() {
		scriptShell = new GroovyShell();
	}

	/**
	 * Creates a new Groovy interpreter for interactive sessions.
	 *
	 * @since 3.1.0
	 */
	@Override
	public void initInteractiveInterpreter() {
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
		IO shellIo = new IO(inStream, outStream, errStream);
		interactiveBinding = new Binding();
		CompilerConfiguration cc = new CompilerConfiguration();

		// load the preload imports if enabled
		boolean preloadEnabled = parentPlugin != null && parentPlugin.isAutoImportEnabled();
		if (preloadEnabled) {
			long startTime = System.currentTimeMillis();
			outWriter.append("starting auto-import...\n");
			outWriter.flush();

			ImportCustomizer ic = new ImportCustomizer();
			try {
				DragonPlugin.forEachAutoImport((packageName, className) -> {
					ic.addImport(className, packageName + "." + className);
				});
			} catch (JDOMException | IOException e) {
				errWriter.append("could not load auto-import classes: " + e.getMessage() + "\n");
				errWriter.flush();
			}
			cc.addCompilationCustomizers(ic);
			long endTime = System.currentTimeMillis();
			double importTime = (endTime - startTime) / 1000.0;
			outWriter.append(String.format("auto-imported finished (%.3f seconds)\n", importTime));
			outWriter.flush();
		} else {
			outWriter.append("auto-import disabled.\n");
			outWriter.flush();
		}

		interactiveShell = new Groovysh(classLoader, interactiveBinding, shellIo, registrar, cc);

		// set any variables that were provided before creation
		setVariables.forEach((name, value) -> {
			interactiveBinding.setVariable(name, value);
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
	 * Get the version of Groovy this interpreter supports.
	 *
	 * @return A string with the version of the interpreter.
	 *
	 * @since 3.1.0
	 */
	@Override
	public String getVersion() {
		return "Groovy " + GroovySystem.getVersion();
	}

	/**
	 * Does nothing, as automatic imports are handled in initInteractiveInterpreter
	 * more efficiently. This function is overridden so that the default
	 * implementation is not used.
	 *
	 * @since 3.1.0
	 */
	@Override
	public void importClass(String packageName, String className) {
		return;
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
		initInteractiveInterpreter();
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
		return;
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
	 * current engine.
	 *
	 * @param name  The name of the variable to create or update.
	 * @param value The value of the variable to add.
	 *
	 * @since 3.1.0
	 */
	@Override
	public void setVariable(String name, Object value) {
		setVariables.put(name, value);
		if (interactiveBinding != null) {
			interactiveBinding.setVariable(name, value);
		}
	}

	/**
	 * Starts an interactive session with the current input/output/error streams.
	 */
	@Override
	public void startInteractiveSession() {
		replThread.start();
	}

	/**
	 * Updates a state with the current selection/location/etc. variables from the
	 * script interpreter.
	 *
	 * @param scriptState The state to update.
	 */
	@Override
	public void updateState(GhidraState scriptState) {
		Program currentProgram = (Program) scriptShell.getVariable(getCurrentProgramName());
		scriptState.setCurrentProgram(currentProgram);

		ProgramLocation programLoc = (ProgramLocation) scriptShell.getVariable(getCurrentLocationName());
		scriptState.setCurrentLocation(programLoc);

		Address addr = (Address) scriptShell.getVariable(getCurrentAddressName());
		scriptState.setCurrentAddress(addr);

		ProgramSelection highlight = (ProgramSelection) scriptShell.getVariable(getCurrentHighlightName());
		scriptState.setCurrentHighlight(highlight);

		ProgramSelection sel = (ProgramSelection) scriptShell.getVariable(getCurrentSelectionName());
		scriptState.setCurrentSelection(sel);
	}

}
