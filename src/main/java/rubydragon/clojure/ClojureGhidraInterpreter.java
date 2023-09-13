// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2021-2023 Joel E. Anderson
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

package rubydragon.clojure;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

import clojure.lang.LineNumberingPushbackReader;
import clojure.lang.Namespace;
import clojure.lang.RT;
import clojure.lang.Symbol;
import clojure.lang.Var;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.exception.AssertException;
import rubydragon.DragonPlugin;
import rubydragon.ScriptableGhidraInterpreter;

/**
 * A Clojure interpreter for Ghidra.
 */
public class ClojureGhidraInterpreter extends ScriptableGhidraInterpreter {
	private Thread replThread;
	final private ClassLoader clojureClassLoader;
	private DragonPlugin parentPlugin;
	private PrintWriter outWriter;
	private PrintWriter errWriter;

	private Runnable replLoop = () -> {
		initInteractiveInterpreterWithProgress(outWriter, errWriter);

		Var clojureMainFunction = RT.var("clojure.main", "main");
		while (true) {
			String[] args = { "--repl" };
			clojureMainFunction.applyTo(RT.seq(args));
		}
	};

	/**
	 * Creates a new Clojure interpreter.
	 */
	public ClojureGhidraInterpreter() {
		parentPlugin = null;
		clojureClassLoader = new ClojureGhidraClassLoader();
		replThread = new Thread(replLoop);
		replThread.setContextClassLoader(clojureClassLoader);
	}

	/**
	 * Creates a new interpreter, and ties the streams for the provided console to
	 * the new interpreter.
	 *
	 * @param console      The console to bind to the interpreter streams.
	 * @param parentPlugin The DragonPlugin instance owning this interpreter.
	 */
	public ClojureGhidraInterpreter(InterpreterConsole console, DragonPlugin plugin) {
		this();
		setStreams(console);
		parentPlugin = plugin;
	}

	/**
	 * Should end the interpreter and release all resources. Currently does nothing.
	 *
	 * Unfortunately, Clojure kills the entire process when the interactive session
	 * is ended. Since this kills Ghidra completely rather than just disabling the
	 * plugin, we elect to do nothing here and wait for a restart to kill this
	 * thread. This is also the reason that the console is not destroyed in
	 * ClojureDragonPlugin.dispose().
	 */
	@Override
	public void dispose() {
		// do nothing
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

	@Override
	public String getCurrentAddressName() {
		return "current-address";
	}

	@Override
	public String getCurrentAPIName() {
		return "current-api";
	}

	@Override
	public String getCurrentHighlightName() {
		return "current-highlight";
	}

	@Override
	public String getCurrentLocationName() {
		return "current-location";
	}

	@Override
	public String getCurrentProgramName() {
		return "current-program";
	}

	@Override
	public String getCurrentSelectionName() {
		return "current-selection";
	}

	@Override
	public DragonPlugin getParentPlugin() {
		return parentPlugin;
	}

	/**
	 * Get the version of Clojure this interpreter supports.
	 *
	 * @return A string with the version of the interpreter.
	 */
	@Override
	public String getVersion() {
		Var clojureVersion = RT.var("clojure.core", "clojure-version");
		return "Clojure " + clojureVersion.invoke().toString();
	}

	@Override
	public void importClass(String packageName, String className) {
		Namespace ghidraNs = Namespace.findOrCreate(Symbol.intern(null, "ghidra"));
		ghidraNs.importClass(RT.classForName(className));
	}

	/**
	 * Sets up the Clojure environment, and auto loads classes if enabled.
	 */
	@Override
	public void initInteractiveInterpreter() {
		Symbol clojureMain = Symbol.intern("clojure.main");
		Var clojureCoreRequire = RT.var("clojure.core", "require");
		RT.init();
		clojureCoreRequire.invoke(clojureMain);
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
	 * Public and protected fields and public methods are bound into the ghidra
	 * namespace before the script itself is run. A "ghidra/script" binding is also
	 * created, bound to this ClojureScript instance (via "this").
	 *
	 * @throws IllegalArgumentException if the script does not exist
	 * @throws IOException              if the script could not be read
	 * @throws FileNotFoundException    if the script file wasn't found
	 */
	@Override
	public void runScript(GhidraScript script, String[] scriptArguments, GhidraState scriptState)
			throws IllegalArgumentException, FileNotFoundException, IOException {
		ClassLoader previous = Thread.currentThread().getContextClassLoader();
		Thread.currentThread().setContextClassLoader(clojureClassLoader);
		try {
			ResourceFile scriptFile = script.getSourceFile();
			loadState(scriptState);
			RT.var("ghidra", "script", script);

			// putting the methods from this script class into the interpreter
			// taken from the PythonScript class in the ghidra source
			for (Class<?> scriptClass = script.getClass(); scriptClass != Object.class; scriptClass = scriptClass
					.getSuperclass()) {

				// Add public and protected fields
				for (Field field : scriptClass.getDeclaredFields()) {
					if (Modifier.isPublic(field.getModifiers()) || Modifier.isProtected(field.getModifiers())) {
						try {
							field.setAccessible(true);
							RT.var("ghidra", field.getName(), field.get(script));
						} catch (IllegalAccessException iae) {
							throw new AssertException("Unexpected security manager being used!");
						}
					}
				}

				// Add public methods. Ignore inner classes.
				for (Method method : scriptClass.getDeclaredMethods()) {

					if (!method.getName().contains("$") && Modifier.isPublic(method.getModifiers())) {
						method.setAccessible(true);
						RT.var("ghidra", method.getName(), method);
					}
				}
			}

			ArrayList<String> modifiedArgs = new ArrayList<String>(scriptArguments.length);
			modifiedArgs.add("--");
			for (String arg : scriptArguments) {
				modifiedArgs.add(arg);
			}
			RT.processCommandLine(modifiedArgs.toArray(scriptArguments));
			RT.loadResourceScript(scriptFile.getAbsolutePath());
			updateState(scriptState);
		} finally {
			Thread.currentThread().setContextClassLoader(previous);
		}
	}

	/**
	 * Sets the error output stream for this interpreter.
	 */
	@Override
	public void setErrWriter(PrintWriter errOut) {
		errWriter = errOut;
		Var.intern(RT.CLOJURE_NS, Symbol.intern("*err*"), errOut);
	}

	/**
	 * Sets the input stream for this interpreter.
	 */
	@Override
	public void setInput(InputStream input) {
		LineNumberingPushbackReader inReader = new LineNumberingPushbackReader(new InputStreamReader(input));
		Var.intern(RT.CLOJURE_NS, Symbol.intern("*in*"), inReader);
	}

	/**
	 * Sets the output stream for this interpreter.
	 */
	@Override
	public void setOutWriter(PrintWriter output) {
		outWriter = output;
		Var.intern(RT.CLOJURE_NS, Symbol.intern("*out*"), output);
	}

	/**
	 * Adds or updates the variable with the given name to the given value in the
	 * scripting container.
	 *
	 * @param name  The name of the variable to create or update.
	 * @param value The value of the variable to add.
	 */
	@Override
	public void setVariable(String name, Object value) {
		RT.var("ghidra", name, value);
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
	 * interpreter.
	 *
	 * @param scriptState The state to update.
	 */
	@Override
	public void updateState(GhidraState scriptState) {
		Namespace ghidraNS = Namespace.findOrCreate(Symbol.intern("ghidra"));
		Program currentProgram = (Program) Var.intern(ghidraNS, Symbol.intern("current-program")).get();
		scriptState.setCurrentProgram(currentProgram);

		ProgramLocation programLoc = (ProgramLocation) Var.intern(ghidraNS, Symbol.intern("current-location")).get();
		scriptState.setCurrentLocation(programLoc);

		Address addr = (Address) Var.intern(ghidraNS, Symbol.intern("current-address")).get();
		scriptState.setCurrentAddress(addr);

		ProgramSelection highlight = (ProgramSelection) Var.intern(ghidraNS, Symbol.intern("current-highlight")).get();
		scriptState.setCurrentHighlight(highlight);

		ProgramSelection sel = (ProgramSelection) Var.intern(ghidraNS, Symbol.intern("current-selection")).get();
		scriptState.setCurrentSelection(sel);
	}

}
