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

package rubydragon.ruby;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jruby.embed.EvalFailedException;
import org.jruby.embed.LocalContextScope;
import org.jruby.embed.LocalVariableBehavior;
import org.jruby.embed.ScriptingContainer;

import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import rubydragon.DragonPlugin;
import rubydragon.ScriptableGhidraInterpreter;

/**
 * A Ruby interpreter for Ghidra, built using JRuby.
 */
public class RubyGhidraInterpreter extends ScriptableGhidraInterpreter {
	private Map<String, Object> setVariables = new HashMap<String, Object>();
	private ScriptingContainer container;
	private Thread irbThread;
	private boolean disposed = false;
	private DragonPlugin parentPlugin;
	private PrintWriter outWriter = null;
	private PrintWriter errWriter = null;
	private InputStream input = null;
	private OutputStream output = null;
	private OutputStream errOut = null;

	private Runnable replLoop = () -> {
		initInteractiveInterpreterWithProgress(outWriter, errWriter);

		while (!disposed) {
			container.runScriptlet("IRB.start");
		}
	};

	/**
	 * Creates a new Ruby interpreter.
	 */
	public RubyGhidraInterpreter() {
		container = null;
		irbThread = new Thread(replLoop);
		parentPlugin = null;
	}

	/**
	 * Creates a new interpreter, and ties the streams for the provided console to
	 * the new interpreter.
	 *
	 * @param console The console to bind to the interpreter streams.
	 */
	public RubyGhidraInterpreter(InterpreterConsole console, DragonPlugin plugin) {
		this();
//		setStreams(console);
		setInput(console.getStdin());
		this.output = console.getStdOut();
		outWriter = new PrintWriter(this.output);
		this.errOut = console.getStdErr();
		errWriter = new PrintWriter(errOut);
		parentPlugin = plugin;
	}

	/**
	 * Sets up method proxies at the top level to mirror $script or $current_api
	 * methods, as jython does.
	 */
	public void createProxies() {
		// ignore base java Object, ruby Object, main, and Kernel methods. We don't want
		// to overwrite any of them.
		//@formatter:off
		container.runScriptlet(
			"((($current_api.methods - java.lang.Object.new.methods) - self.methods) - Kernel.methods).each { |mn| \n" +
			// proxy the current object (hence not method binding)
			" define_method(mn){|*argv|($current_api).send(mn, *argv);}\n" +
			// hide from all other objects so we don't see it in autocomplete when called
			// with an explicit receiver
			" private(mn)\n" +
			" }");
		//@formatter:on
	}

	/**
	 * Should end the interpreter and release all resources. Currently does nothing.
	 */
	@Override
	public void dispose() {
		disposed = true;
		// container.terminate(); // makes ghidra hang on close
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
		container.put("GHIDRA_LAST_PARTIAL", cmd);
		// CodeCompletion.new(description, text_to_append, optional_nil)
		try {
			// use IRB to get the completed lines, then strip off the relevant parts
			//@formatter:off
			CodeCompletion[] tmp = (CodeCompletion[]) container.runScriptlet("IRB::InputCompletor::CompletionProc.call(GHIDRA_LAST_PARTIAL).reject(&:nil?).map{|y|compl = y[GHIDRA_LAST_PARTIAL.length..-1];desc = y.split(/\\s+|\\.|::/).last;Java::GhidraAppPluginCoreConsole::CodeCompletion.new(desc, compl, nil)}.to_java(Java::GhidraAppPluginCoreConsole::CodeCompletion)");
			//@formatter:on
			return Arrays.asList(tmp);
		} catch (Throwable t) {
			// often: org.jruby.embed.EvalFailedException: (ArgumentError) Java package
			// 'ghidra.program' does not have a method `instance_methods' with 1 argument
			// test this code path with: [].length.t<TAB>
			// ignore, see https://github.com/ruby/irb/issues/295 and
			// https://github.com/jruby/jruby/issues/7323 for exceptions this catches
			return new ArrayList<>();
		}
	}

	/**
	 * The name for the current address variable.
	 *
	 * @return The name for the current address variable.
	 *
	 * @since 3.1.0
	 */
	@Override
	public String getCurrentAddressName() {
		return "$current_address";
	}

	/**
	 * The name for the current FlatProgramAPI variable.
	 *
	 * @return The name for the current API variable.
	 *
	 * @since 3.1.0
	 */
	@Override
	public String getCurrentAPIName() {
		return "$current_api";
	}

	/**
	 * The name for the current highlight variable.
	 *
	 * @return The name for the current highlight variable.
	 *
	 * @since 3.1.0
	 */
	@Override
	public String getCurrentHighlightName() {
		return "$current_highlight";
	}

	/**
	 * The name for the current location variable.
	 *
	 * @return The name for the current location variable.
	 *
	 * @since 3.1.0
	 */
	@Override
	public String getCurrentLocationName() {
		return "$current_location";
	}

	/**
	 * The name for the current program variable.
	 *
	 * @return The name for the current program variable.
	 *
	 * @since 3.1.0
	 */
	@Override
	public String getCurrentProgramName() {
		return "$current_program";
	}

	/**
	 * The name for the current selection variable.
	 *
	 * @return The name for the current selection variable.
	 *
	 * @since 3.1.0
	 */
	@Override
	public String getCurrentSelectionName() {
		return "$current_selection";
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
	 * Get the version of Ruby this interpreter supports.
	 *
	 * @return A string with the version of the interpreter.
	 *
	 * @since 3.1.0
	 */
	@Override
	public String getVersion() {
		return (new ScriptingContainer()).getSupportedRubyVersion();
	}

	/**
	 * Creates a new Ruby interpreter, sets up the automatic variables, and adds
	 * proxies into the namespace for the current Program methods.
	 *
	 * @since 3.1.0
	 */
	@Override
	public void initInteractiveInterpreter() {
		container = new ScriptingContainer(LocalContextScope.SINGLETHREAD, LocalVariableBehavior.PERSISTENT);

		// set the input and output streams if they've been set
		if (errWriter != null) {
//			container.setError(errWriter);
			container.setError(new PrintStream(errOut));
		}
		if (input != null) {
			container.setInput(input);
		}
		if (output != null) {
//			container.setOutput(outWriter);
			container.setOutput(new PrintStream(output));
		}

		// run the ruby setup script
		InputStream stream = getClass().getResourceAsStream("/scripts/ruby-init.rb");
		container.runScriptlet(stream, "ruby-init.rb");

		// set any variables that were provided before creation
		setVariables.forEach((name, value) -> {
			container.put(name, value);
		});

		createProxies();
	}

	/**
	 * Imports a given class into the Ruby environment.
	 *
	 * @param packageName The name of the package the class is in.
	 * @param className   The name of the class to import.
	 *
	 * @since 3.1.0
	 */
	@Override
	public void importClass(String packageName, String className) {
		// we don't import the class if it will stomp an existing symbol
		// we also have to skip Data because it generates deprecation warnings
		if (container != null && !className.equals("Data") && container.get(className) == null) {
			String importStatement = "java_import Java::" + packageName + "." + className;
			try {
				container.runScriptlet(importStatement);
			} catch (EvalFailedException e) {
				String evalError = "could not load class " + packageName + "." + className + ": " + e.getMessage()
						+ "\n";
				container.getError().append(evalError);
			}
		}
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
		initInteractiveInterpreter();
		InputStream scriptStream = script.getSourceFile().getInputStream();
		loadState(scriptState);
		Object savedAPI = container.get(getCurrentAPIName());
		container.put("$script", script);
		container.put(getCurrentAPIName(), script);
		container.put("ARGV", scriptArguments);
		container.runScriptlet(scriptStream, script.getScriptName());
		container.remove("$script");
		container.put(getCurrentAPIName(), savedAPI);
		updateState(scriptState);
	}

	/**
	 * Sets the error output stream for this interpreter.
	 */
	@Override
	public void setErrWriter(PrintWriter errOut) {
		errWriter = errOut;
		if (container != null) {
			container.setError(errOut);
		}
	}

	/**
	 * Sets the input stream for this interpreter.
	 */
	@Override
	public void setInput(InputStream input) {
		this.input = input;
		if (container != null) {
			container.setInput(input);
		}
	}

	/**
	 * Sets the output stream for this interpreter.
	 */
	@Override
	public void setOutWriter(PrintWriter output) {
		outWriter = output;
		if (container != null) {
//			container.setOutput(output);
		}
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
		setVariables.put(name, value);
		if (container != null) {
			container.put(name, value);
		}
	}

	/**
	 * Starts an interactive session with the current input/output/error streams.
	 */
	@Override
	public void startInteractiveSession() {
		irbThread.start();
	}

	/**
	 * Updates the current program in "$current_program" to the one provided, as
	 * well as the "$current_api" variable holding a flat api instance.
	 *
	 * @param program The new current program.
	 */
	@Override
	public void updateProgram(Program program) {
		super.updateProgram(program);

		if (container != null) {
			createProxies();
		}
	}

	/**
	 * Updates a state with the $current_*. variables from the interpreter.
	 *
	 * @param scriptState The state to update.
	 */
	@Override
	public void updateState(GhidraState scriptState) {
		scriptState.setCurrentProgram((Program) setVariables.get(getCurrentProgramName()));
		scriptState.setCurrentLocation((ProgramLocation) setVariables.get(getCurrentLocationName()));
		scriptState.setCurrentAddress((Address) setVariables.get(getCurrentAddressName()));
		scriptState.setCurrentHighlight((ProgramSelection) setVariables.get(getCurrentHighlightName()));
		scriptState.setCurrentSelection((ProgramSelection) setVariables.get(getCurrentSelectionName()));
	}
}
