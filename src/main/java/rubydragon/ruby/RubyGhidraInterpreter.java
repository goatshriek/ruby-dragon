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

package rubydragon.ruby;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.jdom.Document;
import org.jdom.Element;
import org.jruby.embed.LocalContextScope;
import org.jruby.embed.LocalVariableBehavior;
import org.jruby.embed.ScriptingContainer;

import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.framework.Application;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.xml.XmlUtilities;
import rubydragon.ScriptableGhidraInterpreter;

/**
 * A Ruby interpreter for Ghidra, built using JRuby.
 */
public class RubyGhidraInterpreter extends ScriptableGhidraInterpreter {
	private ScriptingContainer container;
	private Thread irbThread;
	private boolean disposed = false;

	/**
	 * Creates a new Ruby interpreter.
	 */
	public RubyGhidraInterpreter() {
		container = new ScriptingContainer(LocalContextScope.SINGLETHREAD, LocalVariableBehavior.PERSISTENT);
		irbThread = new Thread(() -> {
			try {
				// run the ruby setup script
				InputStream stream = getClass().getResourceAsStream("/scripts/ruby-init.rb");
				container.runScriptlet(stream, "ruby-init.rb");

				Document preload = XmlUtilities.readDocFromFile(Application.findDataFileInAnyModule("preload.xml"));
				@SuppressWarnings("unchecked")
				List<Element> preloadClasses = preload.getRootElement().getChildren("class");
				for (int i = 0; i < preloadClasses.size(); i++) {
					Element preloadClass = preloadClasses.get(i);
					String packageName = preloadClass.getChildText("package");
					String className = preloadClass.getChildText("name");
					String importStatement = "java_import Java::" + packageName + "." + className;
					container.runScriptlet(importStatement);
				}
			} catch (Throwable t) {
				// we don't want an exception to crash everything, just the input thread
				throw new RuntimeException(t);
			}
			while (!disposed) {
				container.runScriptlet("IRB.start");
			}
		});
	}

	/**
	 * Creates a new interpreter, and ties the streams for the provided console to
	 * the new interpreter.
	 *
	 * @param console The console to bind to the interpreter streams.
	 */
	public RubyGhidraInterpreter(InterpreterConsole console) {
		this();
		setStreams(console);
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
		InputStream scriptStream = script.getSourceFile().getInputStream();
		loadState(scriptState);
		Object savedAPI = container.get("$current_api");
		container.put("$script", script);
		container.put("$current_api", script);
		container.put("ARGV", scriptArguments);
		createProxies();
		container.runScriptlet(scriptStream, script.getScriptName());
		container.remove("$script");
		container.put("$current_api", savedAPI);
		updateState(scriptState);
	}

	/**
	 * Sets the error output stream for this interpreter.
	 */
	@Override
	public void setErrWriter(PrintWriter errOut) {
		container.setError(errOut);
	}

	/**
	 * Sets the input stream for this interpreter.
	 */
	@Override
	public void setInput(InputStream input) {
		container.setInput(input);
	}

	/**
	 * Sets the output stream for this interpreter.
	 */
	@Override
	public void setOutWriter(PrintWriter output) {
		container.setOutput(output);
	}

	/**
	 * Starts an interactive session with the current input/output/error streams.
	 */
	@Override
	public void startInteractiveSession() {
		irbThread.start();
	}

	/**
	 * Updates the current address pointed to by the "$current_address" variable.
	 *
	 * @param address The new current address in the program.
	 */
	@Override
	public void updateAddress(Address address) {
		container.put("$current_address", address);
	}

	/**
	 * Updates the highlighted selection pointed to by the "$current_highlight"
	 * variable.
	 *
	 * @param sel The new highlighted selection.
	 */
	@Override
	public void updateHighlight(ProgramSelection sel) {
		container.put("$current_highlight", sel);
	}

	/**
	 * Updates the location in the "$current_location" variable as well as the
	 * address in the "$current_address" variable.
	 *
	 * @param loc The new location in the program.
	 */
	@Override
	public void updateLocation(ProgramLocation loc) {
		if (loc == null) {
			container.remove("$current_location");
		} else {
			container.put("$current_location", loc);
			updateAddress(loc.getAddress());
		}
	}

	/**
	 * Updates the current program in "$current_program" to the one provided, as
	 * well as the "$current_api" variable holding a flat api instance.
	 *
	 * @param program The new current program.
	 */
	@Override
	public void updateProgram(Program program) {
		if (program != null) {
			container.put("$current_program", program);
			container.put("$current_api", new FlatProgramAPI(program));
			createProxies();
		}
	}

	/**
	 * Updates the selection pointed to by the "$current_selection" variable.
	 *
	 * @param sel The new selection.
	 */
	@Override
	public void updateSelection(ProgramSelection sel) {
		container.put("$current_selection", sel);
	}

	/**
	 * Updates a state with the $current_*. variables from the interpreter.
	 *
	 * @param scriptState The state to update.
	 */
	@Override
	public void updateState(GhidraState scriptState) {
		scriptState.setCurrentProgram((Program) container.get("$current_program"));
		scriptState.setCurrentLocation((ProgramLocation) container.get("$current_location"));
		scriptState.setCurrentAddress((Address) container.get("$current_address"));
		scriptState.setCurrentHighlight((ProgramSelection) container.get("$current_highlight"));
		scriptState.setCurrentSelection((ProgramSelection) container.get("$current_selection"));
	}
}
