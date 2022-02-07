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

package rubydragon.clojure;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.InterpreterConnection;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.plugin.core.interpreter.InterpreterPanelService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import rubydragon.DragonDependency;
import rubydragon.DragonPlugin;
import rubydragon.GhidraInterpreter;

/**
 * ClojureDragon provides Clojure support within Ghidra, both in an interactive
 * terminal session as well as standalone scripts.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.INTERPRETERS,
	shortDescription = "Clojure Interpreter",
	description = "Provides an interactive Clojure interpreter integrated with loaded Ghidra programs.",
	servicesRequired = { InterpreterPanelService.class },
	isSlowInstallation = true
)
//@formatter:on
public class ClojureDragonPlugin extends DragonPlugin implements InterpreterConnection {

	public static final Collection<DragonDependency> DEPENDENCIES = Arrays.asList();

	private InterpreterConsole console;
	private GhidraInterpreter interpreter;

	/**
	 * Plugin constructor.
	 *
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public ClojureDragonPlugin(PluginTool tool) {
		super(tool, "Clojure");
	}

	/**
	 * Destroys the plugin and any interpreters within. The interactive console is
	 * not destroyed as Clojure would then end the entire Ghidra process.
	 */
	@Override
	protected void dispose() {
		interpreter.dispose();
		super.dispose();
	}

	/**
	 * Get a list of completions for the given command prefix.
	 *
	 * Currently not implemented, and will always return an empty list.
	 */
	@Override
	public List<CodeCompletion> getCompletions(String cmd) {
		// TODO currently just an empty list, need to actually implement
		return new ArrayList<CodeCompletion>();
	}

	/**
	 * Gets all of the dependencies needed by ClojureDragon to function correctly.
	 *
	 * This is simply a wrapper for the static DEPENDENCIES class variable.
	 *
	 * @return A Collection holding all ClojureDragon dependencies.
	 */
	@Override
	public Collection<DragonDependency> getDependencies() {
		return DEPENDENCIES;
	}

	/**
	 * Gives the clojure interpreter currently in use.
	 *
	 * @return The clojure interpreter for this plugin. Will always be a
	 *         ClojureGhidraInterpreter instance.
	 */
	@Override
	public GhidraInterpreter getInterpreter() {
		return interpreter;
	}

	/**
	 * Set up the plugin, including the creation of the interactive interpreter.
	 */
	@Override
	public void init() {
		super.init();

		console = getTool().getService(InterpreterPanelService.class).createInterpreterPanel(this, false);
		console.setPrompt(" ");
		interpreter = new ClojureGhidraInterpreter(console);
		console.addFirstActivationCallback(() -> {
			interpreter.startInteractiveSession();
		});
	}
}
