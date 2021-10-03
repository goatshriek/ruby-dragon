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

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.swing.ImageIcon;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.InterpreterConnection;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.plugin.core.interpreter.InterpreterPanelService;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import resources.ResourceManager;
import rubydragon.GhidraInterpreter;

/**
 * RubyDragon provides Ruby support within Ghidra, both in an interactive
 * terminal session as well as standalone scripts.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.INTERPRETERS,
	shortDescription = "Ruby Interpreter",
	description = "Provides an interactive Ruby Interpreter that is tightly integrated with a loaded Ghidra program.",
	servicesRequired = { InterpreterPanelService.class },
	isSlowInstallation = true
)
//@formatter:on
public class RubyDragonPlugin extends ProgramPlugin implements InterpreterConnection {

	private InterpreterConsole console;
	private GhidraInterpreter interpreter;

	/**
	 * Plugin constructor.
	 *
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public RubyDragonPlugin(PluginTool tool) {
		super(tool, true, true);
	}

	/**
	 * Destroys the plugin and any interpreters within.
	 */
	@Override
	protected void dispose() {
		interpreter.dispose();
		console.dispose();
		super.dispose();
	}

	/**
	 * The title of the plugin.
	 */
	@Override
	public String getTitle() {
		return "Ruby";
	}

	/**
	 * The icon for this plugin.
	 */
	@Override
	public ImageIcon getIcon() {
		return ResourceManager.loadImage("images/ruby.png");
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
	 * Set up the plugin, including the creation of the interactive interpreter.
	 */
	@Override
	public void init() {
		super.init();

		console = getTool().getService(InterpreterPanelService.class).createInterpreterPanel(this, false);
		interpreter = new RubyGhidraInterpreter(console);
		console.addFirstActivationCallback(() -> {
			List<String> brokenVersions = Arrays.asList("10.0.3", "10.0.4");
			String ghidraVersion = Application.getApplicationVersion();
			if (brokenVersions.contains(ghidraVersion)) {
				PrintWriter errWriter = new PrintWriter(console.getStdErr());
				errWriter.print("RubyDragon may have problems running in this "
						+ "version of Ghidra. If you receive errors regarding class lookup "
						+ "failures, you may need to replace the launch.properties "
						+ "file in the support directory of the Ghidra install "
						+ "with the one in this plugin (in the "
						+ "Extensions/RubyDragon/data directory in your Ghidra install).\n");
				errWriter.flush();
			}

			interpreter.startInteractiveSession();
		});
	}

	/**
	 * Called whenever the highlight is changed within the CodeBrowser tool.
	 */
	@Override
	public void highlightChanged(ProgramSelection sel) {
		interpreter.updateHighlight(sel);
	}

	/**
	 * Called whenever the location is changed within the CodeBrowser tool.
	 */
	@Override
	public void locationChanged(ProgramLocation loc) {
		interpreter.updateLocation(loc);
	}

	/**
	 * Called whenever a program is activate within the CodeBrowser tool.
	 */
	@Override
	public void programActivated(Program program) {
		interpreter.updateProgram(program);
	}

	/**
	 * Called whenever the selection is changed within the CodeBrowser tool.
	 */
	@Override
	public void selectionChanged(ProgramSelection sel) {
		interpreter.updateSelection(sel);
	}
}
