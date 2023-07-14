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

import java.awt.event.KeyEvent;

import docking.ActionContext;
import docking.DockingUtils;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.ToolBarData;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.interpreter.InterpreterConnection;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.plugin.core.interpreter.InterpreterPanelService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import resources.ResourceManager;
import rubydragon.DragonPlugin;
import rubydragon.GhidraInterpreter;

/**
 * GroovyDragon provides an interactive Groovy terminal session within Ghidra.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.INTERPRETERS,
	shortDescription = "Groovy Interpreter",
	description = "Provides an interactive Groovy interpreter integrated with loaded Ghidra programs.",
	servicesRequired = { InterpreterPanelService.class },
	isSlowInstallation = true
)
//@formatter:on
public class GroovyDragonPlugin extends DragonPlugin implements InterpreterConnection {

	private InterpreterConsole console;
	private GroovyGhidraInterpreter interpreter;

	/**
	 * Plugin constructor.
	 *
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public GroovyDragonPlugin(PluginTool tool) {
		super(tool, "Groovy");
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
	 * Gives the Groovy interpreter currently in use.
	 *
	 * @return The Groovy interpreter for this plugin. Will always be a
	 *         GroovyGhidraInterpreter instance.
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
		interpreter = new GroovyGhidraInterpreter(console, this);
		console.setPrompt("> ");
		console.addFirstActivationCallback(() -> {
			interpreter.startInteractiveSession();
		});

		DockingAction resetAction = new DockingAction("Reset Interpreter", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				interpreter.reset();
				interpreter.updateHighlight(getProgramHighlight());
				interpreter.updateLocation(getProgramLocation());
				interpreter.updateProgram(getCurrentProgram());
				interpreter.updateSelection(getProgramSelection());
				console.clear();
			}
		};
		resetAction.setDescription("Reset Interpreter");
		resetAction.setToolBarData(new ToolBarData(ResourceManager.loadImage("images/reload3.png"), null));
		resetAction.setEnabled(true);
		resetAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_D, DockingUtils.CONTROL_KEY_MODIFIER_MASK));
		resetAction.setHelpLocation(new HelpLocation(getTitle(), "Reset_Interpreter"));
		console.addAction(resetAction);
	}

	/**
	 * Shows the interpreter console.
	 */
	@Override
	public void showConsole() {
		console.show();
	}
}
