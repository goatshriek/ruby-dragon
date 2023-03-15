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
 * JShellDragon provides an interactive Java terminal session within Ghidra via
 * JShell.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.INTERPRETERS,
	shortDescription = "JShell Interpreter",
	description = "Provides an interactive JShell interpreter integrated with loaded Ghidra programs.",
	servicesRequired = { InterpreterPanelService.class },
	isSlowInstallation = true
)
//@formatter:on
public class JShellDragonPlugin extends DragonPlugin implements InterpreterConnection {

	private InterpreterConsole console;
	private JShellGhidraInterpreter interpreter;

	/**
	 * Plugin constructor.
	 *
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public JShellDragonPlugin(PluginTool tool) {
		super(tool, "JShell");
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
	 * Gives the java interpreter currently in use.
	 *
	 * @return The java interpreter for this plugin. Will always be a
	 *         JShellGhidraInterpreter instance.
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
		interpreter = new JShellGhidraInterpreter(console, this);
		console.setPrompt("> ");
		console.addFirstActivationCallback(() -> {
			interpreter.startInteractiveSession();
		});

		DockingAction interruptAction = new DockingAction("Interrupt Interpreter", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				interpreter.interrupt();
			}
		};
		interruptAction.setDescription("Interrupt Interpreter");
		interruptAction.setToolBarData(new ToolBarData(ResourceManager.loadImage("images/dialog-cancel.png"), null));
		interruptAction.setEnabled(true);
		interruptAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_I, DockingUtils.CONTROL_KEY_MODIFIER_MASK));
		interruptAction.setHelpLocation(new HelpLocation(getTitle(), "Interrupt_Interpreter"));
		console.addAction(interruptAction);

		DockingAction resetAction = new DockingAction("Reset Interpreter", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				console.clear();
				interpreter.reset();
				interpreter.updateHighlight(getProgramHighlight());
				interpreter.updateLocation(getProgramLocation());
				interpreter.updateProgram(getCurrentProgram());
				interpreter.updateSelection(getProgramSelection());
			}
		};
		resetAction.setDescription("Reset Interpreter");
		resetAction.setToolBarData(new ToolBarData(ResourceManager.loadImage("images/reload3.png"), null));
		resetAction.setEnabled(true);
		resetAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_D, DockingUtils.CONTROL_KEY_MODIFIER_MASK));
		resetAction.setHelpLocation(new HelpLocation(getTitle(), "Reset_Interpreter"));
		console.addAction(resetAction);
	}
}
