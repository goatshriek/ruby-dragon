/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package rubydragon.clojure;

import java.util.ArrayList;
import java.util.List;

import javax.swing.ImageIcon;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.InterpreterConnection;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.plugin.core.interpreter.InterpreterPanelService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import resources.ResourceManager;
import rubydragon.GhidraInterpreter;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.INTERPRETERS,
	shortDescription = "Clojure Interpreter",
	description = "Provides an interactive Clojure interpreter integrated with loaded Ghidra programs.",
	servicesRequired = { InterpreterPanelService.class },
	isSlowInstallation = true
)
//@formatter:on
public class ClojureDragonPlugin extends ProgramPlugin implements InterpreterConnection {

	private InterpreterConsole console;
	private GhidraInterpreter interpreter;

	/**
	 * Plugin constructor.
	 *
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public ClojureDragonPlugin(PluginTool tool) {
		super(tool, true, true);
	}

	@Override
	protected void dispose() {
		interpreter.dispose();
		console.dispose();
		super.dispose();
	}

	@Override
	public String getTitle() {
		return "Clojure";
	}

	@Override
	public ImageIcon getIcon() {
		return ResourceManager.loadImage("images/clojure.png");
	}

	@Override
	public List<CodeCompletion> getCompletions(String cmd) {
		// TODO currently just an empty list, need to actually implement
		return new ArrayList<CodeCompletion>();
	}

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

	@Override
	public void highlightChanged(ProgramSelection sel) {
		interpreter.updateHighlight(sel);
	}

	@Override
	public void locationChanged(ProgramLocation loc) {
		interpreter.updateLocation(loc);
	}

	@Override
	public void programActivated(Program program) {
		interpreter.updateProgram(program);
	}

	@Override
	public void selectionChanged(ProgramSelection sel) {
		interpreter.updateSelection(sel);
	}
}
