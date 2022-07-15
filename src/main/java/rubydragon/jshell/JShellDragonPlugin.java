package rubydragon.jshell;

import java.util.ArrayList;
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
import rubydragon.DragonPlugin;
import rubydragon.GhidraInterpreter;

/**
 * KotlinDragon provides Kotlin support within Ghidra, both in an interactive
 * terminal session as well as standalone scripts.
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
	private GhidraInterpreter interpreter;

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
		interpreter = new JShellGhidraInterpreter(console);
		console.setPrompt("> ");
		console.addFirstActivationCallback(() -> {
			interpreter.startInteractiveSession();
		});
	}
}
