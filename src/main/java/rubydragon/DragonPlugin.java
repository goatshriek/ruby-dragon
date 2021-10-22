package rubydragon;

import javax.swing.ImageIcon;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.interpreter.InterpreterConnection;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import resources.ResourceManager;

/**
 * A plugin for RubyDragon that provides an interactive interpreter for a chosen
 * language.
 */
public abstract class DragonPlugin extends ProgramPlugin implements InterpreterConnection {
	/**
	 * The name of this plugin instance.
	 */
	private String name;

	/**
	 * Creates a new DragonPlugin.
	 *
	 * @param tool The plugin tool that this plugin is added to.
	 *
	 * @param name The name of the language provided by the instance.
	 */
	public DragonPlugin(PluginTool tool, String name) {
		super(tool, true, true);
		this.name = name;
	}

	/**
	 * The icon for this plugin.
	 */
	@Override
	public ImageIcon getIcon() {
		String imageFilename = "images/" + name.toLowerCase() + ".png";
		return ResourceManager.loadImage(imageFilename);
	}

	/**
	 * Gives the interpreter currently in use by the plugin.
	 *
	 * @return The interpreter for this plugin.
	 */
	public abstract GhidraInterpreter getInterpreter();

	/**
	 * The title of the plugin.
	 */
	@Override
	public String getTitle() {
		return name;
	}

	/**
	 * Called whenever the highlight is changed within the CodeBrowser tool.
	 */
	@Override
	public void highlightChanged(ProgramSelection sel) {
		getInterpreter().updateHighlight(sel);
	}

	/**
	 * Called whenever the location is changed within the CodeBrowser tool.
	 */
	@Override
	public void locationChanged(ProgramLocation loc) {
		getInterpreter().updateLocation(loc);
	}

	/**
	 * Called whenever a program is activate within the CodeBrowser tool.
	 */
	@Override
	public void programActivated(Program program) {
		getInterpreter().updateProgram(program);
	}

	/**
	 * Called whenever the selection is changed within the CodeBrowser tool.
	 */
	@Override
	public void selectionChanged(ProgramSelection sel) {
		getInterpreter().updateSelection(sel);
	}

}
