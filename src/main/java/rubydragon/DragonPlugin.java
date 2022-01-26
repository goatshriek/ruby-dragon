package rubydragon;

import java.io.IOException;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;

import javax.swing.ImageIcon;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.interpreter.InterpreterConnection;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.dialog.ExtensionDetails;
import ghidra.framework.plugintool.dialog.ExtensionException;
import ghidra.framework.plugintool.dialog.ExtensionUtils;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import resources.ResourceManager;
import rubydragon.clojure.ClojureDragonPlugin;
import rubydragon.kotlin.KotlinDragonPlugin;
import rubydragon.ruby.RubyDragonPlugin;

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
		this.downloadDependencies();
	}

	/**
	 * Downloads the dependencies for all known RubyDragon language plugins.
	 */
	public static void downloadAllDependencies() {
		downloadDependencies(ClojureDragonPlugin.DEPENDENCIES);
		downloadDependencies(KotlinDragonPlugin.DEPENDENCIES);
		downloadDependencies(RubyDragonPlugin.DEPENDENCIES);
	}

	/**
	 * Downloads all dependencies for this plugin into the RubyDragon extension
	 * install folder.
	 */
	public void downloadDependencies() {
		downloadDependencies(getDependencies());
	}

	/**
	 * Downloads all given dependencies into the RubyDragon extension install
	 * folder.
	 */
	public static void downloadDependencies(Collection<DragonDependency> dependencies) {
		try {
			for (ExtensionDetails det : ExtensionUtils.getExtensions()) {
				if (det.getName().equals("RubyDragon")) {
					for (DragonDependency dep : dependencies) {
						dep.download(Paths.get(det.getInstallPath(), "lib"));
					}
				}
			}
		} catch (ExtensionException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * Gets all of the dependencies needed by this plugin to function correctly.
	 *
	 * This should never return null. If no dependencies are needed, then this list
	 * will be empty.
	 *
	 * @return A Collection holding the plugin dependencies.
	 */
	public abstract Collection<DragonDependency> getDependencies();

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
