//Downloads dependencies (`jar`s) for all RubyDragon language plugins which need
//them. This is available as a script that can be run in headless mode to do
//setup before running other RubyDragon scripts.
//
//You will likely need to restart Ghidra in order for dependencies that have
//been downloaded take effect.
//
//@category RubyDragon

import ghidra.app.script.GhidraScript;
import rubydragon.DragonPlugin;

public class DownloadDependenciesScript extends GhidraScript {

	@Override
	public void run() {
		DragonPlugin.downloadAllDependencies(monitor);
	}
}
