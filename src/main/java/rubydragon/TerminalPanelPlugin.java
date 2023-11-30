package rubydragon;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.interpreter.InterpreterComponentProvider;
import ghidra.app.plugin.core.interpreter.InterpreterConnection;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.plugin.core.interpreter.InterpreterPanelService;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

//@formatter:off
@PluginInfo(
  status = PluginStatus.STABLE,
  packageName = CorePluginPackage.NAME,
  category = PluginCategoryNames.SUPPORT,
  shortDescription = "Terminal panel service",
  description = "Provides an interpreter panel with terminal support",
  servicesProvided = { InterpreterPanelService.class }
)
//@formatter:on
public class TerminalPanelPlugin extends Plugin implements InterpreterPanelService {

	public TerminalPanelPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	public InterpreterConsole createInterpreterPanel(InterpreterConnection interpreter, boolean visible) {
        return new TerminalComponentProvider(this, interpreter, visible);
    }

}
