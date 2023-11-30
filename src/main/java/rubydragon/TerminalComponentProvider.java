package rubydragon;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;

import javax.swing.JComponent;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.interpreter.InterpreterConnection;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import resources.Icons;
import utility.function.Callback;

public class TerminalComponentProvider extends ComponentProviderAdapter implements InterpreterConsole {

	public TerminalComponentProvider(DragonPlugin plugin) {
		super(plugin.getTool(), plugin.getTitle(), plugin.getName());
	}

	public TerminalComponentProvider(TerminalPanelPlugin plugin, InterpreterConnection interpreter,
			boolean visible) {
        super(plugin.getTool(), interpreter.getTitle(), plugin.getName());
	}

	@Override
	public void dispose() {
		// TODO Auto-generated method stub

	}

	@Override
	public void clear() {
		// TODO Auto-generated method stub

	}

	@Override
	public InputStream getStdin() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public OutputStream getStdOut() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public OutputStream getStdErr() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public PrintWriter getOutWriter() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public PrintWriter getErrWriter() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setPrompt(String prompt) {
		// TODO Auto-generated method stub

	}

	@Override
	public void addAction(DockingAction action) {
		// TODO Auto-generated method stub

	}

	@Override
	public void addFirstActivationCallback(Callback activationCallback) {
		// TODO Auto-generated method stub

	}

	@Override
	public boolean isInputPermitted() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void setInputPermitted(boolean permitted) {
		// TODO Auto-generated method stub

	}

	@Override
	public void setTransient() {
		DockingAction disposeAction = new DockingAction("Remove Terminal", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
//				int choice = OptionDialog.showYesNoDialog(panel, "Remove Terminal?",
//						"Are you sure you want to permanently close the terminal?");
				int choice = OptionDialog.NO_OPTION; // TODO need panel to make a choice
				if (choice == OptionDialog.NO_OPTION) {
					return;
				}

				TerminalComponentProvider.this.dispose();
			}
		};
		disposeAction.setDescription("Remove terminal from tool");
		disposeAction.setToolBarData(new ToolBarData(Icons.STOP_ICON, null));
		disposeAction.setEnabled(true);

		addLocalAction(disposeAction);
	}

	@Override
	public void show() {
		// TODO Auto-generated method stub

	}

	@Override
	public void updateTitle() {
		// TODO Auto-generated method stub

	}

	@Override
	public JComponent getComponent() {
		// TODO Auto-generated method stub
		return null;
	}

}
