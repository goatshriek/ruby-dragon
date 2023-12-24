package rubydragon;

import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintWriter;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.swing.Action;
import javax.swing.ActionMap;
import javax.swing.Icon;
import javax.swing.InputMap;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;

import org.jetbrains.annotations.NotNull;

import com.jediterm.terminal.TtyConnector;
import com.jediterm.terminal.ui.JediTermWidget;
import com.jediterm.terminal.ui.settings.DefaultSettingsProvider;

import docking.ActionContext;
import docking.DockingUtils;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.actions.KeyBindingUtils;
import docking.widgets.OptionDialog;
import generic.theme.GIcon;
import ghidra.app.plugin.core.interpreter.InterpreterConnection;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import resources.Icons;
import utility.function.Callback;

public class TerminalComponentProvider extends ComponentProviderAdapter implements InterpreterConsole {

	private List<Callback> firstActivationCallbacks;
	private JediTermWidget widget;
	private JTextArea panel;
	PipedInputStream stdin;
	PipedOutputStream stdout;
	PrintWriter stdoutWriter;

	public TerminalComponentProvider(DragonPlugin plugin) {
		super(plugin.getTool(), plugin.getTitle(), plugin.getName());
		System.out.println("called simple constructor");
	}

	public TerminalComponentProvider(TerminalPanelPlugin plugin, InterpreterConnection interpreter, boolean visible) {
		super(plugin.getTool(), interpreter.getTitle(), plugin.getName());
		firstActivationCallbacks = new ArrayList<>();

		widget = new JediTermWidget(80, 24, new DefaultSettingsProvider());
		stdin = new PipedInputStream();
		stdout = new PipedOutputStream();
		stdoutWriter = new PrintWriter(stdout);
		widget.setTtyConnector(new StdTtyConnector(stdin, stdout));
		widget.start();
		widget.addKeyListener(new KeyListener() {
			private void handleEvent(KeyEvent e) {
				System.out.println("widget key event handled: " + e.toString());
			}

			@Override
			public void keyTyped(KeyEvent e) {
				handleEvent(e);
			}

			@Override
			public void keyReleased(KeyEvent e) {
				handleEvent(e);
			}

			@Override
			public void keyPressed(KeyEvent e) {
				handleEvent(e);
			}
		});

//		panel = new TerminalJPanel();
		panel = new JTextArea();
		panel.add(widget);
		panel.setFocusable(true);

		addToTool();

		panel.addKeyListener(new KeyListener() {
			private void handleEvent(KeyEvent e) {
				System.out.println("panel key event handled: " + e.toString());

				// Send everything else down to the widget.
				KeyBindingUtils.retargetEvent(widget, e);
			}

			@Override
			public void keyTyped(KeyEvent e) {
				handleEvent(e);
			}

			@Override
			public void keyReleased(KeyEvent e) {
				handleEvent(e);
			}

			@Override
			public void keyPressed(KeyEvent e) {
				handleEvent(e);
			}
		});

		// in create actions elsewhere
		DockingAction clearAction = new DockingAction("Clear Interpreter", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				clear();
			}
		};
		clearAction.setDescription("Clear Interpreter");
		clearAction.setToolBarData(new ToolBarData(Icons.CLEAR_ICON, null));
		clearAction.setEnabled(true);

		addLocalAction(clearAction);

		Icon icon = interpreter.getIcon();
		if (icon == null) {
			icon = new GIcon("icon.plugin.interpreter.provider");
		}
		setIcon(icon);

		setVisible(visible);
	}

	@Override
	public void componentActivated() {
		// Since we only care about the first activation, clear the list of callbacks so
		// future activations don't trigger anything. First save them off to a local
		// list so when we process them we aren't affected by concurrent modification
		// due to reentrance.
		List<Callback> callbacks = new ArrayList<>(firstActivationCallbacks);
		firstActivationCallbacks.clear();

		// Call the callbacks
		callbacks.forEach(l -> l.call());
	}

	@Override
	public void dispose() {
		removeFromTool();
	}

	@Override
	public void clear() {
		// TODO need to implement
	}

	@Override
	public InputStream getStdin() {
		return stdin;
	}

	@Override
	public OutputStream getStdOut() {
		return stdout;
	}

	@Override
	public OutputStream getStdErr() {
		return getStdOut();
	}

	@Override
	public PrintWriter getOutWriter() {
		return stdoutWriter;
	}

	@Override
	public PrintWriter getErrWriter() {
		return getOutWriter();
	}

	@Override
	public void setPrompt(String prompt) {
		// TODO this isn't supported right now
	}

	@Override
	public void addAction(DockingAction action) {
		addLocalAction(action);
	}

	@Override
	public void addFirstActivationCallback(Callback activationCallback) {
		firstActivationCallbacks.add(activationCallback);
	}

	@Override
	public boolean isInputPermitted() {
		System.out.println("input permitted: " + widget.isEnabled());
		return widget.isEnabled();
	}

	@Override
	public void setInputPermitted(boolean permitted) {
		System.out.println("setting input permitted to: " + permitted);
		widget.setEnabled(permitted);
	}

	@Override
	public void setTransient() {
		DockingAction disposeAction = new DockingAction("Remove Terminal", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				int choice = OptionDialog.showYesNoDialog(panel, "Remove Terminal?",
						"Are you sure you want to permanently close the terminal?");
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
		tool.showComponentProvider(this, true);
	}

	@Override
	public void updateTitle() {
		tool.updateTitle(this);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	private static class StdTtyConnector implements TtyConnector {

		private final Reader stdoutReader;
		private final PipedOutputStream stdinOutputStream;

		public StdTtyConnector(@NotNull PipedInputStream stdin, @NotNull PipedOutputStream stdout) {
			try {
				stdinOutputStream = new PipedOutputStream(stdin);
				stdoutReader = new InputStreamReader(new PipedInputStream(stdout));
			} catch (IOException e) {
				// TODO deal with this better
				throw new RuntimeException(e);
			}
		}

		@Override
		public void close() {
		}

		@Override
		public String getName() {
			return null;
		}

		@Override
		public int read(char[] buf, int offset, int length) throws IOException {
			return stdoutReader.read(buf, offset, length);
		}

		@Override
		public void write(byte[] bytes) {
			try {
				System.out.println("writing bytes: " + Arrays.toString(bytes));
				stdinOutputStream.write(bytes);
				stdinOutputStream.flush();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		@Override
		public boolean isConnected() {
			return true;
		}

		@Override
		public void write(String string) {
			write(string.getBytes(StandardCharsets.UTF_8));
		}

		@Override
		public int waitFor() {
			return 0;
		}

		@Override
		public boolean ready() throws IOException {
			return stdoutReader.ready();
		}

	}

	private class TerminalJPanel extends JPanel {
		@Override
		protected void processKeyEvent(KeyEvent e) {
			System.out.println("got a key event!");
			System.out.println(e.toString());
		}
		
		@Override
        protected boolean processKeyBinding(KeyStroke ks, KeyEvent e, int condition,
                boolean pressed) {
			System.out.println("keybinding called");

            InputMap map = getInputMap(condition);
            ActionMap am = getActionMap();
            if (map != null && am != null && isEnabled()) {
                Object binding = map.get(ks);
                Action action = (binding == null) ? null : am.get(binding);
                if (action != null) {
                    if (!action.isEnabled()) {
                        // we want to consume the event here, so Ghidra doesn't get to
                        // process it when the actions are disabled
                        e.consume();
                        return true;
                    }

                    return SwingUtilities.notifyAction(action, ks, e, this, e.getModifiersEx());
                }
            }
            return false;
        }
	}

}
