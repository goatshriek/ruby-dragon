package rubydragon;

import com.jediterm.terminal.TtyConnector;
import com.jediterm.terminal.ui.JediTermWidget;
import com.jediterm.terminal.ui.settings.DefaultSettingsProvider;
import org.jetbrains.annotations.NotNull;

import javax.swing.*;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PipedReader;
import java.io.PipedWriter;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class JeditermTest {
  private static final char ESC = 27;

  private static void writeTerminalCommands(@NotNull PipedWriter writer) throws IOException {
    writer.write(ESC + "%G");
    writer.write(ESC + "[31m");
    writer.write("Hello\r\n");
    writer.write(ESC + "[32;43m");
    writer.write("Wor\bld\r\n");
  }

  private static @NotNull JediTermWidget createTerminalWidget() {
    JediTermWidget widget = new JediTermWidget(80, 24, new DefaultSettingsProvider());
    PipedWriter terminalWriter = new PipedWriter();
    widget.setTtyConnector(new ExampleTtyConnector(terminalWriter));
    widget.start();
    try {
      writeTerminalCommands(terminalWriter);
      terminalWriter.close();
    } catch (IOException e) {
      e.printStackTrace();
    }
    return widget;
  }

  private static void createAndShowGUI() {
    JFrame frame = new JFrame("Basic Terminal Example");
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    frame.setContentPane(createTerminalWidget());
    frame.pack();
    frame.setVisible(true);
  }

  public static void main(String[] args) {
    // Create and show this application's GUI in the event-dispatching thread.
    SwingUtilities.invokeLater(JeditermTest::createAndShowGUI);
  }

  private static class ExampleTtyConnector implements TtyConnector {

    private final PipedReader myReader;

    public ExampleTtyConnector(@NotNull PipedWriter writer) {
      try {
        myReader =  new PipedReader(writer);
      } catch (IOException e) {
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
      return myReader.read(buf, offset, length);
    }

    @Override
    public void write(byte[] bytes) {
    	System.out.println("got: " + Arrays.toString(bytes));
    }

    @Override
    public boolean isConnected() {
      return true;
    }

    @Override
    public void write(String string) {
    	System.out.println("got string: " + string);
    }

    @Override
    public int waitFor() {
      return 0;
    }

    @Override
    public boolean ready() throws IOException {
      return myReader.ready();
    }

	private static class StdTtyConnector implements TtyConnector {

		private final Reader stdoutReader;
		private final PipedOutputStream stdinOutputStream;

		public StdTtyConnector(@NotNull PipedInputStream stdin, @NotNull PipedOutputStream stdout) {
			try {
				stdinOutputStream = new PipedOutputStream(stdin);
				stdoutReader = new InputStreamReader(new PipedInputStream(stdout), StandardCharsets.UTF_8);
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
			int result = stdoutReader.read(buf, offset, length);
			System.out.println("read bytes: " + Arrays.toString(buf));
			return result;
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


  }
}