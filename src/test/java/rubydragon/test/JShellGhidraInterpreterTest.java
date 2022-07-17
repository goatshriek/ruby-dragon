package rubydragon.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import rubydragon.jshell.JShellGhidraInterpreter;

public class JShellGhidraInterpreterTest {

	private JShellGhidraInterpreter interpreter;
	BufferedReader outputReader;
	BufferedReader errorReader;
	BufferedWriter inputWriter;

	@Before
	public void setUp() throws Exception {
		PipedOutputStream scriptInputOutStream = new PipedOutputStream();
		PipedInputStream scriptInputInStream = new PipedInputStream(scriptInputOutStream);

		PipedInputStream scriptOutputInStream = new PipedInputStream();
		PipedOutputStream scriptOutputOutStream = new PipedOutputStream(scriptOutputInStream);

		PipedInputStream scriptErrorInStream = new PipedInputStream();
		PipedOutputStream scriptErrorOutStream = new PipedOutputStream(scriptErrorInStream);

		interpreter = new JShellGhidraInterpreter(scriptInputInStream, scriptOutputOutStream, scriptErrorOutStream);

		outputReader = new BufferedReader(new InputStreamReader(scriptOutputInStream));
		errorReader = new BufferedReader(new InputStreamReader(scriptErrorInStream));
		inputWriter = new BufferedWriter(new OutputStreamWriter(scriptInputOutStream));

		interpreter.startInteractiveSession();
	}

	@After
	public void tearDown() throws Exception {
		interpreter.dispose();
	}

	/**
	 * Writes the given command to the interpreter input stream.
	 *
	 * @param cmd The command to run.
	 * @throws IOException
	 */
	private void writeCommand(String cmd) throws IOException {
		inputWriter.write(cmd + "\n");
		inputWriter.flush();
	}

	@Test
	public void testCurrentAddressDeclared() throws Exception {
		writeCommand("currentAddress = null;");

		assertEquals("null should be printed", "null", outputReader.readLine());
		assertFalse(errorReader.ready());
	}

	@Test
	public void testCurrentHighlightDeclared() throws Exception {
		writeCommand("currentHighlight = null;");

		assertEquals("null should be printed", "null", outputReader.readLine());
		assertFalse(errorReader.ready());
	}

	@Test
	public void testCurrentLocationDeclared() throws Exception {
		writeCommand("currentLocation = null;");

		assertEquals("null should be printed", "null", outputReader.readLine());
		assertFalse(errorReader.ready());
	}

	@Test
	public void testCurrentProgramDeclared() throws Exception {
		writeCommand("currentProgram = null;");

		assertEquals("null should be printed", "null", outputReader.readLine());
		assertFalse(errorReader.ready());
	}

	@Test
	public void testCurrentSelectionDeclared() throws Exception {
		writeCommand("currentSelection = null;");

		assertEquals("null should be printed", "null", outputReader.readLine());
		assertFalse(errorReader.ready());
	}

	@Test
	public void testIntResult() throws Exception {
		writeCommand("int var = 3;");

		assertEquals("The initial value should be printed", "3", outputReader.readLine());
		assertFalse(errorReader.ready());

		writeCommand("var = 4;");

		assertEquals("The new value should be printed", "4", outputReader.readLine());
		assertFalse(errorReader.ready());
	}

	@Test
	public void testReset() throws Exception {
		writeCommand("String s = \"declared variable\";");

		assertEquals("The initial value should be printed", "\"declared variable\"", outputReader.readLine());
		assertFalse(errorReader.ready());

		interpreter.reset();

		writeCommand("s");
		String error = errorReader.readLine();
		assertTrue(error.contains("fail"));
	}
}
