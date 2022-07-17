package rubydragon.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.io.BufferedReader;
import java.io.BufferedWriter;
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
	}

	@After
	public void tearDown() throws Exception {
		// interpreter.dispose();
	}

	@Test
	public void testIntResult() throws Exception {
		interpreter.startInteractiveSession();

		inputWriter.write("int var = 3;\n");
		inputWriter.flush();

		assertEquals("The initial value should be printed", "3", outputReader.readLine());
		assertFalse(errorReader.ready());

		inputWriter.write("var = 4;\n");
		inputWriter.flush();

		assertEquals("The new value should be printed", "4", outputReader.readLine());
		assertFalse(errorReader.ready());
	}
}
