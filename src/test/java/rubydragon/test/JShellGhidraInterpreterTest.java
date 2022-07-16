package rubydragon.test;

import static org.junit.Assert.assertEquals;

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
	BufferedWriter inputWriter;

	@Before
	public void setUp() throws Exception {
		PipedOutputStream scriptInputOutStream = new PipedOutputStream();
		PipedInputStream scriptInputInStream = new PipedInputStream(scriptInputOutStream);

		PipedInputStream scriptOutputInStream = new PipedInputStream();
		PipedOutputStream scriptOutputOutStream = new PipedOutputStream(scriptOutputInStream);

		// the error stream would ideally also be captured, but this causes builds with
		// gradle to hang for an unknown reason

		interpreter = new JShellGhidraInterpreter(scriptInputInStream, scriptOutputOutStream, scriptOutputOutStream);

		outputReader = new BufferedReader(new InputStreamReader(scriptOutputInStream));
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

		assertEquals("The value should be printed", "3", outputReader.readLine());
	}
}
