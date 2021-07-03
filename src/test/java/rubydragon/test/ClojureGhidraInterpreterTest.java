package rubydragon.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintWriter;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import rubydragon.clojure.ClojureGhidraInterpreter;

public class ClojureGhidraInterpreterTest {

	private ClojureGhidraInterpreter interpreter;
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

		interpreter = new ClojureGhidraInterpreter();
		interpreter.setInput(scriptInputInStream);
		interpreter.setOutWriter(new PrintWriter(scriptOutputOutStream));
		interpreter.setErrWriter(new PrintWriter(scriptErrorOutStream));

		outputReader = new BufferedReader(new InputStreamReader(scriptOutputInStream));
		errorReader = new BufferedReader(new InputStreamReader(scriptErrorInStream));
		inputWriter = new BufferedWriter(new OutputStreamWriter(scriptInputOutStream));
	}

	@After
	public void tearDown() throws Exception {
		interpreter.dispose();
		inputWriter.write("\u0004");
	}

	@Test
	public void testPrint() throws Exception {
		interpreter.startInteractiveSession();

		inputWriter.write("(println \"test print\")\n");
		inputWriter.flush();
		outputReader.readLine();
		assertEquals("The output should be printed", "user=> test print", outputReader.readLine());
		assertFalse(errorReader.ready());
	}
}
