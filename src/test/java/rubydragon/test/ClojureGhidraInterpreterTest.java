package rubydragon.test;

import static org.junit.Assert.assertEquals;

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
	BufferedWriter inputWriter;

	@Before
	public void setUp() throws Exception {
		PipedOutputStream inOut = new PipedOutputStream();
		PipedInputStream inIn = new PipedInputStream(inOut);

		PipedInputStream outIn = new PipedInputStream();
		PipedOutputStream outOut = new PipedOutputStream(outIn);

		PipedInputStream errIn = new PipedInputStream();
		PipedOutputStream errOut = new PipedOutputStream(errIn);

		interpreter = new ClojureGhidraInterpreter();
		interpreter.setInput(inIn);
		interpreter.setOutWriter(new PrintWriter(outOut));
		interpreter.setErrWriter(new PrintWriter(errOut));

		outputReader = new BufferedReader(new InputStreamReader(outIn));
		inputWriter = new BufferedWriter(new OutputStreamWriter(inOut));
	}

	@After
	public void tearDown() throws Exception {
		interpreter.dispose();
	}

	@Test
	public void testPrint() throws Exception {
		interpreter.startInteractiveSession();

		inputWriter.write("(println \"test print\")\n");
		inputWriter.flush();
		outputReader.readLine();
		assertEquals("The output should be printed", "user=> test print", outputReader.readLine());

		inputWriter.write("\u0004");
	}
}
