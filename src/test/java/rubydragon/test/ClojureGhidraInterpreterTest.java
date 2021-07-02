package rubydragon.test;

import static org.junit.Assert.assertEquals;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintWriter;

import org.junit.Test;

import rubydragon.clojure.ClojureGhidraInterpreter;

public class ClojureGhidraInterpreterTest {

	@Test
	public void testPrint() throws Exception {
		PipedOutputStream inOut = new PipedOutputStream();
		PipedInputStream inIn = new PipedInputStream(inOut);

		PipedInputStream outIn = new PipedInputStream();
		PipedOutputStream outOut = new PipedOutputStream(outIn);

		PipedInputStream errIn = new PipedInputStream();
		PipedOutputStream errOut = new PipedOutputStream(errIn);

		ClojureGhidraInterpreter interpreter = new ClojureGhidraInterpreter();
		interpreter.setInput(inIn);
		interpreter.setOutWriter(new PrintWriter(outOut));
		interpreter.setErrWriter(new PrintWriter(errOut));

		interpreter.startInteractiveSession();

		inOut.write("(println \"test print\")\n".getBytes());
		BufferedReader outReader = new BufferedReader(new InputStreamReader(outIn));
		outReader.readLine();
		assertEquals("The output should be printed", "user=> test print", outReader.readLine());

		inOut.write("\u0004".getBytes());
		interpreter.dispose();
	}
}
