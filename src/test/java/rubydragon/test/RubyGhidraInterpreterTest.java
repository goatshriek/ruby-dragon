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

import rubydragon.ruby.RubyGhidraInterpreter;

public class RubyGhidraInterpreterTest {

	private RubyGhidraInterpreter interpreter;
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

		interpreter = new RubyGhidraInterpreter();
		interpreter.setInput(scriptInputInStream);
		interpreter.setOutWriter(new PrintWriter(scriptOutputOutStream));

		outputReader = new BufferedReader(new InputStreamReader(scriptOutputInStream));
		inputWriter = new BufferedWriter(new OutputStreamWriter(scriptInputOutStream));
	}

	@After
	public void tearDown() throws Exception {
		interpreter.dispose();
	}

	@Test
	public void testPrint() throws Exception {
		interpreter.startInteractiveSession();

		inputWriter.write("puts 'test print'\n");
		inputWriter.flush();
		outputReader.readLine();

		assertEquals("The output should be printed", "test print", outputReader.readLine());
	}
}
