package rubydragon.clojure;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;

import clojure.lang.LineNumberingPushbackReader;
import clojure.lang.RT;
import clojure.lang.Symbol;
import clojure.lang.Var;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import rubydragon.GhidraInterpreter;

/**
 * A Clojure intepreter for Ghidra.
 */
public class ClojureGhidraInterpreter extends GhidraInterpreter {
	private Thread replThread;

	public ClojureGhidraInterpreter() {
		Symbol CLOJURE_MAIN = Symbol.intern("clojure.main");
		Var REQUIRE = RT.var("clojure.core", "require");
		Var MAIN = RT.var("clojure.main", "main");
		RT.init();
		REQUIRE.invoke(CLOJURE_MAIN);
		RT.var("ghidra", "current-address", "not-initialized-yet");
		replThread = new Thread(() -> {
			while (true) {
				MAIN.applyTo(RT.seq(new String[0]));
			}
		});
	}

	public ClojureGhidraInterpreter(InterpreterConsole console) {
		this();
		setStreams(console);
	}

	@Override
	public void dispose() {
		// TODO Auto-generated method stub

	}

	@Override
	public void runScript(GhidraScript script, String[] scriptArguments, GhidraState scriptState)
			throws IllegalArgumentException, FileNotFoundException, IOException {
		// TODO Auto-generated method stub

	}

	/**
	 * Sets the error output stream for this interpreter.
	 */
	@Override
	public void setErrWriter(PrintWriter errOut) {
		Var.intern(RT.CLOJURE_NS, Symbol.intern("*err*"), errOut);
	}

	/**
	 * Sets the input stream for this interpreter.
	 */
	@Override
	public void setInput(InputStream input) {
		LineNumberingPushbackReader inReader = new LineNumberingPushbackReader(new InputStreamReader(input));
		Var.intern(RT.CLOJURE_NS, Symbol.intern("*in*"), inReader);
	}

	/**
	 * Sets the output stream for this interpreter.
	 */
	@Override
	public void setOutWriter(PrintWriter output) {
		Var.intern(RT.CLOJURE_NS, Symbol.intern("*out*"), output);
	}

	@Override
	public void startInteractiveSession() {
		replThread.start();
	}

	@Override
	public void updateAddress(Address address) {
		RT.var("ghidra", "current-address", address);
	}

	@Override
	public void updateHighlight(ProgramSelection sel) {
		RT.var("ghidra", "current-highlight", sel);
	}

	@Override
	public void updateLocation(ProgramLocation loc) {
		RT.var("ghidra", "current-location", loc);
		if (loc != null) {
			updateAddress(loc.getAddress());
		}
	}

	@Override
	public void updateSelection(ProgramSelection sel) {
		RT.var("ghidra", "current-selection", sel);
	}

	@Override
	public void updateProgram(Program program) {
		RT.var("ghidra", "current-program", program);
	}

}
