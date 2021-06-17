package rubydragon.clojure;

import java.io.InputStream;
import java.io.PrintWriter;

import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import rubydragon.GhidraInterpreter;

/**
 * A Clojure intepreter for Ghidra.
 */
public class ClojureGhidraInterpreter extends GhidraInterpreter {

	@Override
	public void dispose() {
		// TODO Auto-generated method stub

	}

	/**
	 * Sets the error output stream for this interpreter.
	 */
	@Override
	public void setErrWriter(PrintWriter errOut) {
		// TODO Auto-generated method stub

	}

	/**
	 * Sets the input stream for this interpreter.
	 */
	@Override
	public void setInput(InputStream input) {
		// TODO Auto-generated method stub

	}

	/**
	 * Sets the output stream for this interpreter.
	 */
	@Override
	public void setOutWriter(PrintWriter output) {
		// TODO Auto-generated method stub

	}

	@Override
	public void startInteractiveSession() {
		// TODO Auto-generated method stub

	}

	@Override
	public void updateLocation(ProgramLocation loc) {
		// TODO Auto-generated method stub

	}

	@Override
	public void updateSelection(ProgramSelection sel) {
		// TODO Auto-generated method stub

	}

	@Override
	public void updateHighlight(ProgramSelection sel) {
		// TODO Auto-generated method stub

	}

	@Override
	public void updateProgram(Program program) {
		// TODO Auto-generated method stub

	}

}
