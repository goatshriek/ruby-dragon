package rubydragon;

import java.io.InputStream;
import java.io.PrintWriter;

import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Disposable;

/**
 * An interpreter that users can use interactively as well as to run custom
 * scripts.
 */
public abstract class GhidraInterpreter implements Disposable {

	/**
	 * Cleans up all resources for this intepreter.
	 */
	public abstract void dispose();

	/**
	 * Sets the error output stream for this interpreter.
	 */
	public abstract void setErrWriter(PrintWriter errOut);

	/**
	 * Sets the input stream for this interpreter.
	 */
	public abstract void setInput(InputStream input);

	/**
	 * Sets the output stream for this interpreter.
	 */
	public abstract void setOutWriter(PrintWriter output);

	/**
	 * Sets the input, output, and error streams for this interpreter to those of
	 * the provided console.
	 * 
	 * @param console The console to tie the interpreter streams to.
	 */
	public void setStreams(InterpreterConsole console) {
		setInput(console.getStdin());
		setOutWriter(console.getOutWriter());
		setErrWriter(console.getErrWriter());
	}

	/**
	 * Starts an interactive session with the current input/output/error streams.
	 */
	public abstract void startInteractiveSession();

	/**
	 * Updates the location in the "$current_location" variable as well as the
	 * address in the "$current_address" variable.
	 */
	public abstract void updateLocation(ProgramLocation loc);

	/**
	 * Updates the selection pointed to by the "$current_selection" variable.
	 * 
	 * @param sel
	 */
	public abstract void updateSelection(ProgramSelection sel);

	/**
	 * Updates the highlighted selection pointed to by the "$current_highlight"
	 * variable.
	 * 
	 * @param sel
	 */
	public abstract void updateHighlight(ProgramSelection sel);

	/**
	 * Updates the current program in "$current_program" to the one provided.
	 * 
	 * @param program
	 */
	public abstract void updateProgram(Program program);
}
