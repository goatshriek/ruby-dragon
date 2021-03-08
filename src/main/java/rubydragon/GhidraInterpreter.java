package rubydragon;

import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Disposable;

/**
 * An interpreter that users can use interactively as well as to run custom
 * scripts.
 */
public interface GhidraInterpreter extends Disposable {

	/**
	 * Cleans up all resources for this intepreter.
	 */
	public void dispose();

	/**
	 * Sets the input, output, and error streams for this interpreter to those of
	 * the provided console.
	 * 
	 * @param console The console to tie the interpreter streams to.
	 */
	public void setStreams(InterpreterConsole console);

	/**
	 * Starts an interactive session with the current input/output/error streams.
	 */
	public void startInteractiveSession();

	/**
	 * Updates the location in the "$current_location" variable as well as the
	 * address in the "$current_address" variable.
	 */
	public void updateLocation(ProgramLocation loc);

	/**
	 * Updates the selection pointed to by the "$current_selection" variable.
	 * 
	 * @param sel
	 */
	public void updateSelection(ProgramSelection sel);

	/**
	 * Updates the highlighted selection pointed to by the "$current_highlight"
	 * variable.
	 * 
	 * @param sel
	 */
	public void updateHighlight(ProgramSelection sel);

	/**
	 * Updates the current program in "$current_program" to the one provided.
	 * 
	 * @param program
	 */
	public void updateProgram(Program program);
}
