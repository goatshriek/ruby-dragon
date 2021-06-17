package rubydragon;

import java.io.InputStream;
import java.io.PrintWriter;

import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.script.GhidraState;
import ghidra.program.model.address.Address;
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
	 * Loads a provided GhidraState into the interpreter.
	 *
	 * @param state
	 */
	public void loadState(GhidraState state) {
		updateHighlight(state.getCurrentHighlight());
		updateLocation(state.getCurrentLocation());
		updateSelection(state.getCurrentSelection());
		updateProgram(state.getCurrentProgram());

		// this has to happen after the location update
		// since it clobbers the current address right now
		updateAddress(state.getCurrentAddress());
	}

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
	 * Updates the current address in the interpreter.
	 *
	 * @param address The new current address in the program.
	 */
	public abstract void updateAddress(Address address);

	/**
	 * Updates the location in the current location variable as well as the address
	 * in the current address variable.
	 *
	 * @param loc The new location in the program.
	 */
	public abstract void updateLocation(ProgramLocation loc);

	/**
	 * Updates the selection pointed to by the current selection variable.
	 *
	 * @param sel The new selection.
	 */
	public abstract void updateSelection(ProgramSelection sel);

	/**
	 * Updates the highlighted selection pointed to by the current_highlight
	 * variable.
	 *
	 * @param sel The new highlighted selection.
	 */
	public abstract void updateHighlight(ProgramSelection sel);

	/**
	 * Updates the current program in current program to the one provided.
	 *
	 * @param program The new current program.
	 */
	public abstract void updateProgram(Program program);
}
