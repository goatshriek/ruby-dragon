package rubydragon;

import java.io.FileNotFoundException;
import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;

/**
 * An interpreter that can also run scripts.
 */
public abstract class ScriptableGhidraInterpreter extends GhidraInterpreter {

	/**
	 * Loads a provided GhidraState into the interpreter.
	 *
	 * @param state The state to load.
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
	 * Runs the given script with the arguments and state provided.
	 *
	 * The provided state is loaded into the interpreter at the beginning of
	 * execution, and the values of the globals are then exported back into the
	 * state after it completes.
	 *
	 * If the script cannot be found but the script is not running in headless mode,
	 * the user will be prompted to ignore the error, which will cause the function
	 * to simply continue instead of throwing an IllegalArgumentException.
	 *
	 * @throws IllegalArgumentException if the script does not exist
	 * @throws IOException              if the script could not be read
	 * @throws FileNotFoundException    if the script file wasn't found
	 *
	 * @param script          The script to run.
	 *
	 * @param scriptArguments The arguments to pass to the script.
	 *
	 * @param scriptState     The script to load before the script runs, and update
	 *                        after the script finishes.
	 */
	public abstract void runScript(GhidraScript script, String[] scriptArguments, GhidraState scriptState)
			throws IllegalArgumentException, FileNotFoundException, IOException;

	/**
	 * Updates a state with the current selection/location/etc. variables from the
	 * interpreter.
	 *
	 * This is intended to be called after a call to runScript, to make sure that
	 * any updates made to these variables during execution are reflected in the end
	 * state.
	 *
	 * @param scriptState The state to update.
	 */
	public abstract void updateState(GhidraState scriptState);

}
