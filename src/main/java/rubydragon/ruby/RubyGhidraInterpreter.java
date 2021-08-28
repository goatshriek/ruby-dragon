package rubydragon.ruby;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;

import org.jruby.embed.LocalContextScope;
import org.jruby.embed.LocalVariableBehavior;
import org.jruby.embed.ScriptingContainer;

import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import rubydragon.GhidraInterpreter;

/**
 * A Ruby interpreter for Ghidra, built using JRuby.
 */
public class RubyGhidraInterpreter extends GhidraInterpreter {
	private ScriptingContainer container;
	private Thread irbThread;
	private boolean disposed = false;

	/**
	 * Creates a new Ruby interpreter.
	 */
	public RubyGhidraInterpreter() {
		container = new ScriptingContainer(LocalContextScope.SINGLETHREAD, LocalVariableBehavior.PERSISTENT);
		irbThread = new Thread(() -> {
			while (!disposed) {
				container.runScriptlet("require 'irb';IRB.start");
			}
		});
	}

	/**
	 * Creates a new interpreter, and ties the streams for the provided console to
	 * the new interpreter.
	 *
	 * @param console The console to bind to the interpreter streams.
	 */
	public RubyGhidraInterpreter(InterpreterConsole console) {
		this();
		setStreams(console);
	}

	/**
	 * Should end the interpreter and release all resources. Currently does nothing.
	 */
	@Override
	public void dispose() {
		disposed = true;
		// container.terminate(); // makes ghidra hang on close
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
	 */
	@Override
	public void runScript(GhidraScript script, String[] scriptArguments, GhidraState scriptState)
			throws IllegalArgumentException, FileNotFoundException, IOException {
		InputStream scriptStream = script.getSourceFile().getInputStream();
		loadState(scriptState);
		container.put("$script", script);
		container.runScriptlet(scriptStream, script.getScriptName());
		updateState(scriptState);
	}

	/**
	 * Sets the error output stream for this interpreter.
	 */
	@Override
	public void setErrWriter(PrintWriter errOut) {
		container.setError(errOut);
	}

	/**
	 * Sets the input stream for this interpreter.
	 */
	@Override
	public void setInput(InputStream input) {
		container.setInput(input);
	}

	/**
	 * Sets the output stream for this interpreter.
	 */
	@Override
	public void setOutWriter(PrintWriter output) {
		container.setOutput(output);
	}

	@Override
	public void startInteractiveSession() {
		irbThread.start();
	}

	@Override
	public void updateAddress(Address address) {
		container.put("$current_address", address);
	}

	/**
	 * Updates the highlighted selection pointed to by the "$current_highlight"
	 * variable.
	 *
	 * @param sel The new highlighted selection.
	 */
	@Override
	public void updateHighlight(ProgramSelection sel) {
		container.put("$current_highlight", sel);
	}

	/**
	 * Updates the location in the "$current_location" variable as well as the
	 * address in the "$current_address" variable.
	 *
	 * @param loc The new location in the program.
	 */
	@Override
	public void updateLocation(ProgramLocation loc) {
		if (loc == null) {
			container.remove("$current_location");
		} else {
			container.put("$current_location", loc);
			updateAddress(loc.getAddress());
		}
	}

	/**
	 * Updates the current program in "$current_program" to the one provided.
	 *
	 * @param program The new current program.
	 */
	@Override
	public void updateProgram(Program program) {
		container.put("$current_program", program);
	}

	/**
	 * Updates the selection pointed to by the "$current_selection" variable.
	 *
	 * @param sel The new selection.
	 */
	@Override
	public void updateSelection(ProgramSelection sel) {
		container.put("$current_selection", sel);
	}

	/**
	 * Updates a state with the $current_*. variables from the interpreter.
	 *
	 * @param scriptState The state to update.
	 */
	@Override
	public void updateState(GhidraState scriptState) {
		scriptState.setCurrentProgram((Program) container.get("$current_program"));
		scriptState.setCurrentLocation((ProgramLocation) container.get("$current_location"));
		scriptState.setCurrentAddress((Address) container.get("$current_address"));
		scriptState.setCurrentHighlight((ProgramSelection) container.get("$current_highlight"));
		scriptState.setCurrentSelection((ProgramSelection) container.get("$current_selection"));
	}
}
