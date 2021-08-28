package rubydragon.ruby;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;

/**
 * A ghidra script written in Clojure.
 */
public class RubyScript extends GhidraScript {

	private RubyGhidraInterpreter interpreter;

	/**
	 * Creates a new script, with it's own interpreter instance.
	 */
	public RubyScript() {
		super();
		interpreter = new RubyGhidraInterpreter();
	}

	/**
	 * The category of these scripts.
	 */
	@Override
	public String getCategory() {
		return "Ruby";
	}

	/**
	 * Executes this script.
	 */
	@Override
	public void run() {
		final PrintWriter stderr = getStdErr();
		final PrintWriter stdout = getStdOut();

		interpreter.setErrWriter(stderr);
		interpreter.setOutWriter(stdout);

		try {
			interpreter.runScript(this, null, state);
		} catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		stderr.flush();
		stdout.flush();
	}

	/**
	 * Runs a script by name with the given arguments using the given state, within
	 * this script.
	 *
	 * If the script cannot be found but the script is not running in headless mode,
	 * the user will be prompted to ignore the error, which will cause the function
	 * to simply continue instead of throwing an IllegalArgumentException.
	 *
	 * @throws IllegalArgumentException if the script does not exist
	 * @throws IOException              if an error occurs getting the provider
	 * @throws IllegalAccessException   if an error occurs getting the script
	 * @throws InstantiationException   if an error occurs getting the script
	 * @throws ClassNotFoundException   if an error occurs getting the script
	 * @throws Exception                if an error occurs running the script
	 */
	@Override
	public void runScript(String scriptName, String[] scriptArguments, GhidraState scriptState) throws Exception {
		ResourceFile scriptSource = GhidraScriptUtil.findScriptByName(scriptName);
		if (scriptSource == null) {
			boolean shouldContinue = true;

			if (!isRunningHeadless()) {
				// spaces are left between the newlines on purpose
				String question = getScriptName() + " is attempting to run another script " + "[" + scriptName + "]"
						+ " that does not exist or can not be found.\n \n"
						+ "You can silently ignore this error, which could lead to bad results (choose Yes)\n"
						+ "or allow the calling script to receive the error (choose No).\n \n"
						+ "Do you wish to suppress this error?";
				shouldContinue = askYesNo("Script does not exist", question);
			}

			if (!shouldContinue) {
				throw new IllegalArgumentException("could not find a script with name " + scriptName);
			}

			return;
		}

		GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptSource);
		if (provider == null) {
			throw new IOException("Attempting to run subscript '" + scriptName + "': unable to run this script type.");
		}

		GhidraScript ghidraScript = provider.getScriptInstance(scriptSource, writer);
		ghidraScript.setScriptArgs(scriptArguments);

		if (scriptState == state) {
			updateStateFromVariables();
		}

		ghidraScript.execute(scriptState, monitor, writer);

		if (scriptState == state) {
			loadVariablesFromState();
		}
	}

	/**
	 * Gets the error output for this script.
	 *
	 * @return A writer for this script's error output.
	 */
	private PrintWriter getStdErr() {
		PluginTool tool = state.getTool();
		if (tool != null) {
			ConsoleService console = tool.getService(ConsoleService.class);
			if (console != null) {
				return console.getStdErr();
			}
		}
		return new PrintWriter(System.err, true);
	}

	/**
	 * Gets the standard output for this script.
	 *
	 * @return A writer for this script's standard output.
	 */
	private PrintWriter getStdOut() {
		PluginTool tool = state.getTool();
		if (tool != null) {
			ConsoleService console = tool.getService(ConsoleService.class);
			if (console != null) {
				return console.getStdOut();
			}
		}
		return new PrintWriter(System.out, true);
	}

}
