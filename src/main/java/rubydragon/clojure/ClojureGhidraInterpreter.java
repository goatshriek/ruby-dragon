package rubydragon.clojure;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

import clojure.lang.LineNumberingPushbackReader;
import clojure.lang.Namespace;
import clojure.lang.RT;
import clojure.lang.Symbol;
import clojure.lang.Var;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.exception.AssertException;
import rubydragon.GhidraInterpreter;

/**
 * A Clojure intepreter for Ghidra.
 */
public class ClojureGhidraInterpreter extends GhidraInterpreter {
	private Thread replThread;
	final private ClassLoader clojureClassLoader;

	public ClojureGhidraInterpreter() {
		clojureClassLoader = new ClojureGhidraClassLoader();
		ClassLoader previous = Thread.currentThread().getContextClassLoader();
		Thread.currentThread().setContextClassLoader(clojureClassLoader);
		Symbol CLOJURE_MAIN = Symbol.intern("clojure.main");
		Var REQUIRE = RT.var("clojure.core", "require");
		Var MAIN = RT.var("clojure.main", "main");
		RT.init();
		REQUIRE.invoke(CLOJURE_MAIN);
		replThread = new Thread(() -> {
			while (true) {
				MAIN.applyTo(RT.seq(new String[0]));
			}
		});
		Thread.currentThread().setContextClassLoader(previous);
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
		ClassLoader previous = Thread.currentThread().getContextClassLoader();
		Thread.currentThread().setContextClassLoader(clojureClassLoader);
		try {
			ResourceFile scriptFile = script.getSourceFile();
			loadState(scriptState);
			RT.var("ghidra", "script", script);

			// putting the methods from this script class into the interpreter
			// taken from the PythonScript class in the ghidra source
			for (Class<?> scriptClass = script.getClass(); scriptClass != Object.class; scriptClass = scriptClass
					.getSuperclass()) {

				// Add public and protected fields
				for (Field field : scriptClass.getDeclaredFields()) {
					if (Modifier.isPublic(field.getModifiers()) || Modifier.isProtected(field.getModifiers())) {
						try {
							field.setAccessible(true);
							RT.var("ghidra", field.getName(), field.get(script));
						} catch (IllegalAccessException iae) {
							throw new AssertException("Unexpected security manager being used!");
						}
					}
				}

				// Add public methods. Ignore inner classes.
				for (Method method : scriptClass.getDeclaredMethods()) {

					if (!method.getName().contains("$") && Modifier.isPublic(method.getModifiers())) {
						method.setAccessible(true);
						RT.var("ghidra", method.getName(), method);
					}
				}
			}

			RT.loadResourceScript(scriptFile.getAbsolutePath());
			updateState(scriptState);
		} finally {
			Thread.currentThread().setContextClassLoader(previous);
		}
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

	/**
	 * Updates a state with the current selection/location/etc. variables from the
	 * interpreter.
	 *
	 * @param scriptState The state to update.
	 */
	@Override
	public void updateState(GhidraState scriptState) {
		Namespace ghidraNS = Namespace.findOrCreate(Symbol.intern("ghidra"));
		Program currentProgram = (Program) Var.intern(ghidraNS, Symbol.intern("current-program")).get();
		scriptState.setCurrentProgram(currentProgram);

		ProgramLocation programLoc = (ProgramLocation) Var.intern(ghidraNS, Symbol.intern("current-location")).get();
		scriptState.setCurrentLocation(programLoc);

		Address addr = (Address) Var.intern(ghidraNS, Symbol.intern("current-address")).get();
		scriptState.setCurrentAddress(addr);

		ProgramSelection highlight = (ProgramSelection) Var.intern(ghidraNS, Symbol.intern("current-highlight")).get();
		scriptState.setCurrentHighlight(highlight);

		ProgramSelection sel = (ProgramSelection) Var.intern(ghidraNS, Symbol.intern("current-selection")).get();
		scriptState.setCurrentSelection(sel);
	}

	@Override
	public void updateProgram(Program program) {
		RT.var("ghidra", "current-program", program);
	}

}
