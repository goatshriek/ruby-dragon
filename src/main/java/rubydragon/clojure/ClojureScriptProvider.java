package rubydragon.clojure;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;

/**
 * Supports clojure scripts within ghidra.
 */
public class ClojureScriptProvider extends GhidraScriptProvider {

	/**
	 * A short description of the type of scripts this provider supports.
	 */
	@Override
	public String getDescription() {
		return "Clojure";
	}

	/**
	 * The extension of clojure scripts, including the period.
	 */
	@Override
	public String getExtension() {
		return ".clj";
	}

	/**
	 * Creates a new ClojureScript instance for the given file and returns it.
	 */
	@Override
	public GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
			throws ClassNotFoundException, InstantiationException, IllegalAccessException {
		GhidraScript script = new ClojureScript();
		script.setSourceFile(sourceFile);
		return script;
	}

	/**
	 * Creates a new script file for the given script and category.
	 */
	@Override
	public void createNewScript(ResourceFile newScript, String category) throws IOException {
		PrintWriter writer = new PrintWriter(new FileWriter(newScript.getFile(false)));
		writeHeader(writer, category);
		writer.println("");
		writeBody(writer);
		writer.println("");
		writer.close();
	}

	/**
	 * The comment character for clojure scripts.
	 */
	@Override
	public String getCommentCharacter() {
		return ";";
	}

}
