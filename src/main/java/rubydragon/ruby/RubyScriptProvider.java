package rubydragon.ruby;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;

/**
 * Supports ruby scripts within ghidra.
 */
public class RubyScriptProvider extends GhidraScriptProvider {

	/**
	 * A short description of the type of scripts this provider supports.
	 */
	@Override
	public String getDescription() {
		return "Ruby";
	}

	/**
	 * The extension of ruby scripts, including the period.
	 */
	@Override
	public String getExtension() {
		return ".rb";
	}

	/**
	 * Creates a new RubyScript instance for the given file and returns it.
	 */
	@Override
	public GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
			throws ClassNotFoundException, InstantiationException, IllegalAccessException {
		GhidraScript script = new RubyScript();
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
	 * The comment character for ruby scripts.
	 */
	@Override
	public String getCommentCharacter() {
		return "#";
	}

}
