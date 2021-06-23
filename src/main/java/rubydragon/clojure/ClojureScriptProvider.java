package rubydragon.clojure;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;

public class ClojureScriptProvider extends GhidraScriptProvider {

	@Override
	public String getDescription() {
		return "Clojure";
	}

	@Override
	public String getExtension() {
		return ".clj";
	}

	@Override
	public GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
			throws ClassNotFoundException, InstantiationException, IllegalAccessException {
		GhidraScript script = new ClojureScript();
		script.setSourceFile(sourceFile);
		return script;
	}

	@Override
	public void createNewScript(ResourceFile newScript, String category) throws IOException {
		PrintWriter writer = new PrintWriter(new FileWriter(newScript.getFile(false)));
		writeHeader(writer, category);
		writer.println("");
		writeBody(writer);
		writer.println("");
		writer.close();
	}

	@Override
	public String getCommentCharacter() {
		return ";";
	}

}
