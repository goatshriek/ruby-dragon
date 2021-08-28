// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2021 Joel E. Anderson
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
