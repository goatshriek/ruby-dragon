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

package rubydragon.kotlin;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.regex.Pattern;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptLoadException;
import ghidra.app.script.GhidraScriptProvider;
import rubydragon.MissingDragonDependency;

/**
 * Supports Kotlin scripts within Ghidra.
 */
public class KotlinScriptProvider extends GhidraScriptProvider {
	/**
	 * A pattern to match the beginning of a block comment.
	 */
	private static final Pattern BLOCK_COMMENT_START = Pattern.compile("/\\*");

	/**
	 * A pattern to match the end of a block comment.
	 */
	private static final Pattern BLOCK_COMMENT_END = Pattern.compile("\\*/");

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
	 * Returns a Pattern that matches block comment openings. For Kotlin this is
	 * "/*".
	 *
	 * @return the Pattern for Kotlin block comment openings
	 */
	@Override
	public Pattern getBlockCommentStart() {
		return BLOCK_COMMENT_START;
	}

	/**
	 * Returns a Pattern that matches block comment closings. In Kotlin this is an
	 * asterisk followed by a forward slash.
	 *
	 * @return the Pattern for Kotlin block comment closings
	 */
	@Override
	public Pattern getBlockCommentEnd() {
		return BLOCK_COMMENT_END;
	}

	/**
	 * The comment character for Kotlin scripts.
	 */
	@Override
	public String getCommentCharacter() {
		return "//";
	}

	/**
	 * A short description of the type of scripts this provider supports.
	 */
	@Override
	public String getDescription() {
		return "Kotlin";
	}

	/**
	 * The extension of Kotlin scripts, including the period.
	 */
	@Override
	public String getExtension() {
		return ".kts";
	}

	/**
	 * Creates a new KotlinScript instance for the given file and returns it.
	 */
	@Override
	public GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
			throws GhidraScriptLoadException {
		GhidraScript script;
		try {
			script = new KotlinScript();
		} catch (MissingDragonDependency e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		script.setSourceFile(sourceFile);
		return script;
	}

}
