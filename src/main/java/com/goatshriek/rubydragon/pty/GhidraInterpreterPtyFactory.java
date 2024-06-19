// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2024 Joel E. Anderson
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

package com.goatshriek.rubydragon.pty;

import java.io.IOException;

import com.goatshriek.rubydragon.GhidraInterpreter;
import com.goatshriek.rubydragon.ruby.RubyGhidraInterpreter;

import ghidra.pty.PtyFactory;
public class GhidraInterpreterPtyFactory implements PtyFactory {
	private static final String TITLE = "Ruby Dragon Interpreter title";
	private static final int WRAP_LEN = 80;

	@Override
	public GhidraInterpreterPty openpty(short cols, short rows) throws IOException {
		GhidraInterpreterPty pty = new GhidraInterpreterPty(new RubyGhidraInterpreter());
		if (cols != 0 && rows != 0) {
			pty.getChild().setWindowSize(cols, rows);
		}
		return pty;
	}

	@Override
	public String getDescription() {
		// TODO: make this meaningful
		return "Ruby Dragon Interpreter description";
//		return "ssh:" + hostname + "(user=" + username + ",port=" + port + ")";
	}
}
