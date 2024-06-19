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

import java.io.InputStream;
import java.io.OutputStream;

import com.goatshriek.rubydragon.GhidraInterpreter;

import ghidra.pty.Pty;
import ghidra.pty.PtyChild;
import ghidra.pty.PtyParent;

public class GhidraInterpreterPty implements Pty {
	private final GhidraInterpreter interpreter;
	private final GhidraInterpreterPtyParent parent;
	private final GhidraInterpreterPtyChild child;

	public GhidraInterpreterPty(GhidraInterpreter interpreter) {
		this.interpreter = interpreter;

		out = interpreter.getOutputStream();
		in = interpreter.getInputStream();

		parent = new GhidraInterpreterPtyParent(interpreter, out, in);
		child = new GhidraInterpreterPtyChild(interpreter, out, in);
	}

	@Override
	public PtyParent getParent() {
		return parent;
	}

	@Override
	public PtyChild getChild() {
		return child;
	}

	@Override
	public void close() {
		return;
	}
}
