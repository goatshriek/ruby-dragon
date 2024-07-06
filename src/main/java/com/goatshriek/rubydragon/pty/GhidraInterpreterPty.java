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
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

import com.goatshriek.rubydragon.GhidraInterpreter;

import ghidra.pty.Pty;
import ghidra.pty.PtyChild;
import ghidra.pty.PtyParent;

public class GhidraInterpreterPty implements Pty {
	private final GhidraInterpreter interpreter;
	private final GhidraInterpreterPtyParent parent;
	private final GhidraInterpreterPtyChild child;
	private PipedOutputStream parentOut;
	private PipedOutputStream childOut;
	private PipedInputStream parentIn;
	private PipedInputStream childIn;

	public GhidraInterpreterPty(GhidraInterpreter interpreter) {
		this.interpreter = interpreter;
		
		parentOut = new PipedOutputStream();
		childOut = new PipedOutputStream();
		try {
			childIn = new PipedInputStream(parentOut);
			parentIn = new PipedInputStream(childOut);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		interpreter.setInputStream(childIn);
		interpreter.setOutputStream(childOut);

		parent = new GhidraInterpreterPtyParent(interpreter, parentOut, parentIn);
		child = new GhidraInterpreterPtyChild(interpreter, childOut, childIn);
	}

	@Override
	public void close() {
		return;
	}

	@Override
	public PtyChild getChild() {
		return child;
	}
	
	public GhidraInterpreter getInterpreter() {
		return interpreter;
	}

	@Override
	public PtyParent getParent() {
		return parent;
	}
}
