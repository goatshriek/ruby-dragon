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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

import com.goatshriek.rubydragon.GhidraInterpreter;
import com.jcraft.jsch.JSchException;

import ghidra.dbg.util.ShellUtils;
import ghidra.pty.PtyChild;
import ghidra.pty.ssh.SshPtySession;
import ghidra.util.Msg;

public class GhidraInterpreterPtyChild extends GhidraInterpreterPtyEndpoint implements PtyChild {
	private String name;

	public GhidraInterpreterPtyChild(GhidraInterpreter interpreter, OutputStream outputStream,
			InputStream inputStream) {
		super(interpreter, outputStream, inputStream);
	}

	@Override
	public GhidraInterpreterPtySession session(String[] args, Map<String, String> env, File workingDirectory,
			Collection<TermMode> mode) throws IOException {
		return new GhidraInterpreterPtySession(interpreter);
	}

	@Override
	public String nullSession(Collection<TermMode> mode) throws IOException {
		return "Ghidra interpreter null session";
	}

	@Override
	public void setWindowSize(short cols, short rows) {
		// TODO do we need to implement this?
		return;
	}
}
