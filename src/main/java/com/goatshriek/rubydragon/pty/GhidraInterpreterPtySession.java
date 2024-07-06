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

import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.goatshriek.rubydragon.GhidraInterpreter;

import ghidra.pty.PtySession;

public class GhidraInterpreterPtySession implements PtySession {

	private final GhidraInterpreter interpreter;

	public GhidraInterpreterPtySession(GhidraInterpreter interpreter) {
		this.interpreter = interpreter;
	}

	@Override
	public int waitExited() throws InterruptedException {
		return 0;
	}

	@Override
	public int waitExited(long timeout, TimeUnit unit) throws InterruptedException, TimeoutException {
	 return 0;
	}

	@Override
	public void destroyForcibly() {
		return;
	}

	@Override
	public String description() {
		// TODO make this meaningful
		return "Ruby Dragon interpreter terminal session";
	}
}
