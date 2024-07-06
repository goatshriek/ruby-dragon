// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2021-2023 Joel E. Anderson
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

package com.goatshriek.rubydragon.ruby;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import com.goatshriek.rubydragon.DragonPlugin;
import com.goatshriek.rubydragon.GhidraInterpreter;
import com.goatshriek.rubydragon.pty.GhidraInterpreterPty;
import com.goatshriek.rubydragon.pty.GhidraInterpreterPtyFactory;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.core.interpreter.InterpreterConnection;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.services.Terminal;
import ghidra.app.services.TerminalService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.pty.Pty;
import ghidra.pty.PtyFactory;
import ghidra.pty.PtyParent;
import ghidra.pty.PtySession;

/**
 * RubyDragon provides Ruby support within Ghidra, both in an interactive
 * terminal session as well as standalone scripts.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = DragonPlugin.PLUGIN_CATEGORY_NAME,
	shortDescription = "Ruby Interpreter",
	description = "Provides an interactive Ruby Interpreter that is tightly integrated with a loaded Ghidra program.",
	servicesRequired = { TerminalService.class },
	isSlowInstallation = true
)
//@formatter:on
public class RubyDragonPlugin extends DragonPlugin implements InterpreterConnection {

//	private InterpreterConsole console;
	private Terminal terminal;
	private RubyGhidraInterpreter interpreter;

	private PipedInputStream errIn;
	private PipedOutputStream errOut;

	private PipedInputStream stdOutIn;
	private PipedOutputStream stdOutOut;

	private PipedInputStream stdInIn;
	private PipedOutputStream stdInOut;

	/**
	 * Plugin constructor.
	 *
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public RubyDragonPlugin(PluginTool tool) {
		super(tool, "Ruby");
		
		terminal = null;

		errIn = new PipedInputStream();
		stdOutIn = new PipedInputStream();
		stdInIn = new PipedInputStream();

		try {
			errOut = new PipedOutputStream(errIn);
			stdOutOut = new PipedOutputStream(stdOutIn);
			stdInOut = new PipedOutputStream(stdInIn);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * Destroys the plugin and any interpreters within.
	 */
	@Override
	protected void dispose() {
		interpreter.dispose();
//		console.dispose();
		super.dispose();
	}

	/**
	 * Gives the ruby interpreter currently in use.
	 *
	 * @return The ruby interpreter for this plugin. Will always be a
	 *         RubyGhidraInterpreter instance.
	 */
	@Override
	public GhidraInterpreter getInterpreter() {
		return interpreter;
	}

	/**
	 * Set up the plugin, including the creation of the interactive interpreter.
	 */
	@Override
	public void init() {
		super.init();

//		console = getTool().getService(InterpreterPanelService.class).createInterpreterPanel(this, false);
		TerminalService terminalService = getTool().getService(TerminalService.class);
		// .createWithStreams(StandardCharsets.UTF_8, stdOutIn,stdInOut);
		GhidraInterpreterPtyFactory f = new GhidraInterpreterPtyFactory();
		GhidraInterpreterPty pty;
		PtySession session;
		PtyParent parent;
		try {
			pty = (GhidraInterpreterPty) f.openpty();
			interpreter = (RubyGhidraInterpreter) pty.getInterpreter();
			session = pty.getChild().session(new String[] { "not-a-real-cmd" }, null);
			parent = pty.getParent();
			terminal = terminalService.createWithStreams(this, StandardCharsets.UTF_8, parent.getInputStream(),
					parent.getOutputStream());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
//		interpreter = new RubyGhidraInterpreter(stdInIn, stdOutOut, stdOutOut, this);
//		interpreter.setInput(stdInIn);
//		interpreter.setOutput(stdOutOut);
//		console.addFirstActivationCallback(() -> {
//			interpreter.startInteractiveSession();
//		});
		interpreter.startInteractiveSession();
	}

	/**
	 * Shows the interpreter console.
	 */
	@Override
	public void showConsole() {
//		console.show();
		terminal.toFront();
	}
}
