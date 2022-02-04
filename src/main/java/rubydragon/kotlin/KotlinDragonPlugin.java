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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.InterpreterConnection;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.plugin.core.interpreter.InterpreterPanelService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import rubydragon.DragonDependency;
import rubydragon.DragonPlugin;
import rubydragon.GhidraInterpreter;
import rubydragon.MissingDragonDependency;

/**
 * KotlinDragon provides Kotlin support within Ghidra, both in an interactive
 * terminal session as well as standalone scripts.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.INTERPRETERS,
	shortDescription = "Kotlin Interpreter",
	description = "Provides an interactive Kotlin interpreter integrated with loaded Ghidra programs.",
	servicesRequired = { InterpreterPanelService.class },
	isSlowInstallation = true
)
//@formatter:on
public class KotlinDragonPlugin extends DragonPlugin implements InterpreterConnection {

	//@formatter:off
	public static final Collection<DragonDependency> DEPENDENCIES = Arrays.asList(
		new DragonDependency(
			"annotations-13.0.jar",
			"https://search.maven.org/remotecontent?filepath=org/jetbrains/annotations/13.0/annotations-13.0.jar",
			"ace2a10dc8e2d5fd34925ecac03e4988b2c0f851650c94b8cef49ba1bd111478"),
		new DragonDependency(
			"jna-5.6.0.jar",
			"https://search.maven.org/remotecontent?filepath=net/java/dev/jna/jna/5.6.0/jna-5.6.0.jar",
			"5557e235a8aa2f9766d5dc609d67948f2a8832c2d796cea9ef1d6cbe0b3b7eaf"),
		new DragonDependency(
			"kotlin-compiler-embeddable-1.6.0.jar",
			"https://search.maven.org/remotecontent?filepath=org/jetbrains/kotlin/kotlin-compiler-embeddable/1.6.0/kotlin-compiler-embeddable-1.6.0.jar",
			"0366843cd2defdd583c6b16b10bc32b85f28c5bf9510f10e44c886f5bd24c388"),
		new DragonDependency(
			"kotlin-daemon-embeddable-1.6.0.jar",
			"https://search.maven.org/remotecontent?filepath=org/jetbrains/kotlin/kotlin-daemon-embeddable/1.6.0/kotlin-daemon-embeddable-1.6.0.jar",
			"20d08706aa17762fe5ab03a916d62c9b7ee211d20844a8aabe0db83d9d90284a"),
		new DragonDependency(
			"kotlin-reflect-1.6.0.jar",
			"https://search.maven.org/remotecontent?filepath=org/jetbrains/kotlin/kotlin-reflect/1.6.0/kotlin-reflect-1.6.0.jar",
			"c6161884209221db7f5ddb031bb480a3c46bb90d5b65d7cc0167b149aaa9c494"),
		new DragonDependency(
			"kotlin-script-runtime-1.6.0.jar",
			"https://search.maven.org/remotecontent?filepath=org/jetbrains/kotlin/kotlin-script-runtime/1.6.0/kotlin-script-runtime-1.6.0.jar",
			"ddca0f765c416e77a4d8816f3d2df6eda953f61af811737846a22033225a0e57"),
		new DragonDependency(
			"kotlin-script-util-1.6.0.jar",
			"https://search.maven.org/remotecontent?filepath=org/jetbrains/kotlin/kotlin-script-util/1.6.0/kotlin-script-util-1.6.0.jar",
			"b731c9eaf94d22a08f9f86e4b9dd53236ba3883c802c9281dec6049775fd8128"),
		new DragonDependency(
			"kotlin-scripting-common-1.6.0.jar",
			"https://search.maven.org/remotecontent?filepath=org/jetbrains/kotlin/kotlin-scripting-common/1.6.0/kotlin-scripting-common-1.6.0.jar",
			"16699b070afc4422300c9ed66e81e98b65f7c691faa852b8d44195e509dd6d22"),
		new DragonDependency(
			"kotlin-scripting-compiler-embeddable-1.6.0.jar",
			"https://search.maven.org/remotecontent?filepath=org/jetbrains/kotlin/kotlin-scripting-compiler-embeddable/1.6.0/kotlin-scripting-compiler-embeddable-1.6.0.jar",
			"2cd1c6f6af69c16b7934d7d8d67c183349b434f450482d7229a9607136fa0447"),
		new DragonDependency(
			"kotlin-scripting-compiler-impl-embeddable-1.6.0.jar",
			"https://search.maven.org/remotecontent?filepath=org/jetbrains/kotlin/kotlin-scripting-compiler-impl-embeddable/1.6.0/kotlin-scripting-compiler-impl-embeddable-1.6.0.jar",
			"e4bd48906746e4cd19e016445599dca2683a994da06ac38cad383aac48338da8"),
		new DragonDependency(
			"kotlin-scripting-jsr223-1.6.0.jar",
			"https://search.maven.org/remotecontent?filepath=org/jetbrains/kotlin/kotlin-scripting-jsr223/1.6.0/kotlin-scripting-jsr223-1.6.0.jar",
			"a6f721ccc064e0ee4634ddaabce58783c347d7b3b9fa51f84c8252fee8ac0dcc"),
		new DragonDependency(
			"kotlin-scripting-jvm-1.6.0.jar",
			"https://search.maven.org/remotecontent?filepath=org/jetbrains/kotlin/kotlin-scripting-jvm/1.6.0/kotlin-scripting-jvm-1.6.0.jar",
			"5f6a7ea274cb6c6c4372094a3572df2a392aa5389f1553b824873d62d6003652"),
		new DragonDependency(
			"kotlin-scripting-jvm-host-1.6.0.jar",
			"https://search.maven.org/remotecontent?filepath=org/jetbrains/kotlin/kotlin-scripting-jvm-host/1.6.0/kotlin-scripting-jvm-host-1.6.0.jar",
			"376bf30d5055b8e845e388e698f8b2546c827a6cd8a540ec4d401ccb9f5cba08"),
		new DragonDependency(
			"kotlin-stdlib-1.6.0.jar",
			"https://search.maven.org/remotecontent?filepath=org/jetbrains/kotlin/kotlin-stdlib/1.6.0/kotlin-stdlib-1.6.0.jar",
			"115daea30b0d484afcf2360237b9d9537f48a4a2f03f3cc2a16577dfc6e90342"),
		new DragonDependency(
			"kotlin-stdlib-common-1.6.0.jar",
			"https://search.maven.org/remotecontent?filepath=org/jetbrains/kotlin/kotlin-stdlib-common/1.6.0/kotlin-stdlib-common-1.6.0.jar",
			"644a7257c23b51a1fd5068960e40922e3e52c219f11ece3e040a3abc74823f22"),
		new DragonDependency(
			"trove4j-1.0.20181211.jar",
			"https://search.maven.org/remotecontent?filepath=org/jetbrains/intellij/deps/trove4j/1.0.20181211/trove4j-1.0.20181211.jar",
			"affb7c85a3c87bdcf69ff1dbb84de11f63dc931293934bc08cd7ab18de083601"));
	//@formatter:on

	private InterpreterConsole console;
	private GhidraInterpreter interpreter;

	/**
	 * Plugin constructor.
	 *
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public KotlinDragonPlugin(PluginTool tool) {
		super(tool, "Kotlin");
	}

	/**
	 * Destroys the plugin and any interpreters within.
	 */
	@Override
	protected void dispose() {
		interpreter.dispose();
		console.dispose();
		super.dispose();
	}

	/**
	 * Gets all of the dependencies needed by KotlinDragon to function correctly.
	 *
	 * This is simply a wrapper for the static DEPENDENCIES class variable.
	 *
	 * @return A Collection holding all KotlinDragon dependencies.
	 */
	@Override
	public Collection<DragonDependency> getDependencies() {
		return DEPENDENCIES;
	}

	/**
	 * Gives the clojure interpreter currently in use.
	 *
	 * @return The clojure interpreter for this plugin. Will always be a
	 *         ClojureGhidraInterpreter instance.
	 */
	@Override
	public GhidraInterpreter getInterpreter() {
		return interpreter;
	}

	/**
	 * Get a list of completions for the given command prefix.
	 *
	 * Currently not implemented, and will always return an empty list.
	 */
	@Override
	public List<CodeCompletion> getCompletions(String cmd) {
		// TODO currently just an empty list, need to actually implement
		return new ArrayList<CodeCompletion>();
	}

	/**
	 * Set up the plugin, including the creation of the interactive interpreter.
	 */
	@Override
	public void init() {
		super.init();

		console = getTool().getService(InterpreterPanelService.class).createInterpreterPanel(this, false);
		try {
			interpreter = new KotlinGhidraInterpreter(console);
		} catch (MissingDragonDependency e) {
			throw new RuntimeException(e.getMessage());
		}
		console.setPrompt("> ");
		console.addFirstActivationCallback(() -> {
			interpreter.startInteractiveSession();
		});
	}
}
