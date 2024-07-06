package com.goatshriek.rubydragon;

import org.jruby.embed.LocalContextScope;
import org.jruby.embed.LocalVariableBehavior;
import org.jruby.embed.ScriptingContainer;

public class IrbTest {

	public static void main(String[] args) {
		ScriptingContainer container = new ScriptingContainer(LocalContextScope.SINGLETHREAD,
				LocalVariableBehavior.PERSISTENT);
		container.setInput(System.in);
		container.setOutput(System.out);
		
		System.out.println(container.getProperty("jruby.console"));
		container.runScriptlet("puts 'start'");
		container.runScriptlet("require 'irb'");
		container.runScriptlet("require 'irb/completion'");
		container.runScriptlet("IRB.conf[:USE_AUTOCOMPLETE] = true");
		container.runScriptlet("IRB.conf[:USE_MULTILINE] = false");
		container.runScriptlet("IRB.start");
		container.runScriptlet("puts 'done'");
		container.terminate();
	}

}
