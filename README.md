# Ruby Dragon
[![build](https://github.com/goatshriek/ruby-dragon/actions/workflows/build.yml/badge.svg)](https://github.com/goatshriek/ruby-dragon/actions/workflows/build.yml)
[![Apache 2.0 License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

[Ruby](#ruby-usage), [Kotlin](#kotlin-usage), [JShell](#jshell-usage), and
[Clojure](#clojure-usage) support for Ghidra, both interactive and scripting.


## Installation
Check out the
[releases](https://github.com/goatshriek/ruby-dragon/releases/latest) page
for the latest release build of the plugin. After downloading, you can
install this in Ghidra by going to `File->Install Extensions...`, choosing
the `Add Extension` option, and then navigating to the downloaded zip file.
You'll be prompted to restart Ghidra for the new extension to be active.

You will then need to activate the plugin before using it. You might get
prompted to do this next time you open the CodeBrowser tool, in which case you
can simply select OK. Otherwise, you can manually activate it by opening the
CodeBrowser tool, going to `File->Configure...`, and selecting the `RubyDragon`
plugin for Ruby, the `KotlinDragon` plugin for Kotlin, the `JShellDragon` plugin
for the Java interpreter, and the `ClojureDragon` plugin for Clojure. They
should appear in the `Ghidra Core` listing, but you can check the `Configure All
Plugins` option if you aren't able to find them.

If you need to remove a language plugin, you can do so by unchecking the box in
the configuration dialog in the CodeBrowser tool. If you want to remove the
extension as a whole, you'll also need to uncheck it in the `Install Extensions`
menu from the project browser, and finally restart Ghidra. You may also need to
manually delete the folder from your
`.ghidra/<ghidrainstall>/Extensions` folder to completely remove it,
particularly if you want to load the plugin via the Eclipse plugin for
development.


## Ruby Usage
Once the RubyDragon plugin is enabled, you will be able to open an interactive
Ruby session from the CodeBrowser tool by going to `Window->Ruby`. This is a 
standard IRB session provided by JRuby.

The same environmental variables provided in Java and Python scripts are also
available in this session, as the following global variables:

```ruby
$current_address
$current_highlight
$current_location
$current_program
$current_selection
```

Another variable named `$current_api` is also provided, which is an instance of
`FlatProgramAPI` created with `currentProgram`. This has many (but not all) of
the convenience functions that would be available within a `GhidraScript`
instance.

You can also write scripts in Ruby, much the same way as you would with Java or
Python. Ruby will be available as a new script type, and you can see several
example scripts in the `Examples.Ruby` directory of the Script Manager that
show basic usage of both JRuby and Ghidra basics. Scripts also have an
additional global variable `$script` that provides access to the `RubyScript`
instance for them.

The same global variables available in the interactive sessions are also
provided for scripts to use in the same manner.

You can also find help directly in the Ghidra help menu (press `F1`) on the 
`Ghidra Functionality->Scripting->Ruby Interpreter` page.

Current versions of Ghidra suffer from a class loading problem that may cause
issues with Ruby depending on your version of Java. If you run into this, copy
the `launch.properties` file in the `data` folder (both in this repo and in
the extension package) into your Ghidra installation's `support` directory.
This will add the necessary arguments to the JVM to resolve the issue.


### Installing Gems
If you want to install gems to be available in your interactive interpreter
or scripts, then you'll need to take a few extra steps, depending on how
isolated you want the gem environment to be.

If you're using something like rvm to manage your Ruby environment, then you can
simply rely on this to have already set the `GEM_PATH` environment variable to
point to your gem installation. For maximum success however, you should switch
to a JRuby installation, ideally of the same version as packaged in RubyDragon,
and let rvm point to a gemset within that.

If you want the Ghidra gem set to be specific to Ghidra, or if you don't have a
Ruby environment outside of Ghidra to point to, you can choose a location on
your own and set the `GEM_PATH` environment variable to point to that. To
install new gems to the path, invoke the version of `gem` from the bundled JRuby
jar like so, changing version and paths as needed. Here the gem path will be set
to `~/ghidra_gems`

```sh
# from a shell environment
java -jar ~/.ghidra/.ghidra_10.2_PUBLIC/Extensions/RubyDragon/lib/jruby-complete-9.3.9.0.jar -S gem install -i ~/ghidra_gems wrapture
```

```bat
REM from a windows command line
java -jar %USERPROFILE%\.ghidra\.ghidra_10.2_PUBLIC\Extensions\RubyDragon\lib\jruby-complete-9.3.9.0.jar -S gem install -i %USERPROFILE%\ghidra_gems wrapture
```

Once this is done, you can require the `wrapture` gem (or whatever you chose
to install) from scripts and the interactive terminal.

If you don't want to create an environment variable in your global
configuration, you'll need to mess with the script used to launch Ghidra in
order to set `GEM_PATH` appropriately. You can do this by adding a `set`
command in `launch.bat` or `launch.sh` (depending on your OS). For Windows
systems, you'll also need to remove the `/I` parameter from the `start`
command used to launch Ghidra so that the environment variable is passed on.


## Kotlin Usage
Kotlin is used in much the same way as the Ruby toolset with some obvious
differences, such as being provided by the `KotlinDragon` plugin and being
reached from the `Window->Kotlin` menu option. The built in variables for
scripts and the interpreter window in Kotlin are the same as Java:

```
currentAddress
currentHighlight
currentLocation
currentProgram
currentSelection
```

`currentAPI` is also provided similar to the Ruby interpreter, again holding an
instance of `FlatProgramAPI` created with `currentProgram`.

Kotlin scripts use a `kts` extension as they are interpreted as scripts rather
than being compiled to java first.


## JShell Usage
The JShell plugin provides an interactive Java interpreter by JShell, a Java
REPL included in Java. It provides the same built in variables that are
available in Java scripts:

```
currentAddress
currentHighlight
currentLocation
currentProgram
currentSelection
```

`currentAPI` is also provided as with the Kotlin interpreter, again holding an
instance of `FlatProgramAPI` created with `currentProgram`.

This interpreter is especially handy when writing Java scripts, as it allows you
to iteratively test snippets of code from the script without needing to do any
sort of conversion to other languages like Python or Kotlin.


## Clojure Usage
Clojure follows the same patterns as the other languages, being provided in the
`ClojureDragon` plugin and reachable from the `Window->Clojure` menu option.

The Clojure interpreter and scripts also have bindings that make the state
information available to them, within the `ghidra` namespace. They are:

```clojure
ghidra/current-address
ghidra/current-highlight
ghidra/current-location
ghidra/current-program
ghidra/current-selection
```

`ghidra/current-api` is provided as the instance of `FlatProgramAPI` created
with `currentProgram`, as with the other interpreters.

And, as with Ruby, a `ghidra/script` binding is available within scripts that
provides access to the underlying `ClojureScript` instance. Unlike Ruby however,
this variable does not allow access to protected fields or private methods.
These are instead injected into the `ghidra` namespace as well. For example, to
access the `TaskMonitor` for a script, you can simply reference `ghidra/monitor`
to do things like update the progress. The Clojure Ghidra Basics script has an
example of this type of access. Those familiar with the Python scripting
interface may recognize this paradigm, as it is the same there.


## Contributing
Right now, the easiest way to contribute is to post any suggestions or try it
out and open an issue if you have any problems. Head over to the
[issue list](https://github.com/goatshriek/ruby-dragon/issues) to join the
discussion!

If you're feeling adventurous, you can add an example script in your language
of choice. This could be an equivalent to one of the scripts that come packaged
with Ghidra, or it could be all new! Just be sure you add a test for it in the
Github Action workflow so that it isn't broken later on. Check out the
`ghidra_scripts` folder to see what's there now, and perhaps draw some
inspiration on what you could add.

Or, if all of that is a bit much, just give us a shoutout at
[#GhidraRubyDragon](https://twitter.com/search?q=%23GhidraRubyDragon) on
Twitter with your thoughts!
