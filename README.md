# Ruby Dragon
[![build](https://github.com/goatshriek/ruby-dragon/actions/workflows/build.yml/badge.svg)](https://github.com/goatshriek/ruby-dragon/actions/workflows/build.yml)
[![Apache 2.0 License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Ruby, Kotlin, and Clojure support for Ghidra, both interactive and scripting.


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
plugin for Ruby, the `KotlinDragon` plugin for Kotlin, and the `ClojureDragon`
plugin for Clojure. They should appear in the `Ghidra Core` listing, but you
can check the `Configure All Plugins` option if you aren't able to find them.

If you need to remove a language plugin, you can do so by unchecking the box in
the configuration dialog in the CodeBrowser tool. If you want to remove the
extension as a whole, you'll also need to uncheck it in the `Install Extensions`
menu from the project browser, and finally restart Ghidra. You may also need to
manually delete the folder from your
`.ghidra/<ghidrainstall>/Extensions` folder to completely remove it,
particularly if you want to load the plugin via the Eclipse plugin for
development.

The Kotlin extension has additional dependencies that are not included in the
plugin itself for size reasons. If you try to enable this extension before these
are available in the plugin directory, you'll receive a `MissingDependencies`
error. You can either copy the files into the `lib` folder of the plugin
yourself, or run the `DownloadDependenciesScript` Java script included with the
plugin to do this automatically, and finally restart Ghidra (yet again).


## Ruby Usage
Once the RubyDragon plugin is enabled, you will be able to open an interactive
Ruby session from the CodeBrowser tool by going to `Window->Ruby`. This is a 
tandard IRB session provided by JRuby.

The same environmental variables provided in Java and Python scripts are also
available in this session, as the following global variables:

```ruby
$current_address
$current_highlight
$current_location
$current_program
$current_selection
```

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

Kotlin scripts use a `kts` extension as they are interpreted as scripts rather
than being compiled to java first.

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
