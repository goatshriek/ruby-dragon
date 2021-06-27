# Ruby Dragon
[![build](https://github.com/goatshriek/ruby-dragon/actions/workflows/build.yml/badge.svg)](https://github.com/goatshriek/ruby-dragon/actions/workflows/build.yml)
[![Apache 2.0 License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Ruby and Clojure support for Ghidra, both interactive and scripting.


## Installation
Check out the releases page for the latest release build of the plugin. After
downloading, you can install this in Ghidra by going to
`File->Install Extensions...`, choosing the `Add Extension` option, and then
navigating to the downloaded zip file. You'll be prompted to restart Ghidra
for the new extension to be active.

You will then need to activate the plugin before using it. You might get
prompted to do this next time you open the CodeBrowser tool, in which case you
can simply select OK. Otherwise, you can manually activate it by opening the
CodeBrowser tool, going to `File->Configure...`, and selecting the `RubyDragon`
plugin for Ruby, and the `ClojureDragon` plugin for Clojure. The
`Configure All Plugins` option will show you all plugins if you cannot find
them in a particular category, though they should appear in the `Experimental`
listing.

If you need to remove the plugin, you can do so by unchecking the box in the
configuration dialog in the CodeBrowser tool, and then in the
`Install Extensions` menu from the project browser as well, and finally
restarting Ghidra. You may also need to manually delete the folder from your
`.ghidra/<ghidrainstall>/Extensions` folder to completely remove it,
particularly if you want to load the plugin via the Eclipse plugin for
development.


## Basic Ruby Usage
Once the plugin is enabled, you will be able to open an interactive Ruby session
from the CodeBrowser tool by going to `Window->Ruby`. This is a standard IRB
session provided by JRuby.

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
show basic usage of both JRuby and Ghidra basics.

The same global variables available in the interactive sessions are also
provided for scripts to use in the same manner.

You can also find help directly in the Ghidra help menu (press `F1`) on the 
`Ghidra Functionality->Scripting->Ruby Interpreter` page.


## Basic Clojure Usage
Clojure is used in much the same way as the Ruby toolset with some obvious
differences, such as being reached from the `Window->Clojure` menu option
instead.


## Contributing
Ruby Dragon is still in the early stages of development; while it is
functional, it won't be considered stable until version 1.0.0 is reached. Right
now, the best way to contribute is to post any suggestions or try it out and
open an issue if you have any problems. Head over to the
[issue list](https://github.com/goatshriek/ruby-dragon/issues) to join the
discussion!

Or, just give us a shoutout at
[#GhidraRubyDragon](https://twitter.com/search?q=%23GhidraRubyDragon) on
Twitter with your thoughts!
