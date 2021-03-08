---
title: Ruby Dragon
keywords: ruby, jruby, ghidra, plugin
last_updated: March 8, 2021
layout: default
---


# Ruby Dragon
Ruby Dragon is a plugin for Ghidra, offering Ruby support for both interactive
sessions as well as writing reusable scripts.

To install, head over to the
[release page](https://github.com/goatshriek/ruby-dragon/releases/latest) and
grab the latest zip! Then install it in your own Ghidra from the
`File->Install Extensions...` menu option.


## Basic Usage
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


## Examples
Examples are included with the plugin, under the `Examples.Ruby` category. If
you want to just browse them before installing though, you can go through each
of them here:
 * [JRuby Basics](./examples/JRubyBasicsScriptRb.html)
 * [Ghidra Basics](./examples/GhidraBasicsScriptRb.html)


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

