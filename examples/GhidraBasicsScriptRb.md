---
title: Ghidra Basics in Ruby
keywords: ruby, jruby, ghidra, basics
last_updated: March 8, 2021
layout: default
---


# Ghidra Basics in Ruby
The following script demonstrates how to accomplish some simple tasks in Ghidra
using the Ruby capability provided by Ruby Dragon. Note the use of the automatic
global variables to get state information, and the use of standard Ruby idioms.

```ruby
# Examples of basic Ghidra scripting in Ruby
# @category: Examples.Ruby

# get info about the current program
program_name = $current_program.getName
creation_date = $current_program.getCreationDate
language_id = $current_program.getLanguageID
compiler_spec_id = $current_program.getCompilerSpec.getCompilerSpecID
puts 'Program Info:'
puts "#{program_name} #{creation_date}_#{language_id} (#{compiler_spec_id})"
```
You can see the output of a typical invocation of this script here:

```
TODO
```
