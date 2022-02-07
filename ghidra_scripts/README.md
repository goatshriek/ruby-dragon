# Example Ghidra Scripts
Most of the scripts included with RubyDragon demonstrate different aspects of
writing Ghidra scripts in each of the supported languages. You'll see a
different version of the same script for each language, accomplishing the
same thing.

Some of the scripts serve other purposes though, as outlined below.


### JRubyBasics
Demonstrates some of the nuances of working with JRuby that may not be obvious
to users familiar only with native Ruby implementations.


### DownloadDependencies
Downloads dependencies (`jar`s) for RubyDragon languages which need them. Some
languagues require a large enough supporting cast that including all of these
with the installation bundle is not feasible. This script grabs them for you and
puts them in the correct locations, perhaps saving you some time and headache.