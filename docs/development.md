# Developing Ruby Dragon
If you're looking to get involved with Ruby Dragon by fixing bugs, adding
features, or maybe even adding support for a new language, here is some
information that you will likely find useful.


## Setting Up a Development Environment
While there is documentation included with Ghidra on how to set up a plugin
development environment, there are a few unmentioned pitfalls that are worth
mentioning.

TODO: upgrade steps (deleted build directory, link to new Ghidra)


## Adding a New Language
Support for a wide variety of languages is the primary goal of Ruby Dragon. As
such, its design is optimized to make the addition of a new one as
straightforward as possible. Such an enhancement can be made in a simple and
straightforward manner, provided that the following primitives are available
for the language, all from Java code:

 * starting an interactive interpreter and connecting its input/output/error
   streams to existing ones
 * creating and updating variables in an interpreter session
 * executing a script file within an interpreter

Once you can do these things from Java, then adding the language to Ghidra via
Ruby Dragon is a straightforward class implementation, documentation, and
branding exercise. If you're ever stuck, take a look at one of the existing
language implementations to see how to approach your problem area.


### Create a Plugin Class
Most Ghidra plugins extend the `ProgramPlugin` class in order to hook in and
provide functionality. RubyDragon provides an abstract subclass of this which
takes care of a number of boilerplate tasks such as dependency downloading and
setting up the window titles and icons. Start by subclassing this and adding
concrete functions where needed.


### Create an Interpreter Class
The `GhidraInterpreter` class serves as a wrapper around the language-specific
details of your new language. Create a new subclass of this for your language,
and use the primitives described above to implement the necessary features.


### Add Script Support
In order to support scripts, you'll need to extend `GhidraScript` and
`GhidraScriptProvider` with support for your own language. These classes are
very straightforward to extend, and existing RubyDragon subclasses are a great
place to look if you get stuck.


### Add Help Page
Ghidra has a robust help system built in, and users expect to be able to find
information about whatever they're working in there. Add a help page describing
the specifics of using your language within Ghidra, by adding an entry into
`src/main/help/help/TOC_Source.xml` and then a new page alongside the others in
`src/main/help/help/topics/rubydragon`. Once again, the existing pages are the
best place to look for examples of what to do.


### Add Example Scripts and Tests
Example scripts serve two purposes. First, they provide a way for newcomers to
quickly check to see how to do the basics within your language setup, such as
how script arguments are handled or how to interace with the Ghidra-provided
classes and variables. Second, they are run by the continuous integration
pipeline as a test for functionality after installation. All languages implement
two of these which you will need to provide. The first is a basics script that
does several common tasks in Ghidra. The second saves all strings that are
defined in a program to a given file. You will need to implement these two
scripts, and also add runs of them in the Github Action tests and verify their
output against an expected value.
