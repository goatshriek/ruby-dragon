# Developing Ruby Dragon
If you're looking to get involved with Ruby Dragon by fixing bugs, adding
features, or maybe even adding support for a new language, here is some
information that you will likely find useful.


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
Ruby Dragon reduces to essentially a documentation and branding exercise.


### Create an Interpreter Class
Do it.


### Add Help Page
Documentation is important. Do it.

