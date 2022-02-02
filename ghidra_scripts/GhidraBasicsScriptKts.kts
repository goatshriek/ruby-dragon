//Examples of basic Ghidra scripting in Kotlin.
//@category: Examples.Kotlin

// of course, standard variable assignments and type inference work as expected
val programName = currentProgram.getName()

script.println(programName)
