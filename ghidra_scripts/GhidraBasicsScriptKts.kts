//Examples of basic Ghidra scripting in Kotlin.
//@category: Examples.Kotlin

// of course, standard variable assignments and type inference work as expected
val programName = currentProgram.getName()
val creationDate = currentProgram.getCreationDate()
val languageId = currentProgram.getLanguageID()
val compilerSpecId = currentProgram.getCompilerSpec().getCompilerSpecID()

// printing out some basic program information
// remember to use the script.println function
script.println("Program Info:")
script.println(programName + " " + languageId + " (" + compilerSpecId + ")")
script.println()
