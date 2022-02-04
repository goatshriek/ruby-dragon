//Examples of basic Ghidra scripting in Kotlin.
//@category: Examples.Kotlin

// of course, standard variable assignments and type inference work as expected
val programName = currentProgram.getName()
val creationDate = currentProgram.getCreationDate()
val languageId = currentProgram.getLanguageID()
val compilerSpecId = currentProgram.getCompilerSpec().getCompilerSpecID()

// printing out some basic program information
// remember to use the script.print functions
script.println("Program Info:")
script.println("$programName $languageId ($compilerSpecId)\n")
script.println()

// get info about the current program's memory layout
script.println("Memory Layout:")
script.printf("Imagebase: 0x%x", currentProgram.getImageBase().getOffset())
currentProgram.getMemory().getBlocks().forEach {
  script.println("${it.getName()} [start: 0x${it.getStart()}, end: 0x${it.getEnd()}]")
}
script.println()

// get the current program's function names
script.println("Function List:")

