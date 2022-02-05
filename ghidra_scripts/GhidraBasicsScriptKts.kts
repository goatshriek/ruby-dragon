//Examples of basic Ghidra scripting in Kotlin.
//@category: Examples.Kotlin

import ghidra.program.model.listing.CodeUnit
import ghidra.app.util.datatype.DataTypeSelectionDialog
import ghidra.util.data.DataTypeParser

// of course, standard variable assignments and type inference work as expected
// in normal Kotlin fashion, you can also use getters without the 'get' prefix
val programName = currentProgram.name
val creationDate = currentProgram.creationDate
val languageId = currentProgram.languageID
val compilerSpecId = currentProgram.compilerSpec.compilerSpecID

// printing out some basic program information
// you'll need to use the script.print family of functions to see the output
// if you are going to do a lot of this, you can of course use with to
// shorten things up a bit
with (script) {
  println("Program Info:")
  println("$programName $languageId ($compilerSpecId)")
  println()
}

// get info about the current program's memory layout
script.println("Memory Layout:")
script.println("Imagebase: 0x%x".format(currentProgram.imageBase.offset))
currentProgram.memory.blocks.forEach {
  script.println("${it.name} [start: 0x${it.start}, end: 0x${it.end}]")
}
script.println()

// get the current program's function names
script.println("Function List:")
var function = script.firstFunction
while (function != null) {
  script.println(function.name)
  function = script.getFunctionAfter(function)
}

// get the current location in the program
script.println("Current Location: 0x%x".format(currentAddress.offset))


// get some user input
val userInput = script.askString("Hello", "Please enter a value")
script.println("You entered '$userInput'")

// output a popup window with the entered value
script.popup(userInput)

// add a comment to the current program
val minAddress = currentProgram.minAddress
val listing = currentProgram.listing
val codeUnit = listing.getCodeUnitAt(minAddress)
codeUnit.setComment(CodeUnit.PLATE_COMMENT, "This is an added comment from Kotlin!")

// only valid in interactive scripts
if (!script.isRunningHeadless()) {
  // prompting the user for a data type
  script.println()
  script.println("prompting for a data type...")
  val tool = script.state.tool
  val dtm = currentProgram.dataTypeManager
  val types = DataTypeParser.AllowedDataTypes.FIXED_LENGTH
  val selectionDialog = DataTypeSelectionDialog(tool, dtm, -1, types)
  tool.showDialog(selectionDialog)
  val dataType = selectionDialog.getUserChosenDataType()
  if (dataType != null) {
    script.println("Chosen data type: $dataType")
  }
  script.println()

  // report progress to the user interface
  // do this anywhere things take a while
  script.monitor.initialize(10)
  for (i in 1..10) {
    script.monitor.checkCanceled()
    Thread.sleep(1000)
    script.monitor.incrementProgress(1)
    script.monitor.message = "working on step $i"
  }
}
