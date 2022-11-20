//Examples of basic Ghidra scripting in Groovy.
//@category: Examples.Groovy

import ghidra.program.model.listing.CodeUnit
import ghidra.app.util.datatype.DataTypeSelectionDialog
import ghidra.util.data.DataTypeParser

// of course, standard variable assignments work as expected
// in normal Groovy fashion, you can use getters without the 'get' prefix
programName = currentProgram.name
creationDate = currentProgram.creationDate
languageId = currentProgram.languageID
compilerSpecId = currentProgram.compilerSpec.compilerSpecID

// printing out some basic program information
// you'll need to use the script.print family of functions to see the output
script.println('Program Info:')
script.println("$programName $languageId ($compilerSpecId)")
script.println()

// get info about the current program's memory layout
script.println('Memory Layout:')
script.println(String.format('Imagebase: 0x%x', currentProgram.imageBase.offset))
currentProgram.memory.blocks.each {
  script.println("${it.name} [start: 0x${it.start}, end: 0x${it.end}]")
}
script.println()

// get the current program's function names
script.println('Function List:')
function = script.firstFunction
while (function) {
  script.println(function.name)
  function = script.getFunctionAfter(function)
}
script.println()

// get the current location in the program
script.println(String.format('Current Location: 0x%x', currentAddress.offset))
script.println()

// get some user input
userInput = script.askString('Hello', 'Please enter a value')
script.println("You entered '$userInput'")

// output a popup window with the entered value
script.popup(userInput)

// add a comment to the current program
minAddress = currentProgram.minAddress
codeUnit = currentProgram.listing.getCodeUnitAt(minAddress)
codeUnit.setComment(CodeUnit.PLATE_COMMENT, 'This is an added comment from Groovy!')

// only valid in interactive scripts
if (!script.isRunningHeadless()) {
  // prompting the user for a data type
  script.println()
  script.println('prompting for a data type...')
  tool = script.state.tool
  dtm = currentProgram.dataTypeManager
  types = DataTypeParser.AllowedDataTypes.FIXED_LENGTH
  selectionDialog = new DataTypeSelectionDialog(tool, dtm, -1, types)
  tool.showDialog(selectionDialog)
  dataType = selectionDialog.getUserChosenDataType()
  if (dataType) {
    script.println("Chosen data type: $dataType")
  }
  script.println()

  // report progress to the user interface
  // do this anywhere things take a while
  script.monitor.initialize(10)
  10.times {
    script.monitor.checkCanceled()
    Thread.sleep(1000)
    script.monitor.incrementProgress(1)
    script.monitor.message = "working on step $it"
  }
}

// script output against example executable located in this repository at
// src/test/resources/bin/HelloGhidra.exe
