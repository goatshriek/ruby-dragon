// Save all strings of five characters or more in the current program to a file
// with the given name, or `saved_strings.txt` if no filename was given as a
// command line argument. This script is based on the CountAndSaveStrings script
// included with Ghidra.

// @category: Examples.Groovy

import java.io.File

// read in the filename, or default to `saved_strings.txt` if none was passed
filename = args.length > 0 ? args[0] : 'saved_strings.txt'

// initialize the string counter
stringCount = 0

// go through the data in the program
new File(filename).withPrintWriter { outFile ->
  currentProgram.listing.getDefinedData(true).each {
    typeName = it.dataType.name
    valueRep = it.defaultValueRepresentation
    if ((typeName.equals('unicode') || typeName.equals('string')) && valueRep.length() > 4) {
      outFile.println(valueRep)
      stringCount += 1
    }
  }
}


// print out the final string count
script.println("total number of strings: $stringCount")
