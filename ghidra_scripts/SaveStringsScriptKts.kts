// Save all strings of five characters or more in the current program to a file
// with the given name, or `saved_strings.txt` if no filename was given as a
// command line argument. This script is based on the CountAndSaveStrings script
// included with Ghidra.

// @category: Examples.Kotlin

import java.io.File

// read in the filename, or default to `saved_strings.txt` if none was passed
val filename = args.getOrElse(0) {"saved_strings.txt"} as String

// initialize the string counter
var stringCount = 0

// go through the data in the program
File(filename).printWriter().use { outFile ->
  currentProgram.listing.getDefinedData(true).forEach {
    val typeName = it.dataType.name
    val valueRep = it.defaultValueRepresentation
    if ((typeName.equals("unicode") || typeName.equals("string")) && valueRep.length > 4) {
      outFile.println(valueRep)
      stringCount += 1
    }
  }
}


// print out the final string count
script.println("total number of strings: $stringCount")
