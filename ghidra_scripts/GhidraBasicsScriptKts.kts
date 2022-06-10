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
script.println()

// get the current location in the program
script.println("Current Location: 0x%x".format(currentAddress.offset))
script.println()

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

// script output against example executable located in this repository at
// src/test/resources/bin/HelloGhidra.exe
//Program Info:
//HelloGhidra.exe x86:LE:32:default (windows)
//
//Memory Layout:
//Imagebase: 0x400000
//Headers [start: 0x00400000, end: 0x004003ff]
//.text [start: 0x00401000, end: 0x00401fff]
//.rdata [start: 0x00402000, end: 0x00402fff]
//.data [start: 0x00403000, end: 0x004031ff]
//.data [start: 0x00403200, end: 0x00403387]
//.rsrc [start: 0x00404000, end: 0x004041ff]
//.reloc [start: 0x00405000, end: 0x004051ff]
//
//Function List:
//FUN_00401000
//FUN_00401010
//Catch_All@004011b0
//FUN_004012ea
//entry
//FUN_00401549
//FUN_00401571
//find_pe_section
//___scrt_acquire_startup_lock
//___scrt_initialize_crt
//___scrt_initialize_onexit_tables
//___scrt_is_nonwritable_in_current_image
//___scrt_release_startup_lock
//___scrt_uninitialize_crt
//__onexit
//_atexit
//___get_entropy
//___security_init_cookie
//FUN_00401954
//FUN_00401957
//FUN_0040195b
//FUN_00401961
//FUN_0040196d
//FUN_00401970
//_guard_check_icall
//FUN_00401994
//FUN_0040199a
//FUN_004019a0
//FUN_004019bd
//FUN_004019c9
//FUN_004019cf
//FUN_004019d5
//thunk_FUN_00401954
//FUN_00401af5
//FUN_00401b44
//FUN_00401b9a
//FUN_00401ba2
//__SEH_prolog4
//__except_handler4
//FUN_00401c74
//___scrt_is_ucrt_dll_in_use
//Unwind@00401e57
//__current_exception
//__current_exception_context
//memset
//_except_handler4_common
//_seh_filter_exe
//_set_app_type
//__setusermatherr
//_configure_narrow_argv
//_initialize_narrow_environment
//_get_initial_narrow_environment
//_initterm
//_initterm_e
//exit
//_exit
//_set_fmode
//__p___argc
//__p___argv
//_cexit
//_c_exit
//_register_thread_local_exe_atexit_callback
//_configthreadlocale
//__p__commode
//_initialize_onexit_table
//_register_onexit_function
//_crt_atexit
//_controlfp_s
//terminate
//__filter_x86_sse2_floating_point_exception_default
//Unwind@00401f80
//Unwind@00401f88
//
//Current Location: 0x400000
//
//You entered 'HeadlessTest'
