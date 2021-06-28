---
title: Ghidra Basics in Ruby
keywords: ruby, jruby, ghidra, basics
last_updated: June 28, 2021
layout: default
---


# Ghidra Basics in Ruby
The following script demonstrates how to accomplish some simple tasks in Ghidra
using the Ruby capability provided by Ruby Dragon. Note the use of the automatic
global variables to get state information, and the use of standard Ruby idioms.

```ruby
# Examples of basic Ghidra scripting in Ruby
# @category: Examples.Ruby
# you can drop the 'get' from obvious accessors
# for example, instead of using 'getName', just 'name' will do
program_name = $current_program.name

# and multiple words get automatically split to snake case
creation_date = $current_program.creation_date
language_id = $current_program.language_id
compiler_spec_id = $current_program.compiler_spec.compiler_spec_id

# printing out some basic program information
puts 'Program Info:'
puts "#{program_name} #{creation_date}_#{language_id} (#{compiler_spec_id})"
puts

# get info about the current program's memory layout
puts 'Memory Layout:'
puts "Imagebase: 0x%x" % $current_program.image_base.offset
$current_program.memory.blocks.each do |block|
    puts "#{block.name} [start: 0x#{block.start}, end: 0x#{block.end}]"
end
puts

# get the current program's function names
puts 'Function List:'
function = $script.getFirstFunction
while function do
  puts function.name
  function = $script.getFunctionAfter(function)
end
puts

# get the current location in the program
puts "Current location: 0x%x" % $current_address.getOffset

# get some user input
val = $script.askString('Hello', 'Please enter a value')
puts "You entered '#{val}'"
puts

# output a popup window with the entered value
$script.popup(val)

# add a comment to the current program
min_address = $current_program.min_address
listing = $current_program.listing
code_unit = listing.get_code_unit_at(min_address)
code_unit.set_comment(code_unit.class::PLATE_COMMENT, 'This is an added comment from Ruby!')

# prompting the user for a data type
puts 'prompting for a data type...'
java_import 'ghidra.app.util.datatype.DataTypeSelectionDialog'
java_import 'ghidra.util.data.DataTypeParser'
tool = $script.state.tool
dtm = $current_program.data_type_manager
types = DataTypeParser::AllowedDataTypes::FIXED_LENGTH
selection_dialog = DataTypeSelectionDialog.new(tool, dtm, -1, types)
tool.show_dialog(selection_dialog)
data_type = selection_dialog.user_chosen_data_type
puts "Chosen data type: #{data_type}" if data_type
puts

# report progress to the user interface, do this anywhere things take a while
# we have to use `initialize__method` here because `initialize` is private
$script.monitor.initialize__method(10)
(1..10).each do |i|
  $script.monitor.check_canceled # make sure we're still good to go
  sleep(1) # wait for a bit...
  $script.monitor.increment_progress(1) # update the progress bar
  $script.monitor.message = "working on step #{i}" # update the status message
end
```

You can see the output of a typical invocation of this script below. This output
was taken with the .exe of
[this crackme](https://crackmes.one/static/crackme/5fcbac7733c5d424269a1a93.zip).

```
Program Info:
FindMyPassword.exe Wed Mar 10 15:31:04 EST 2021_x86:LE:32:default (windows)
Memory Layout:
Imagebase: 0x400000
Headers [start: 0x00400000, end: 0x004003ff]
.text [start: 0x00401000, end: 0x00403dff]
.data [start: 0x00404000, end: 0x004041ff]
.rdata [start: 0x00405000, end: 0x004053ff]
/4 [start: 0x00406000, end: 0x004069ff]
.bss [start: 0x00407000, end: 0x004070b3]
.idata [start: 0x00408000, end: 0x004087ff]
.CRT [start: 0x00409000, end: 0x004091ff]
.tls [start: 0x0040a000, end: 0x0040a1ff]
/14 [start: 0x0040b000, end: 0x0040b1ff]
/29 [start: 0x0040c000, end: 0x0040ddff]
/41 [start: 0x0040e000, end: 0x0040e1ff]
/55 [start: 0x0040f000, end: 0x0040f1ff]
/67 [start: 0x00410000, end: 0x004101ff]
Function List:
FUN_004011b0
__mingw32_init_mainargs
_mainCRTStartup
_atexit
_hash
_main
__setargv
___cpu_features_init
___main
tls_callback_1
___dyn_tls_init@12
.text
___mingw_TLScallback
.text
FUN_00401f20
__pei386_runtime_relocator
___chkstk_ms
_fesetenv
.text
FUN_00402320
FUN_00402390
FUN_00402650
FUN_00402870
FUN_004028d0
FUN_00402920
___mingw_glob
___mingw_dirname
.text
FUN_004037d0
___mingw_opendir
___mingw_readdir
___mingw_closedir
___mingw_rewinddir
_wcstombs
_vfprintf
_tolower
_strlen
_strcpy
_strcoll
_strcmp
_srand
_signal
_setlocale
_realloc
_rand
_printf
_memcpy
_mbstowcs
_malloc
_fwrite
_free
_calloc
_abort
__setmode
__isctype
__fullpath
__errno
__cexit
___p__fmode
___p__environ
___getmainargs
_VirtualQuery@12
_VirtualProtect@16
_TlsGetValue@4
_SetUnhandledExceptionFilter@4
_LoadLibraryA@4
_LeaveCriticalSection@4
_InitializeCriticalSection@4
_GetProcAddress@8
_GetModuleHandleA@4
_GetLastError@0
_GetCommandLineA@0
_FreeLibrary@4
_FindNextFileA@8
_FindFirstFileA@8
_FindClose@4
_ExitProcess@4
_EnterCriticalSection@4
_DeleteCriticalSection@4
_stricoll
_strdup
Current location: 0x401019
You entered 'example'
prompting for a data type...
Chosen data type: typedef LPCSTR CHAR *
=end
```

