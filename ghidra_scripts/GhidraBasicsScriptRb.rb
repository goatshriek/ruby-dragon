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
puts "#{program_name} #{language_id} (#{compiler_spec_id})"
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
puts "Current Location: 0x%x" % $current_address.getOffset
puts

# get some user input
val = $script.askString('Hello', 'Please enter a value')
puts "You entered '#{val}'"

# output a popup window with the entered value
$script.popup(val)

# add a comment to the current program
min_address = $current_program.min_address
listing = $current_program.listing
code_unit = listing.get_code_unit_at(min_address)
code_unit.set_comment(code_unit.class::PLATE_COMMENT, 'This is an added comment from Ruby!')

# only valid in interactive scripts
unless $script.running_headless?
  # prompting the user for a data type
  puts
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
end

# script output against example executable located in this repository at
# src/test/resources/bin/HelloGhidra.exe
=begin
Program Info:
HelloGhidra.exe x86:LE:32:default (windows)

Memory Layout:
Imagebase: 0x400000
Headers [start: 0x00400000, end: 0x004003ff]
.text [start: 0x00401000, end: 0x00401fff]
.rdata [start: 0x00402000, end: 0x00402fff]
.data [start: 0x00403000, end: 0x004031ff]
.data [start: 0x00403200, end: 0x00403387]
.rsrc [start: 0x00404000, end: 0x004041ff]
.reloc [start: 0x00405000, end: 0x004051ff]

Function List:
FUN_00401000
FUN_00401010
Catch_All@004011b0
FUN_004011d7
FUN_004012ea
entry
FUN_00401549
FUN_00401571
find_pe_section
___scrt_acquire_startup_lock
___scrt_initialize_crt
___scrt_initialize_onexit_tables
___scrt_is_nonwritable_in_current_image
___scrt_release_startup_lock
___scrt_uninitialize_crt
__onexit
_atexit
___get_entropy
___security_init_cookie
FUN_00401954
FUN_00401957
FUN_0040195b
FUN_00401961
FUN_0040196d
FUN_00401970
_guard_check_icall
FUN_00401994
FUN_0040199a
FUN_004019a0
FUN_004019bd
FUN_004019c9
FUN_004019cf
FUN_004019d5
thunk_FUN_00401954
FUN_00401af5
FUN_00401b44
FUN_00401b9a
FUN_00401ba2
__SEH_prolog4
__except_handler4
FUN_00401c74
___scrt_is_ucrt_dll_in_use
Unwind@00401e57
__current_exception
__current_exception_context
memset
_except_handler4_common
_seh_filter_exe
_set_app_type
__setusermatherr
_configure_narrow_argv
_initialize_narrow_environment
_get_initial_narrow_environment
_initterm
_initterm_e
exit
_exit
_set_fmode
__p___argc
__p___argv
_cexit
_c_exit
_register_thread_local_exe_atexit_callback
_configthreadlocale
__p__commode
_initialize_onexit_table
_register_onexit_function
_crt_atexit
_controlfp_s
terminate
__filter_x86_sse2_floating_point_exception_default
Unwind@00401f80
Unwind@00401f88

Current location: 0x400000
You entered 'HeadlessTest'
=end
