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

# script output against .exe from crackme at:
# https://crackmes.one/static/crackme/5fcbac7733c5d424269a1a93.zip
=begin
TODO add the output
=end
