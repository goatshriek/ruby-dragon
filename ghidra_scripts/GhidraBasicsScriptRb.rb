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
function = $script.getFirstFunction()
while function do
  puts function.name
  function = $script.getFunctionAfter(function)
end
puts

=begin
# Get the address of the current program's current location
print "Current location: " + hex(currentLocation.getAddress().getOffset())

# Get some user input
val = askString("Hello", "Please enter a value")
print val

# Output to a popup window
popup(val)

# Add a comment to the current program
minAddress = currentProgram.getMinAddress()
listing = currentProgram.getListing()
codeUnit = listing.getCodeUnitAt(minAddress)
codeUnit.setComment(codeUnit.PLATE_COMMENT, "This is an added comment!")

# Get a data type from the user
from ghidra.app.util.datatype import DataTypeSelectionDialog
from ghidra.util.data.DataTypeParser import AllowedDataTypes
tool = state.getTool()
dtm = currentProgram.getDataTypeManager()
selectionDialog = DataTypeSelectionDialog(tool, dtm, -1, AllowedDataTypes.FIXED_LENGTH)
tool.showDialog(selectionDialog)
dataType = selectionDialog.getUserChosenDataType()
if dataType != None: print "Chosen data type: " + str(dataType)

# Report progress to the GUI.  Do this in all script loops!
import time
monitor.initialize(10)
for i in range(10):
    monitor.checkCanceled() # check to see if the user clicked cancel
    time.sleep(1) # pause a bit so we can see progress
    monitor.incrementProgress(1) # update the progress
    monitor.setMessage("Working on " + str(i)) # update the status message
=end

# script output against .exe from crackme at:
# https://crackmes.one/static/crackme/5fcbac7733c5d424269a1a93.zip
=begin
TODO add the output
=end
