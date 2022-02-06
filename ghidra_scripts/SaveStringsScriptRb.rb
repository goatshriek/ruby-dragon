# Save all strings of five characters or more in the current program to a file
# with the given name, or `saved_strings.txt` if no filename was given as a
# command line argument. This script is based on the CountAndSaveStrings script
# included with Ghidra.

# @category: Examples.Ruby

# read in the filename, or default to `saved_strings.txt` if none was passed
filename = ARGV.first || "saved_strings.txt"

# initialize the string counter
string_count = 0;

# go through the data in the program
open(filename, 'w') do |out_file|
    $current_program.listing.get_defined_data(true).each do |data|
        type_name = data.data_type.name
        val_rep = data.get_default_value_representation
        if %w(unicode string).include?(type_name) && val_rep.length > 4
            out_file.puts(val_rep)
            string_count += 1
        end
    end
end

# print out the final string count
puts "\ntotal number of strings: #{string_count}\n"
