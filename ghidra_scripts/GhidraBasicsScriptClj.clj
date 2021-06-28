; Examples of basic Ghidra scripting in Clojure
; @category: Examples.Clojure

; use the ghidra namespace to access the provided variables
(def program-name
    (.getName ghidra/current-program))

; printing out some basic program information
(println "Program Info:")
(println
    (format "%s %s_%s (%s)"
            program-name
            (.getCreationDate ghidra/current-program)
            (.getLanguageID ghidra/current-program)
            (.getCompilerSpecID (.getCompilerSpec ghidra/current-program))))
(println)

; get info about the current program's memory layout
(println "Memory Layout:")
(println
    (format "Imagebase: 0x%x"
            (.getOffset (.getImageBase ghidra/current-program))))
(doseq [block (.getBlocks (.getMemory ghidra/current-program))]
       (println (format "%s [start: 0x%s, end:0x%s]"
                        (.getName block)
                        (.toString (.getStart block))
                        (.toString (.getEnd block)))))
(println)

; get the current program's function names
(println "Function List:")
(def current-function (.getFirstFunction ghidra/script))
(while (some? current-function)
    (println (.getName current-function))
    (def current-function (.getFunctionAfter ghidra/script current-function)))
(println)

;# get the current location in the program
;puts "Current location: 0x%x" % $current_address.getOffset
;
;# get some user input
;val = $script.askString('Hello', 'Please enter a value')
;puts "You entered '#{val}'"
;puts
;
;# output a popup window with the entered value
;$script.popup(val)
;
;# add a comment to the current program
;min_address = $current_program.min_address
;listing = $current_program.listing
;code_unit = listing.get_code_unit_at(min_address)
;code_unit.set_comment(code_unit.class::PLATE_COMMENT, 'This is an added comment from Ruby!')
;
;# prompting the user for a data type
;puts 'prompting for a data type...'
;java_import 'ghidra.app.util.datatype.DataTypeSelectionDialog'
;java_import 'ghidra.util.data.DataTypeParser'
;tool = $script.state.tool
;dtm = $current_program.data_type_manager
;types = DataTypeParser::AllowedDataTypes::FIXED_LENGTH
;selection_dialog = DataTypeSelectionDialog.new(tool, dtm, -1, types)
;tool.show_dialog(selection_dialog)
;data_type = selection_dialog.user_chosen_data_type
;puts "Chosen data type: #{data_type}" if data_type
;puts
;
;# report progress to the user interface, do this anywhere things take a while
;# we have to use `initialize__method` here because `initialize` is private
;$script.monitor.initialize__method(10)
;(1..10).each do |i|
;  $script.monitor.check_canceled # make sure we're still good to go
;  sleep(1) # wait for a bit...
;  $script.monitor.increment_progress(1) # update the progress bar
;  $script.monitor.message = "working on step #{i}" # update the status message
;end
;
;# script output against .exe from crackme at:
;# https://crackmes.one/static/crackme/5fcbac7733c5d424269a1a93.zip
;=begin
;TODO add the output
;=end
