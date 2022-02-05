; Examples of basic Ghidra scripting in Clojure
; @category: Examples.Clojure

; use the ghidra namespace to access the provided variables
(def program-name (.getName ghidra/current-program))

; printing out some basic program information
(println "Program Info:")
(println (format "%s %s (%s)"
    program-name
    (.getLanguageID ghidra/current-program)
    (.. ghidra/current-program getCompilerSpec getCompilerSpecID)))
(println)

; get info about the current program's memory layout
(println "Memory Layout:")
(println (format "Imagebase: 0x%x"
    (.getOffset (.getImageBase ghidra/current-program))))
(doseq [block (.. ghidra/current-program getMemory getBlocks)]
    (println (format "%s [start: 0x%s, end: 0x%s]"
        (.getName block)
        (.. block getStart toString)
        (.. block getEnd toString))))
(println)

; get the current program's function names
(println "Function List:")
(def current-function (.getFirstFunction ghidra/script))
(while (some? current-function)
    (println (.getName current-function))
    (def current-function (.getFunctionAfter ghidra/script current-function)))
(println)

; get the current location in the program
(println (format "Current Location: 0x%x" (.getOffset ghidra/current-address)))
(println)

; get some user input
(def input-val (.askString ghidra/script "Hello" "Please enter a value"))
(println (format "You entered '%s'" input-val))
(println)

; output a popup window with the entered value
(.popup ghidra/script input-val)

; import a class like so if you want to use it later
(import ghidra.program.model.listing.CodeUnit)

; add a comment to the current program
(def min-address (.getMinAddress ghidra/current-program))
(def listing (.getListing ghidra/current-program))
(def code-unit (.getCodeUnitAt listing min-address))
(.setComment
    code-unit
    CodeUnit/PLATE_COMMENT
    "This is an added comment from Clojure!")

; prompting the user for a data type
(println "Prompting for a data type...")
(import ghidra.app.util.datatype.DataTypeSelectionDialog)
(import ghidra.util.data.DataTypeParser$AllowedDataTypes)
(def tool (.. ghidra/script getState getTool))
(def selection-dialog
    (new DataTypeSelectionDialog
        tool
        (.getDataTypeManager ghidra/current-program)
        -1
        DataTypeParser$AllowedDataTypes/FIXED_LENGTH))
(.showDialog tool selection-dialog)
(def data-type (.getUserChosenDataType selection-dialog))
(if (some? data-type)
    (println (format "Chosen data type: %s" data-type))
    (println "No data type was chosen!"))
(println)

; report progress to the user interface
; do this anywhere things take a while
(.initialize ghidra/monitor 10)
(doseq [i (range 1 10)]
    (.checkCanceled ghidra/monitor) ; make sure we're still good to go
    (Thread/sleep 1000)
    (.incrementProgress ghidra/monitor 1)
    (.setMessage ghidra/monitor (format "working on step %d" i)))

; script output against example executable located in this repository at
; src/test/resources/bin/HelloGhidra.exe
;Program Info:
;HelloGhidra.exe x86:LE:32:default (windows)
;
;Memory Layout:
;Imagebase: 0x400000
;Headers [start: 0x00400000, end: 0x004003ff]
;.text [start: 0x00401000, end: 0x00401fff]
;.rdata [start: 0x00402000, end: 0x00402fff]
;.data [start: 0x00403000, end: 0x004031ff]
;.data [start: 0x00403200, end: 0x00403387]
;.rsrc [start: 0x00404000, end: 0x004041ff]
;.reloc [start: 0x00405000, end: 0x004051ff]
;
;Function List:
;FUN_00401000
;FUN_00401010
;Catch_All@004011b0
;FUN_004012ea
;entry
;FUN_00401549
;FUN_00401571
;find_pe_section
;___scrt_acquire_startup_lock
;___scrt_initialize_crt
;___scrt_initialize_onexit_tables
;___scrt_is_nonwritable_in_current_image
;___scrt_release_startup_lock
;___scrt_uninitialize_crt
;__onexit
;_atexit
;___get_entropy
;___security_init_cookie
;FUN_00401954
;FUN_00401957
;FUN_0040195b
;FUN_00401961
;FUN_0040196d
;FUN_00401970
;_guard_check_icall
;FUN_00401994
;FUN_0040199a
;FUN_004019a0
;FUN_004019bd
;FUN_004019c9
;FUN_004019cf
;FUN_004019d5
;thunk_FUN_00401954
;FUN_00401af5
;FUN_00401b44
;FUN_00401b9a
;FUN_00401ba2
;__SEH_prolog4
;__except_handler4
;FUN_00401c74
;___scrt_is_ucrt_dll_in_use
;Unwind@00401e57
;__current_exception
;__current_exception_context
;memset
;_except_handler4_common
;_seh_filter_exe
;_set_app_type
;__setusermatherr
;_configure_narrow_argv
;_initialize_narrow_environment
;_get_initial_narrow_environment
;_initterm
;_initterm_e
;exit
;_exit
;_set_fmode
;__p___argc
;__p___argv
;_cexit
;_c_exit
;_register_thread_local_exe_atexit_callback
;_configthreadlocale
;__p__commode
;_initialize_onexit_table
;_register_onexit_function
;_crt_atexit
;_controlfp_s
;terminate
;__filter_x86_sse2_floating_point_exception_default
;Unwind@00401f80
;Unwind@00401f88
;
;Current Location: 0x400000
;
;You entered 'HeadlessTest'

