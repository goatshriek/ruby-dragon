; Examples of basic Ghidra scripting in Clojure
; @category: Examples.Clojure

; use the ghidra namespace to access the provided variables
(def program-name
    (.getName ghidra/current-program))

; printing out some basic program information
(println "Program Info:")
(println (format "%s %s_%s (%s)"
    program-name
    (.getCreationDate ghidra/current-program)
    (.getLanguageID ghidra/current-program)
    (.. ghidra/current-program getCompilerSpec getCompilerSpecID)))
(println)

; get info about the current program's memory layout
(println "Memory Layout:")
(println (format "Imagebase: 0x%x"
    (.getOffset (.getImageBase ghidra/current-program))))
(doseq [block (.. ghidra/current-program getMemory getBlocks)]
    (println (format "%s [start: 0x%s, end:0x%s]"
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
(println (format "Current Location: 0x%s" (.getOffset ghidra/current-address)))
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

;# report progress to the user interface, do this anywhere things take a while
(.initialize ghidra/monitor 10)
(doseq [i (range 1 10)]
    (.checkCanceled ghidra/monitor) ; make sure we're still good to go
    (Thread/sleep 1000)
    (.incrementProgress ghidra/monitor 1)
    (.setMessage ghidra/monitor (format "working on step %d" i)))

; script output against .exe from crackme at:
; https://crackmes.one/static/crackme/5fcbac7733c5d424269a1a93.zip
;Program Info:
;FindMyPassword.exe Wed Mar 10 15:31:04 EST 2021_x86:LE:32:default (windows)
;
;Memory Layout:
;Imagebase: 0x400000
;Headers [start: 0x00400000, end:0x004003ff]
;.text [start: 0x00401000, end:0x00403dff]
;.data [start: 0x00404000, end:0x004041ff]
;.rdata [start: 0x00405000, end:0x004053ff]
;/4 [start: 0x00406000, end:0x004069ff]
;.bss [start: 0x00407000, end:0x004070b3]
;.idata [start: 0x00408000, end:0x004087ff]
;.CRT [start: 0x00409000, end:0x004091ff]
;.tls [start: 0x0040a000, end:0x0040a1ff]
;/14 [start: 0x0040b000, end:0x0040b1ff]
;/29 [start: 0x0040c000, end:0x0040ddff]
;/41 [start: 0x0040e000, end:0x0040e1ff]
;/55 [start: 0x0040f000, end:0x0040f1ff]
;/67 [start: 0x00410000, end:0x004101ff]
;
;Function List:
;FUN_004011b0
;__mingw32_init_mainargs
;_mainCRTStartup
;_atexit
;_hash
;_main
;__setargv
;___cpu_features_init
;___main
;tls_callback_1
;___dyn_tls_init@12
;.text
;___mingw_TLScallback
;.text
;FUN_00401f20
;__pei386_runtime_relocator
;___chkstk_ms
;_fesetenv
;.text
;FUN_00402320
;FUN_00402390
;FUN_00402650
;FUN_00402870
;FUN_004028d0
;FUN_00402920
;___mingw_glob
;___mingw_dirname
;.text
;FUN_004037d0
;___mingw_opendir
;___mingw_readdir
;___mingw_closedir
;___mingw_rewinddir
;_wcstombs
;_vfprintf
;_tolower
;_strlen
;_strcpy
;_strcoll
;_strcmp
;_srand
;_signal
;_setlocale
;_realloc
;_rand
;_printf
;_memcpy
;_mbstowcs
;_malloc
;_fwrite
;_free
;_calloc
;_abort
;__setmode
;__isctype
;__fullpath
;__errno
;__cexit
;___p__fmode
;___p__environ
;___getmainargs
;_VirtualQuery@12
;_VirtualProtect@16
;_TlsGetValue@4
;_SetUnhandledExceptionFilter@4
;_LoadLibraryA@4
;_LeaveCriticalSection@4
;_InitializeCriticalSection@4
;_GetProcAddress@8
;_GetModuleHandleA@4
;_GetLastError@0
;_GetCommandLineA@0
;_FreeLibrary@4
;_FindNextFileA@8
;_FindFirstFileA@8
;_FindClose@4
;_ExitProcess@4
;_EnterCriticalSection@4
;_DeleteCriticalSection@4
;_stricoll
;_strdup
;
;Current Location: 0x4194304
;
;You entered 'testing'
;
;Prompting for a data type...
;Chosen data type: char *

