; Save all strings of five characters or more in the current program to a file
; with the given name, or `saved_strings.txt` if no filename was given as a
; command line argument. This script is based on the CountAndSaveStrings script
; included with Ghidra.

; @category: Examples.Clojure


; read in the filename, or default to `saved_strings.txt` if none was passed
(def filename
    (if (nil? (first *command-line-args*))
        "saved_strings.txt"
        (first *command-line-args*)))

; initialize the string counter
(def string-count (atom 0))

; go through the data in the program
(def data-iterator (.. ghidra/current-program getListing (getDefinedData true)))
(with-open [out-file (clojure.java.io/writer filename)]
    (doseq [data (seq data-iterator)]
        (def type-name (.. data getDataType getName))
        (def val-rep (.getDefaultValueRepresentation data))
        (when (and (or (.contains type-name "unicode") (.contains type-name "string")) (> (.length val-rep) 4))
            (swap! string-count inc)
            (.write out-file (format "%s\n" data)))))

; print out the final string count
(spit filename (format "\ntotal number of strings: %s\n" (deref string-count)) :append true)

