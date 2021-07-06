; Save all strings in the current program to a file with the given name, or
; saved_strings.txt if no file is given.
; This script is based on the CountAndSaveStrings script included with Ghidra.

; @category: Examples.Clojure

(def filename "saved_strings.txt")
(println *command-line-args*)

; initialize the string counter
(def string-count (atom 0))

(def data-iterator (.. ghidra/current-program getListing (getDefinedData true)))
(with-open [out-file (clojure.java.io/writer filename)]
    (doseq [data (seq data-iterator)]
        (def type-name (.. data getDataType getName))
        (def val-rep (.getDefaultValueRepresentation data))
        (when (and (or (.contains type-name "unicode") (.contains type-name "string")) (> (.length val-rep) 4))
            (swap! string-count inc)
            (.write out-file (format "%s\n" data)))))

(spit filename (format "\ntotal number of strings: %s\n" (deref string-count)) :append true)

