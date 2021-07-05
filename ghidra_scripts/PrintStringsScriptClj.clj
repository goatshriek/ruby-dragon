; Prints all strings in the current program
; This is based on the CountAndSaveStrings script included with Ghidra.

; @category: Examples.Clojure

(def filename "saved_strings.txt")

(def string-count (atom 0))

(def data-iterator (.. ghidra/current-program getListing (getDefinedData true)))
(doseq [data (seq data-iterator)]
    (def type-name (.. data getDataType getName))
    (def val-rep (.getDefaultValueRepresentation data))
    (when (and (or (.contains type-name "unicode") (.contains type-name "string")) (> (.length val-rep) 4))
        (println (format "found string: %s" data))
        (swap! string-count inc)))

(println (format "total number of strings: %s" (deref string-count)))

