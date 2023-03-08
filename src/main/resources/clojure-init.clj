(require '[clojure.xml :as xml])

(println (xml/parse (.getInputStream ghidra-repl/preload-file)))