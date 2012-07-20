(ns de.softamrhein.crypt.week3)
(use 'de.softamrhein.crypt.week1)

(import (java.io BufferedReader FileReader File FileInputStream))
(import (java.security MessageDigest))

(defn get-file-size [file-name]
  (let [f (File. file-name)]
    (.length f)))

(defn get-block-count [file-name]
  (let [fs (get-file-size file-name) cnt (quot fs 1024) lst (mod fs 1024)]
    (if (zero? lst)
      cnt
      (inc cnt))))


(defn get-next-block [fs size]
  (let [buffer (byte-array size) read-size (.read fs buffer 0 size)]
    (if (= size read-size)
      buffer
      (into-array Byte/TYPE (areduce buffer i ret [] (if (< i read-size) (conj ret (aget buffer i)) ret))))))

(defn get-blocks [file-name]
  (with-open [fs (FileInputStream. file-name)]
    (loop [vec []]
      (let [ buffer (get-next-block fs 1024)]
        (if (zero? (alength buffer))
          vec
          (recur (concat [buffer] vec)))))))

(defn sha [input]
  (let [md (MessageDigest/getInstance "SHA-256")]
    (.digest md input)))

(defn chain-sha [input]
  (loop [res (sha (first input)) data (rest input)]
    (if (empty? data)
      res
      (recur
        (sha (into-array Byte/TYPE
               (flatten (conj (vec (first data)) (vec res)))))
        (rest data)))))

(defn chain-sha-file [file-name]
  (let [blocks (get-blocks file-name)]
    (vec-to-hex (byte-array-to-vec (chain-sha blocks)))))

