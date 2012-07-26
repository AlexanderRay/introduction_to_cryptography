(ns de.softamrhein.crypt.week4)
(require '[clj-http.client :as client])
(use 'de.softamrhein.crypt.week1)

(defn get-status
  ([u] (get-status (u :url) (u :cipher)))
  ([url cipher] ((client/get (str url cipher) {:throw-exceptions false}) :status)))

(defn convert-cipher [cipher-vec guess-vec pad offset]
  (let [r-v (reverse cipher-vec) r-g (reverse guess-vec)]
    (vec
      (reverse
        (map-indexed
          (fn [idx itm]
            (if (or (< idx offset) (>= idx (+ pad offset)))
              itm
              (bit-xor itm pad (nth r-g (- idx offset)))))
          r-v)))))

(defn guess-first-byte [url cipher-v guess-v pad]
  (loop [i 0]
    (let [new-guess (vec (cons i guess-v))
          new-cipher-vec (convert-cipher cipher-v new-guess pad 16)
          s (get-status url (vec-to-hex new-cipher-vec))]
      (cond
        (or
          (= s 404)
          (and (> pad 1) (= s 200))
          ) new-guess
        (>= i 255) "not found"
        :else (recur (inc i))))))

(defn guess-block [url v]
  (loop [pad 1 guess-v []]
    (println "pad - " (dec pad) " v - " guess-v)
    (if (> pad 16)
      guess-v
      (recur
        (inc pad)
        (guess-first-byte url v guess-v pad)))))
