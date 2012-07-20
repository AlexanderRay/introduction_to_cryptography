(ns de.softamrhein.crypt.week1)

(defn hexify [s]
  (format "%02x" (new java.math.BigInteger (.getBytes s))))

(defn hexify-2 [s]
  (apply str
    (map #(format "%02x" (int %)) s)))

(defn string-to-vec [s]
  (map #(+ 128 %1) (vec (.getBytes s))))

(defn hex-to-vec [hex]
  (vec
    (map
      (fn [[x y]] (Integer/parseInt (str x y) 16))
        (partition 2 hex))))

(defn vec-to-hex [vec]
  (apply str
    (map #(format "%02x" %1) vec)))

(defn unhexify [hex]
  (apply str
    (map char (hex-to-vec hex))))

(defn vec-xor [x y]
  (vec (map bit-xor x y)))

(defn otp-transform [m e]
  (vec-to-hex (vec-xor (hex-to-vec (hexify m)) (hex-to-vec e))))

(defn recrypt [m new-m encrypted-m]
  (otp-transform new-m (otp-transform m encrypted-m)))

(defn bit-bool [x] (if x 1 0))

(defn byte-to-bitvec [x]
  (vec (reverse (map #(bit-bool (bit-test x %1)) (range 8)))))

(defn check-bitvec [v]
  (and (= 8 (count v)) (every? #(>= %1 0) v)))

(defn bit-set+ [x n b]
  (if (pos? b)
    (bit-set x n)
    x))

(defn bitvec-to-byte [v]
  (loop [x v b 0]
    (if (empty? x)
      b
      (recur
        (rest x)
        (bit-set+ b (dec (count x)) (first x))))))

(defn bits [n s]
         (take s
               (map
                 (fn [i] (bit-and 0x01 i))
                 (iterate
                   (fn [i] (bit-shift-right i 1))
                   n))))

(defn ubyte [val]
   (if (>= val 128)
     (byte (- val 256))
     (byte val)))

(defn ubyte-to-byte [val]
  (if (neg? val)
    (+ val 256)
    val))

(defn vec-to-byte-array [vc]
  (byte-array
    (loop [vb (vector-of :byte) v vc]
      (if (empty? v)
        vb
        (recur (conj vb (ubyte (first v))) (rest v))))))

(defn byte-array-to-vec [buffer]
  (let [res (vec buffer)]
    (vec (map ubyte-to-byte res))))

(defn split-words [vc cnt]
  (loop [v vc r []]
    (if (empty? v)
      r
      (recur (vec (drop cnt v)) (conj r (vec (take cnt v)))))))

