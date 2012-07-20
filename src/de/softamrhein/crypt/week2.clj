(ns de.softamrhein.crypt.week2)
(use '[de.softamrhein.crypt.week1 :reload true])
(import (javax.crypto KeyGenerator SecretKey Cipher))
(import (javax.crypto.spec SecretKeySpec))

(defn do-aes-encrypt [rawkey rawtext]
     (let [cipher (. Cipher getInstance "AES/ECB/NoPadding")]
         (do (. cipher init (. Cipher ENCRYPT_MODE) (new SecretKeySpec rawkey "AES"))
             (. cipher doFinal rawtext))))

(defn do-aes-decrypt [rawkey ciphertext]
     (let [cipher (. Cipher getInstance "AES/ECB/NoPadding")]
         (do (. cipher init  (. Cipher DECRYPT_MODE) (new SecretKeySpec rawkey "Rijndael"))
             (vec(. cipher doFinal ciphertext)))))

(defn aes-cbc-step [step vec-key vec-ct]
  (unhexify
    (vec-to-hex
      (vec-xor
        (vec (vec-to-byte-array (vec-ct (dec step))))
        (do-aes-decrypt (vec-to-byte-array vec-key) (vec-to-byte-array (vec-ct step)))))))

(defn aes-cbc [key ct]
  (let [vec-key (hex-to-vec key) vec-ct (split-words (hex-to-vec ct) 16)]
    (loop [step 1 m ""]
      (if (>= step (count vec-ct))
      m
      (recur (inc step) (str m (aes-cbc-step step vec-key vec-ct)))))))

(defn inc-iv [iv step]
  (assoc
    iv 15
    (+ (dec step) (iv 15))))

(defn aes-ctr-step [step vec-key vec-ct]
  (unhexify
    (vec-to-hex
      (vec-xor
        (vec (do-aes-encrypt
               (vec-to-byte-array vec-key)
               (vec-to-byte-array (inc-iv (vec-ct 0) step))))
        (vec (vec-to-byte-array (vec-ct step)))))))

(defn aes-ctr [key ct]
  (let [vec-key (hex-to-vec key) vec-ct (split-words (hex-to-vec ct) 16)]
    (loop [step 1 m ""]
      (if (>= step (count vec-ct))
        m
        (recur
          (inc step)
          (str m (aes-ctr-step step vec-key vec-ct)))))))

(defn decrypt-aes-ctr [q]
  (aes-ctr (q :key) (q :ct)))

(defn decrypt-aes-cbc [q]
  (aes-cbc (q :key) (q :ct)))