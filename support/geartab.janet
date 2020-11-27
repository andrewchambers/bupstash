
(import base16)

(print "static GEAR_TAB : [u64; 256] = [")
(for i 0 256
  (print "    0x" (base16/encode (os/cryptorand 8)) ","))
(print "];")