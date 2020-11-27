
(import base16)

(print "static GEAR_TAB : [u32; 256] = [")
(for i 0 256
  (print "    0x" (base16/encode (os/cryptorand 4)) ","))
(print "];")