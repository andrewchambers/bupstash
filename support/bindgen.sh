set -eux

bindgen ./csrc/sodium-bindings.h \
  --whitelist-function "crypto_.*" \
  --whitelist-type "crypto_.*" \
  --whitelist-var "crypto_.*" \
  --whitelist-function "sodium_.*" \
  --whitelist-var "sodium_.*" \
  --whitelist-function "randombytes_.*" \
  > ./src/sodium_bindings_gen.rs