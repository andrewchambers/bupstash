let 
  pkgs = (import <nixpkgs>) {};
in
  pkgs.stdenv.mkDerivation {
      name = "shell";
      
      LIBCLANG_PATH="${pkgs.llvmPackages.libclang}/lib";

      buildInputs =  with pkgs; [ 
        clang
        clang-tools
        linuxPackages.perf
        llvm
        entr
        minio
        minio-client
        pandoc
        bats
        openssl
        libsodium
        pkg-config
        sqlite
        rust-bindgen
        jq
        (pkgs.callPackage ./ronn {})
        hyperfine
      ];

      hardeningDisable = ["all"];
  }
