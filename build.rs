// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

fn main() {
    #[cfg(feature = "cuda")]
    {
        let cuda_path = std::env::var("CUDA_PATH")
            .unwrap_or_else(|_| r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.2".into());

        cc::Build::new()
            .cuda(true)
            .file("src/kk_permute.cu")
            .flag("-O3")
            .flag("--use_fast_math")
            .include(format!("{}/include", cuda_path))
            .compile("kk_cuda");

        println!("cargo:rustc-link-search=native={}/lib/x64", cuda_path);
        println!("cargo:rustc-link-lib=dylib=cudart");
        println!("cargo:rerun-if-changed=src/kk_permute.cu");
    }
}
