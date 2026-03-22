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
