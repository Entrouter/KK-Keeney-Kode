/// AVX-512 detection check for KK-Crypto Phase 3 verification.
fn main() {
    #[cfg(target_arch = "x86_64")]
    {
        println!("=== AVX-512 Feature Detection ===");
        println!("avx512f:  {}", is_x86_feature_detected!("avx512f"));
        println!("avx512dq: {}", is_x86_feature_detected!("avx512dq"));
        println!("avx512vl: {}", is_x86_feature_detected!("avx512vl"));
        println!("avx512bw: {}", is_x86_feature_detected!("avx512bw"));
        println!();

        // CPU brand string via cpuid
        let brand = get_cpu_brand();
        println!("CPU: {brand}");

        // Confirm target-cpu=native is in effect by checking if AVX-512
        // instructions are usable at compile time
        #[cfg(target_feature = "avx512f")]
        println!("\ntarget_feature avx512f: ENABLED at compile time");
        #[cfg(not(target_feature = "avx512f"))]
        println!("\ntarget_feature avx512f: NOT enabled at compile time (runtime dispatch only)");
    }

    #[cfg(not(target_arch = "x86_64"))]
    println!("Not x86_64 - AVX-512 not applicable");
}

#[cfg(target_arch = "x86_64")]
fn get_cpu_brand() -> String {
    let mut brand = String::new();
    for leaf in 0x80000002u32..=0x80000004u32 {
        #[allow(unused_unsafe)]
        let result = unsafe { core::arch::x86_64::__cpuid(leaf) };
        for &reg in &[result.eax, result.ebx, result.ecx, result.edx] {
            let bytes = reg.to_le_bytes();
            for &b in &bytes {
                if b != 0 {
                    brand.push(b as char);
                }
            }
        }
    }
    brand.trim().to_string()
}
