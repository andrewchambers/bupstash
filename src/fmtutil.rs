pub fn format_timestamp(ts: &chrono::DateTime<chrono::Utc>, utc_timestamps: bool) -> String {
    let tsfmt = "%Y/%m/%d %T";
    if utc_timestamps {
        ts.format(tsfmt).to_string()
    } else {
        chrono::DateTime::<chrono::Local>::from(*ts)
            .format(tsfmt)
            .to_string()
    }
}

pub fn format_size(n: u64) -> String {
    // Binary units, not SI units.
    const K: u64 = 1024;
    const M: u64 = 1024 * K;
    const G: u64 = 1024 * M;
    const T: u64 = 1024 * G;
    const P: u64 = 1024 * T;

    if n > P {
        format!("{}.{:0>2}PiB", n / P, (n % P) / (P / 100))
    } else if n > T {
        format!("{}.{:0>2}TiB", n / T, (n % T) / (T / 100))
    } else if n > G {
        format!("{}.{:0>2}GiB", n / G, (n % G) / (G / 100))
    } else if n > M {
        format!("{}.{:0>2}MiB", n / M, (n % M) / (M / 100))
    } else if n > K {
        format!("{}.{:0>2}KiB", n / K, (n % K) / (K / 100))
    } else {
        format!("{}B", n)
    }
}
