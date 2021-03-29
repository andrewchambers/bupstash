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
    if n > 1_000_000_000_000_000 {
        format!(
            "{}.{:0>2}PB",
            n / 1_000_000_000_000_000,
            (n % 1_000_000_000_000_000) / 10_000_000_000_000
        )
    } else if n > 1_000_000_000_000 {
        format!(
            "{}.{:0>2}TB",
            n / 1_000_000_000_000,
            (n % 1_000_000_000_000 / 10_000_000_000)
        )
    } else if n > 1_000_000_000 {
        format!(
            "{}.{:0>2}GB",
            n / 1_000_000_000,
            (n % 1_000_000_000) / 10_000_000
        )
    } else if n > 1_000_000 {
        format!("{}.{:0>2}MB", n / 1_000_000, (n % 1_000_000) / 10_000)
    } else if n > 1_000 {
        format!("{}.{:0>2}kB", n / 1_000, (n % 1_000) / 10)
    } else {
        format!("{}B", n)
    }
}
