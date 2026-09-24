//! Windows FILETIME to ISO-8601 conversion.

/// Convert a Windows FILETIME value to an ISO-8601 UTC timestamp.
pub fn filetime_to_iso(ft: u64) -> Option<String> {
    // Windows FILETIME: 100-ns intervals since 1601-01-01 UTC.
    const EPOCH_DIFF: i64 = 11_644_473_600;
    let secs = (ft / 10_000_000) as i64 - EPOCH_DIFF;
    if !(0..=253_402_300_799).contains(&secs) {
        return None;
    }
    let s = secs % 60;
    let total_m = secs / 60;
    let m = total_m % 60;
    let total_h = total_m / 60;
    let h = total_h % 24;
    let days = total_h / 24;
    let (y, mo, d) = days_to_ymd(days);
    Some(format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z"))
}

fn days_to_ymd(mut days: i64) -> (i64, i64, i64) {
    // Civil days since 1970-01-01 to (year, month, day).
    days += 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
