//! Windows FILETIME and Unix time to ISO-8601 conversion.

/// FILETIME ticks (100 ns) in a second.
pub const FILETIME_TICKS_PER_SECOND: u64 = 10_000_000;
/// Seconds between 1601-01-01 (the FILETIME epoch) and 1970-01-01.
pub const FILETIME_UNIX_EPOCH_SECONDS: u64 = 11_644_473_600;
/// The FILETIME of 1970-01-01.
pub const FILETIME_UNIX_EPOCH_TICKS: u64 = FILETIME_UNIX_EPOCH_SECONDS * FILETIME_TICKS_PER_SECOND;

/// Unix time of 0001-01-01T00:00:00Z and 9999-12-31T23:59:59Z, the range
/// four-digit years cover.
const MIN_UNIX_SECONDS: i64 = -62_135_596_800;
const MAX_UNIX_SECONDS: i64 = 253_402_300_799;

/// Convert seconds since 1970-01-01 UTC (a minidump's `time_t` fields) to an
/// ISO-8601 UTC timestamp.
pub fn unix_time_to_iso(seconds: u64) -> Option<String> {
    iso(i64::try_from(seconds).ok()?, None)
}

/// Unix time `seconds`, which may be before 1970, as ISO-8601 UTC, with
/// `ticks` (100 ns units) as a fraction of the second when not zero; `None`
/// outside years 1 to 9999.
pub fn unix_seconds_to_iso(seconds: i64, ticks: u32) -> Option<String> {
    iso(seconds, (ticks != 0).then_some(ticks))
}

/// Convert a Windows FILETIME value to an ISO-8601 UTC timestamp. A FILETIME
/// before 1970 is `None`: in practice it is an unset field, not a date.
pub fn filetime_to_iso(ft: u64) -> Option<String> {
    iso(filetime_unix_seconds(ft)?, None)
}

/// A FILETIME as ISO-8601 UTC to its 100 ns tick,
/// `2026-10-15T23:31:38.9602438Z`: how the REPL shows a time where the
/// fraction matters (log records, events).
pub fn filetime_to_iso_precise(ft: u64) -> Option<String> {
    iso(
        filetime_unix_seconds(ft)?,
        Some((ft % FILETIME_TICKS_PER_SECOND) as u32),
    )
}

/// The Unix time of FILETIME `ft`, `None` before 1970.
fn filetime_unix_seconds(ft: u64) -> Option<i64> {
    let seconds = (ft / FILETIME_TICKS_PER_SECOND).checked_sub(FILETIME_UNIX_EPOCH_SECONDS)?;
    i64::try_from(seconds).ok()
}

fn iso(seconds: i64, ticks: Option<u32>) -> Option<String> {
    if !(MIN_UNIX_SECONDS..=MAX_UNIX_SECONDS).contains(&seconds) {
        return None;
    }
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let h = day_seconds / 3_600;
    let m = day_seconds % 3_600 / 60;
    let s = day_seconds % 60;
    let (y, mo, d) = days_to_ymd(days);
    Some(match ticks {
        Some(ticks) => format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.{ticks:07}Z"),
        None => format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z"),
    })
}

/// The proleptic-Gregorian (year, month, day) `days` days after 1970-01-01,
/// by Howard Hinnant's civil_from_days; `days` may be negative.
fn days_to_ymd(mut days: i64) -> (i64, i64, i64) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetimes_convert_up_to_the_end_of_year_9999() {
        let last = 2_650_467_743_999_999_999;
        assert_eq!(
            filetime_to_iso_precise(last).as_deref(),
            Some("9999-12-31T23:59:59.9999999Z")
        );
        assert_eq!(filetime_to_iso(last + 1), None);
        assert_eq!(
            unix_seconds_to_iso(-1, 0).as_deref(),
            Some("1969-12-31T23:59:59Z")
        );
    }
}
