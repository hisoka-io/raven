//! Machine class and capture time for a bench artifact.
//!
//! A baseline is only comparable against a run from the same machine class, so an
//! artifact that does not carry one cannot be checked for that at all.

use std::time::{SystemTime, UNIX_EPOCH};

/// Marker for a component this platform does not expose. Never an empty string: a
/// blank field reads as "not applicable" and is what let the fields go unnoticed.
const UNKNOWN: &str = "unknown";

/// Machine class as stable `key=value` pairs, ordered so two artifacts diff line-wise.
///
/// Identifies the class, never the host: a CPU model and a runner image label are
/// public, a hostname is operator infrastructure.
#[must_use]
pub fn hardware() -> String {
    let cpus = std::thread::available_parallelism()
        .map_or_else(|_| UNKNOWN.to_owned(), |n| n.get().to_string());
    let mut out = format!(
        "os={}; arch={}; cpus={}; cpu={}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        cpus,
        cpu_model()
    );
    if let Ok(image) = std::env::var("ImageOS") {
        if !image.is_empty() {
            out.push_str("; image=");
            out.push_str(&image);
        }
    }
    out
}

/// Capture time as RFC 3339 UTC to the second.
#[must_use]
pub fn captured_at() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or_else(|_| UNKNOWN.to_owned(), |d| rfc3339_utc(d.as_secs()))
}

fn cpu_model() -> String {
    let Ok(info) = std::fs::read_to_string("/proc/cpuinfo") else {
        return UNKNOWN.to_owned();
    };
    info.lines()
        .find_map(|line| line.strip_prefix("model name"))
        .and_then(|rest| rest.split_once(':'))
        .map_or_else(
            || UNKNOWN.to_owned(),
            |(_, model)| {
                let model = model.trim();
                if model.is_empty() {
                    UNKNOWN.to_owned()
                } else {
                    model.split_whitespace().collect::<Vec<_>>().join(" ")
                }
            },
        )
}

/// Civil date from a Unix timestamp, after Howard Hinnant's `civil_from_days`
/// (<http://howardhinnant.github.io/date_algorithms.html>). Unsigned because the
/// input is `u64`, so the pre-1970 era branch is unreachable here.
fn rfc3339_utc(epoch_secs: u64) -> String {
    let days = epoch_secs / 86_400;
    let secs_of_day = epoch_secs % 86_400;

    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);

    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_matches_known_timestamps() {
        // Independently checkable: `date -u -d @<secs> +%Y-%m-%dT%H:%M:%SZ`.
        for (secs, expected) in [
            (0_u64, "1970-01-01T00:00:00Z"),
            (1, "1970-01-01T00:00:01Z"),
            (86_399, "1970-01-01T23:59:59Z"),
            (86_400, "1970-01-02T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (1_234_567_890, "2009-02-13T23:31:30Z"),
            (1_709_164_800, "2024-02-29T00:00:00Z"),
            (2_147_483_647, "2038-01-19T03:14:07Z"),
            (4_102_444_800, "2100-01-01T00:00:00Z"),
        ] {
            assert_eq!(rfc3339_utc(secs), expected, "epoch {secs}");
        }
    }

    #[test]
    fn rfc3339_advances_monotonically_across_a_year_of_days() {
        let mut previous = rfc3339_utc(0);
        for day in 1..=366_u64 {
            let current = rfc3339_utc(day * 86_400);
            assert!(
                current > previous,
                "day {day}: {current} did not sort after {previous}"
            );
            previous = current;
        }
    }

    /// The defect this module exists for: a field written empty is read by nothing and
    /// noticed by nobody.
    #[test]
    fn neither_field_is_ever_empty() {
        assert!(!hardware().is_empty());
        assert!(!captured_at().is_empty());
    }

    #[test]
    fn hardware_names_every_component_even_when_a_probe_fails() {
        let h = hardware();
        for key in ["os=", "arch=", "cpus=", "cpu="] {
            assert!(h.contains(key), "hardware() dropped {key}: {h}");
        }
    }

    #[test]
    fn captured_at_is_a_plausible_present_date() {
        let now = captured_at();
        assert_eq!(now.len(), 20, "not RFC 3339 to the second: {now}");
        assert!(now.ends_with('Z'), "not UTC: {now}");
        assert!(
            now.as_str() > "2026-01-01T00:00:00Z",
            "clock reads before this code was written: {now}"
        );
    }
}
