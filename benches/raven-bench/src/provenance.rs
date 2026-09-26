//! Machine class, build and capture time for a bench artifact.
//!
//! A baseline is only comparable against a run from the same machine class and the same
//! build, so an artifact that does not carry both cannot be checked for that at all.

use std::path::Path;
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
    let hypervisor = hypervisor(std::fs::read_to_string("/proc/cpuinfo").ok().as_deref());
    let mut out = format!(
        "os={}; arch={}; cpus={}; cpu={}; hypervisor={hypervisor}",
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

/// The build this binary came from, as stable `key=value` pairs read from the build.
///
/// Cargo takes rustflags from `CARGO_ENCODED_RUSTFLAGS`, then `RUSTFLAGS`, then config,
/// and only the first two reach the compiler's environment. A config-file flag is
/// reported by its effect instead: `target_features` is what the code was compiled for.
#[must_use]
pub fn build() -> String {
    let (source, flags) = rustflags(
        option_env!("CARGO_ENCODED_RUSTFLAGS"),
        option_env!("RUSTFLAGS"),
    );
    let features = compiled_target_features();
    let exe = std::env::current_exe().ok();
    format!(
        "profile_dir={}; debug_assertions={}; rustflags_source={source}; rustflags={flags}; \
         target_features={}",
        exe.as_deref().and_then(profile_dir).unwrap_or(UNKNOWN),
        cfg!(debug_assertions),
        if features.is_empty() {
            "baseline".to_owned()
        } else {
            features.join(",")
        }
    )
}

fn rustflags(encoded: Option<&str>, plain: Option<&str>) -> (&'static str, String) {
    let (source, flags) = match (encoded, plain) {
        (Some(e), _) => (
            "CARGO_ENCODED_RUSTFLAGS",
            e.split('\u{1f}')
                .filter(|f| !f.is_empty())
                .collect::<Vec<_>>()
                .join(" "),
        ),
        (None, Some(p)) => (
            "RUSTFLAGS",
            p.split_whitespace().collect::<Vec<_>>().join(" "),
        ),
        (None, None) => return ("config-or-none", UNKNOWN.to_owned()),
    };
    if flags.is_empty() {
        (source, "none".to_owned())
    } else {
        (source, flags)
    }
}

/// The directory the executable runs from, past `deps/` or `examples/`. It names the cargo
/// profile only when the binary runs where cargo wrote it; a copy reports where it went.
fn profile_dir(exe: &Path) -> Option<&str> {
    let mut dir = exe.parent()?;
    if matches!(dir.file_name()?.to_str()?, "deps" | "examples") {
        dir = dir.parent()?;
    }
    dir.file_name()?.to_str()
}

macro_rules! enabled_target_features {
    ($($feature:literal),* $(,)?) => {{
        let mut on: Vec<&'static str> = Vec::new();
        $(if cfg!(target_feature = $feature) { on.push($feature); })*
        on
    }};
}

fn compiled_target_features() -> Vec<&'static str> {
    enabled_target_features!(
        "sse4.2",
        "popcnt",
        "avx",
        "avx2",
        "fma",
        "bmi2",
        "adx",
        "avx512f",
        "avx512vl",
        "avx512ifma",
        "neon",
        "sve",
    )
}

/// Capture time as RFC 3339 UTC to the second.
#[must_use]
pub fn captured_at() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or_else(|_| UNKNOWN.to_owned(), |d| rfc3339_utc(d.as_secs()))
}

/// The CPUID hypervisor bit as the kernel lists it. Without an x86 `flags` line the answer
/// is unknown, so a platform that cannot say is never read as bare metal.
fn hypervisor(cpuinfo: Option<&str>) -> &'static str {
    let flags = cpuinfo.and_then(|info| info.lines().find_map(|line| line.strip_prefix("flags")));
    match flags.map(|f| f.split_whitespace().any(|flag| flag == "hypervisor")) {
        Some(true) => "yes",
        Some(false) => "no",
        None => UNKNOWN,
    }
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
        for key in ["os=", "arch=", "cpus=", "cpu=", "hypervisor="] {
            assert!(h.contains(key), "hardware() dropped {key}: {h}");
        }
    }

    #[test]
    fn rustflags_follow_cargo_precedence() {
        assert_eq!(
            rustflags(Some("-C\u{1f}target-cpu=native"), Some("-D warnings")),
            ("CARGO_ENCODED_RUSTFLAGS", "-C target-cpu=native".to_owned())
        );
        assert_eq!(
            rustflags(None, Some(" -D  warnings ")),
            ("RUSTFLAGS", "-D warnings".to_owned())
        );
        assert_eq!(rustflags(None, Some("")), ("RUSTFLAGS", "none".to_owned()));
        assert_eq!(
            rustflags(Some(""), None),
            ("CARGO_ENCODED_RUSTFLAGS", "none".to_owned())
        );
        assert_eq!(
            rustflags(None, None),
            ("config-or-none", UNKNOWN.to_owned())
        );
    }

    #[test]
    fn hypervisor_is_read_from_the_x86_flags_line_only() {
        let guest =
            "processor\t: 0\nflags\t\t: fpu sse2 hypervisor avx512ifma\nbugs\t\t: spectre_v1\n";
        let metal = "flags\t\t: fpu sse2 hypervisor_like avx512ifma\nvmx flags\t: hypervisor\n";
        let arm = "processor\t: 0\nFeatures\t: fp asimd\n";
        assert_eq!(hypervisor(Some(guest)), "yes");
        assert_eq!(hypervisor(Some(metal)), "no");
        assert_eq!(hypervisor(Some(arm)), UNKNOWN);
        assert_eq!(hypervisor(None), UNKNOWN);
    }

    /// `rustflags` is covered on its own; this pins which compile-time variable feeds which
    /// argument, where a swap would attribute flags cargo did not use.
    #[test]
    fn build_reads_the_variable_cargo_took_its_flags_from() {
        let (source, flags) = rustflags(
            option_env!("CARGO_ENCODED_RUSTFLAGS"),
            option_env!("RUSTFLAGS"),
        );
        let b = build();
        assert!(
            b.contains(&format!("; rustflags_source={source}; rustflags={flags}; ")),
            "{b}"
        );
    }

    #[test]
    fn profile_dir_is_the_directory_cargo_chose() {
        for (exe, expected) in [
            ("/r/target/release/b1-inspire", Some("release")),
            ("/r/target/ci-test/deps/bench-0123abcd", Some("ci-test")),
            (
                "/r/target/x86_64-unknown-linux-gnu/release/deps/t-1",
                Some("release"),
            ),
            ("/r/target/debug/examples/demo", Some("debug")),
            ("b1-inspire", None),
        ] {
            assert_eq!(profile_dir(Path::new(exe)), expected, "{exe}");
        }
    }

    #[test]
    fn build_names_every_component_and_none_is_blank() {
        let b = build();
        for key in [
            "profile_dir=",
            "debug_assertions=",
            "rustflags_source=",
            "rustflags=",
            "target_features=",
        ] {
            let value = b
                .split("; ")
                .find_map(|pair| pair.strip_prefix(key))
                .unwrap_or_else(|| panic!("build() dropped {key}: {b}"));
            assert!(!value.is_empty(), "{key} is blank: {b}");
        }
    }

    #[test]
    fn build_reports_what_this_crate_was_compiled_for() {
        let b = build();
        assert_eq!(b.contains("avx2"), cfg!(target_feature = "avx2"), "{b}");
        assert_eq!(
            b.contains("debug_assertions=true"),
            cfg!(debug_assertions),
            "{b}"
        );
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
