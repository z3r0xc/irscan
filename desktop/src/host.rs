//! Host identification for the window.
//!
//! Kept separate from `scan.rs` so that the pure conversion in `view.rs` stays testable
//! and so that this, the only part that reads the machine's identity, is easy to find.

use irscan::report::HostInfo;
use irscan::win;

/// Read the machine's identity, using the same accessors as the command-line tool.
///
/// The date arithmetic is duplicated from the CLI on purpose: it is twenty lines of
/// civil-from-days, and moving it into the library to share it would mean the library
/// owning presentation. If it ever needs to change, the library gains a
/// `format_epoch` helper and both surfaces call it.
pub fn collect() -> HostInfo {
    let ver = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let os_name = win::reg::get_string(win::reg::RootKey::Hklm, ver, "ProductName")
        .unwrap_or_else(|| "Windows".to_string());
    let build_number = win::reg::get_string(win::reg::RootKey::Hklm, ver, "CurrentBuildNumber")
        .unwrap_or_default();
    let revision = win::reg::get_string(win::reg::RootKey::Hklm, ver, "UBR").unwrap_or_default();
    let install_epoch = win::reg::get_u64(win::reg::RootKey::Hklm, ver, "InstallDate");

    let build = if revision.is_empty() {
        build_number
    } else {
        format!("{build_number}.{revision}")
    };
    let install_date = match install_epoch {
        Some(secs) => epoch_to_datetime(secs),
        None => "unknown".to_string(),
    };
    let boot_epoch = now_epoch_secs().saturating_sub(win::uptime_seconds());

    HostInfo {
        name: std::env::var("COMPUTERNAME").unwrap_or_default(),
        user: std::env::var("USERNAME").unwrap_or_default(),
        os: os_name,
        build,
        install_date,
        boot_time: epoch_to_datetime(boot_epoch),
        elevated: win::is_elevated(),
        collected_at: win::local_time_string(),
    }
}

fn now_epoch_secs() -> u64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => 0,
    }
}

/// Convert Unix epoch seconds to a UTC stamp. Howard Hinnant's civil-from-days.
fn epoch_to_datetime(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_conversion_matches_published_values() {
        assert_eq!(epoch_to_datetime(0), "1970-01-01 00:00:00");
        assert_eq!(epoch_to_datetime(946_684_800), "2000-01-01 00:00:00");
        assert_eq!(epoch_to_datetime(1_000_000_000), "2001-09-09 01:46:40");
        // A leap day, where naive implementations break.
        assert_eq!(epoch_to_datetime(951_782_400), "2000-02-29 00:00:00");
    }

    #[test]
    fn the_host_block_is_populated_on_windows() {
        let host = collect();
        assert!(!host.os.is_empty());
        assert!(host.collected_at.len() >= 19);
    }
}
