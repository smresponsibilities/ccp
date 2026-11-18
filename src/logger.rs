//! Tiny append-only log (`ccp.log`) so you can see what the background daemon did
//! without attaching a debugger. Never write credentials here.

use std::fs;
use std::io::Write;
use std::path::Path;

pub const LOG_FILE: &str = "ccp.log";
const MAX_BYTES: u64 = 256 * 1024;

/// Appends a timestamped line; rotates to `ccp.log.1` past 256 KiB. Failures are
/// ignored: logging must never break the daemon.
pub fn log(config_dir: &Path, msg: &str) {
    let path = config_dir.join(LOG_FILE);
    let _ = fs::create_dir_all(config_dir);

    if fs::metadata(&path).is_ok_and(|m| m.len() > MAX_BYTES) {
        let _ = fs::rename(&path, config_dir.join(format!("{LOG_FILE}.1")));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "[{}] {}", format_utc(now), msg.replace('\n', " "));
    }
}

/// Last `n` log lines (oldest first).
pub fn tail(config_dir: &Path, n: usize) -> Vec<String> {
    let content = fs::read_to_string(config_dir.join(LOG_FILE)).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].iter().map(|s| s.to_string()).collect()
}

/// `YYYY-MM-DD HH:MM:SSZ` (UTC) without pulling in a date/time crate.
pub fn format_utc(epoch_secs: u64) -> String {
    let days = (epoch_secs / 86_400) as i64;
    let rem = epoch_secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's days-since-epoch -> civil date algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_timestamps() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00Z");
        assert_eq!(format_utc(1_700_000_000), "2023-11-14 22:13:20Z");
        // Leap day
        assert_eq!(format_utc(1_709_164_800), "2024-02-29 00:00:00Z");
    }

    #[test]
    fn log_tail_and_rotation() {
        let dir = std::env::temp_dir().join(format!("ccp_log_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        log(&dir, "first");
        log(&dir, "multi\nline");
        log(&dir, "third");
        let lines = tail(&dir, 2);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].ends_with("multi line"));
        assert!(lines[1].ends_with("third"));

        // Force a rotation
        fs::write(dir.join(LOG_FILE), vec![b'x'; (MAX_BYTES + 10) as usize]).unwrap();
        log(&dir, "after rotate");
        assert!(dir.join("ccp.log.1").exists());
        assert_eq!(tail(&dir, 10).len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }
}
