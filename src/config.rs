//! Config-directory resolution, credential storage and user settings.
//!
//! Everything `ccp` persists (credentials, state, lock, trust list, log) lives in one
//! directory. Resolution order:
//!
//! 1. `CCP_CONFIG_DIR` (explicit override, also handy for tests)
//! 2. `<home>/.config/ccp` if it already holds credentials (the canonical location)
//! 3. a legacy location that already holds credentials (older versions probed several)
//! 4. `<home>/.config/ccp` for new installs

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub const CREDENTIALS_FILE: &str = "credentials.txt";
const SETTINGS_FILE: &str = "settings.json";

fn canonical_dir() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".config").join("ccp"))
        .unwrap_or_else(|| PathBuf::from(".config/ccp"))
}

fn legacy_dirs() -> Vec<PathBuf> {
    let mut dirs_out = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        dirs_out.push(PathBuf::from(home).join(".config").join("ccp"));
    }
    if let Some(cfg) = dirs::config_dir() {
        dirs_out.push(cfg.join("ccp"));
    }
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        dirs_out.push(PathBuf::from(profile).join(".config").join("ccp"));
    }
    dirs_out
}

/// Directory that holds credentials, state, lock file, trust list and log.
pub fn config_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("CCP_CONFIG_DIR")
        && !dir.is_empty()
    {
        return PathBuf::from(dir);
    }

    let canonical = canonical_dir();
    if canonical.join(CREDENTIALS_FILE).exists() {
        return canonical;
    }
    for dir in legacy_dirs() {
        if dir.join(CREDENTIALS_FILE).exists() {
            return dir;
        }
    }
    canonical
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

// Never print the password, even by accident (`{:?}` in an error path).
impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Parses `username\npassword\n`. Surrounding whitespace is trimmed (a stray trailing
/// space from a paste is far more common than an intentional one).
pub fn parse_credentials(contents: &str) -> Option<Credentials> {
    let mut lines = contents.lines();
    let username = lines.next()?.trim().to_string();
    let password = lines.next()?.trim().to_string();
    if username.is_empty() || password.is_empty() {
        return None;
    }
    Some(Credentials { username, password })
}

pub fn credentials_path(dir: &Path) -> PathBuf {
    dir.join(CREDENTIALS_FILE)
}

pub fn load_credentials(dir: &Path) -> Result<Credentials, String> {
    let path = credentials_path(dir);
    if !path.exists() {
        return Err("Credentials not found. Run `ccp set` first.".to_string());
    }
    let contents =
        fs::read_to_string(&path).map_err(|e| format!("Failed to read credentials: {e}"))?;
    tighten_permissions(&path);
    parse_credentials(&contents)
        .ok_or_else(|| "Username or password missing in credentials file.".to_string())
}

/// Self-heal: a credentials file copied or restored with loose permissions (e.g. 0644)
/// is made owner-only the next time it is read. No-op on Windows.
fn tighten_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path)
            && meta.permissions().mode() & 0o077 != 0
        {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

pub fn save_credentials(dir: &Path, username: &str, password: &str) -> io::Result<()> {
    create_private_dir(dir)?;
    write_private(
        &credentials_path(dir),
        format!("{username}\n{password}\n").as_bytes(),
    )
}

/// Creates the config directory (mode 0700 on Unix).
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best effort: the directory may be shared with something we don't own.
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// Writes `bytes` to `path` via a temp file + rename, so a crash can't leave a
/// half-written credentials file. The file is mode 0600 on Unix, including when
/// replacing an older, more permissive file.
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let result = (|| {
        let mut file = opts.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/// User-editable settings, stored as `settings.json`. Unknown/missing fields fall
/// back to defaults so the file stays forward and backward compatible.
#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct Settings {
    /// Wi-Fi networks `ccp` may (re)connect to by itself. Empty = never touch Wi-Fi.
    pub wifi_ssids: Vec<String>,
}

impl Settings {
    pub fn load(dir: &Path) -> Self {
        fs::read_to_string(dir.join(SETTINGS_FILE))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> io::Result<()> {
        create_private_dir(dir)?;
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_private(&dir.join(SETTINGS_FILE), json.as_bytes())
    }

    /// Returns `true` if the SSID was newly added (case-insensitive de-dup).
    pub fn add_ssid(&mut self, ssid: &str) -> bool {
        let ssid = ssid.trim();
        if ssid.is_empty() || self.has_ssid(ssid) {
            return false;
        }
        self.wifi_ssids.push(ssid.to_string());
        true
    }

    /// Returns `true` if something was removed.
    pub fn remove_ssid(&mut self, ssid: &str) -> bool {
        let before = self.wifi_ssids.len();
        self.wifi_ssids
            .retain(|s| !s.eq_ignore_ascii_case(ssid.trim()));
        self.wifi_ssids.len() != before
    }

    pub fn has_ssid(&self, ssid: &str) -> bool {
        self.wifi_ssids
            .iter()
            .any(|s| s.eq_ignore_ascii_case(ssid.trim()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ccp_cfg_{name}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn parses_credentials_and_rejects_incomplete() {
        let c = parse_credentials("  alice \n  s3cret pass \n").unwrap();
        assert_eq!(c.username, "alice");
        assert_eq!(c.password, "s3cret pass");
        assert!(parse_credentials("alice\n").is_none());
        assert!(parse_credentials("\nsecret\n").is_none());
        assert!(parse_credentials("alice\n   \n").is_none());
        assert!(parse_credentials("").is_none());
        // Windows line endings
        assert_eq!(parse_credentials("a\r\nb\r\n").unwrap().password, "b");
    }

    #[test]
    fn debug_output_never_contains_the_password() {
        let c = Credentials {
            username: "alice".into(),
            password: "hunter2".into(),
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("alice"));
        assert!(!dbg.contains("hunter2"));
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tmp("roundtrip");
        save_credentials(&dir, "bob", "pa&ss=1").unwrap();
        let c = load_credentials(&dir).unwrap();
        assert_eq!(
            (c.username.as_str(), c.password.as_str()),
            ("bob", "pa&ss=1")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_credentials_is_a_helpful_error() {
        let dir = tmp("missing");
        let err = load_credentials(&dir).unwrap_err();
        assert!(err.contains("ccp set"));
    }

    #[cfg(unix)]
    #[test]
    fn credentials_are_private_even_when_replacing_a_loose_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("perms");
        fs::create_dir_all(&dir).unwrap();
        let path = credentials_path(&dir);
        fs::write(&path, "old\nold\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        save_credentials(&dir, "new", "new").unwrap();

        let file_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let dir_mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(dir_mode, 0o700);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn loading_tightens_a_world_readable_credentials_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("selfheal");
        fs::create_dir_all(&dir).unwrap();
        let path = credentials_path(&dir);
        fs::write(&path, "alice\nhunter2\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(load_credentials(&dir).is_ok());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn settings_round_trip_and_ssid_management() {
        let dir = tmp("settings");
        let mut s = Settings::load(&dir);
        assert!(s.wifi_ssids.is_empty());

        assert!(s.add_ssid("Campus-WiFi"));
        assert!(!s.add_ssid("campus-wifi"), "case-insensitive duplicate");
        assert!(!s.add_ssid("   "));
        s.save(&dir).unwrap();

        let mut loaded = Settings::load(&dir);
        assert_eq!(loaded, s);
        assert!(loaded.has_ssid("CAMPUS-WIFI"));
        assert!(loaded.remove_ssid("campus-wifi"));
        assert!(!loaded.remove_ssid("campus-wifi"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn settings_tolerate_garbage_and_unknown_fields() {
        let dir = tmp("settings_garbage");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(SETTINGS_FILE), "{ not json").unwrap();
        assert_eq!(Settings::load(&dir), Settings::default());
        fs::write(dir.join(SETTINGS_FILE), r#"{"future_field": 1}"#).unwrap();
        assert_eq!(Settings::load(&dir), Settings::default());
        let _ = fs::remove_dir_all(&dir);
    }
}
