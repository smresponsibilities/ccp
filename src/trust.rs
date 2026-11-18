//! Trusted portal gateways.
//!
//! `ccp` discovers the login page from whatever redirect the network hands it. Without
//! a safeguard, any private-IP captive portal (a café, an airport, an evil-twin AP)
//! would receive your campus username and password. So credentials are only ever sent
//! to hosts listed in `trusted_gateways.txt`.
//!
//! * Existing installs are migrated: the gateway you last logged into is trusted.
//! * `ccp` (interactive) asks once per new portal; the daemon never asks, it records
//!   the blocked host so `ccp status` / `ccp trust` can show and approve it.
//! * `CCP_TRUST_ANY=1` restores the old send-to-anything behaviour (not recommended).

use crate::config;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const TRUST_FILE: &str = "trusted_gateways.txt";
const CACHED_GATEWAY_FILE: &str = "cached_gateway.txt";

/// Extracts the lowercase host from a URL, `host:port` or bare host.
pub fn host_of(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    let parsed = url::Url::parse(&with_scheme).ok()?;
    parsed.host_str().map(|h| h.to_lowercase())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Trusted,
    Untrusted { host: String },
}

pub struct TrustStore {
    path: PathBuf,
}

impl TrustStore {
    /// Opens the store for `config_dir`, seeding it from the previously used gateway
    /// (`cached_gateway.txt`) the first time, so upgrades keep working.
    pub fn open(config_dir: &Path) -> Self {
        let store = Self {
            path: config_dir.join(TRUST_FILE),
        };
        if !store.path.exists()
            && let Ok(cached) = fs::read_to_string(config_dir.join(CACHED_GATEWAY_FILE))
            && let Some(host) = host_of(&cached)
        {
            let _ = store.add(&host);
        }
        store
    }

    pub fn hosts(&self) -> Vec<String> {
        fs::read_to_string(&self.path)
            .unwrap_or_default()
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_lowercase)
            .collect()
    }

    pub fn is_trusted(&self, host: &str) -> bool {
        let host = host.trim().to_lowercase();
        self.hosts().contains(&host)
    }

    /// Returns `true` if the host was newly added.
    pub fn add(&self, input: &str) -> io::Result<bool> {
        let host = host_of(input)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not a valid host"))?;
        let mut hosts = self.hosts();
        if hosts.contains(&host) {
            return Ok(false);
        }
        hosts.push(host);
        self.write(&hosts)?;
        Ok(true)
    }

    /// Returns `true` if the host was present.
    pub fn remove(&self, input: &str) -> io::Result<bool> {
        let Some(host) = host_of(input) else {
            return Ok(false);
        };
        let hosts = self.hosts();
        let kept: Vec<String> = hosts.iter().filter(|h| **h != host).cloned().collect();
        if kept.len() == hosts.len() {
            return Ok(false);
        }
        self.write(&kept)?;
        Ok(true)
    }

    fn write(&self, hosts: &[String]) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            config::create_private_dir(parent)?;
        }
        let mut body =
            String::from("# Hosts that may receive your campus credentials (one per line)\n");
        for h in hosts {
            body.push_str(h);
            body.push('\n');
        }
        config::write_private(&self.path, body.as_bytes())
    }
}

/// Decides whether credentials may be sent to `login_url`.
pub fn check(config_dir: &Path, login_url: &str) -> Verdict {
    if std::env::var("CCP_TRUST_ANY").is_ok_and(|v| v == "1") {
        return Verdict::Trusted;
    }
    let Some(host) = host_of(login_url) else {
        // Unparseable target: never send credentials to something we can't identify.
        return Verdict::Untrusted {
            host: login_url.to_string(),
        };
    };
    if TrustStore::open(config_dir).is_trusted(&host) {
        Verdict::Trusted
    } else {
        Verdict::Untrusted { host }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ccp_trust_{name}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn host_of_handles_urls_ports_and_bare_hosts() {
        assert_eq!(
            host_of("http://172.16.68.6:8090/login.xml").as_deref(),
            Some("172.16.68.6")
        );
        assert_eq!(
            host_of("https://Portal.Campus.EDU/php/uid.php?x=1").as_deref(),
            Some("portal.campus.edu")
        );
        assert_eq!(host_of("10.1.1.9:8090").as_deref(), Some("10.1.1.9"));
        assert_eq!(host_of("10.1.1.9").as_deref(), Some("10.1.1.9"));
        assert_eq!(host_of("  "), None);
    }

    #[test]
    fn host_of_ignores_userinfo_tricks() {
        // The *real* host here is evil.example, not the trusted-looking prefix.
        assert_eq!(
            host_of("http://172.16.68.6@evil.example/login").as_deref(),
            Some("evil.example")
        );
    }

    #[test]
    fn add_list_remove_round_trip() {
        let dir = tmp("crud");
        let store = TrustStore::open(&dir);
        assert!(store.hosts().is_empty());
        assert!(store.add("http://10.1.1.9:8090/login.xml").unwrap());
        assert!(
            !store.add("10.1.1.9").unwrap(),
            "same host, different spelling"
        );
        assert!(store.add("172.16.68.6").unwrap());
        assert_eq!(store.hosts(), vec!["10.1.1.9", "172.16.68.6"]);
        assert!(store.is_trusted("10.1.1.9"));
        assert!(!store.is_trusted("10.1.1.10"));
        assert!(store.remove("10.1.1.9:80").unwrap());
        assert!(!store.remove("10.1.1.9").unwrap());
        assert_eq!(store.hosts(), vec!["172.16.68.6"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn upgrade_migrates_the_last_used_gateway() {
        let dir = tmp("migrate");
        fs::write(
            dir.join(CACHED_GATEWAY_FILE),
            "http://172.16.68.6:8090/login.xml\n",
        )
        .unwrap();
        let store = TrustStore::open(&dir);
        assert_eq!(store.hosts(), vec!["172.16.68.6"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn migration_does_not_override_an_existing_list() {
        let dir = tmp("no_migrate");
        TrustStore::open(&dir).add("10.0.0.1").unwrap();
        fs::write(dir.join(CACHED_GATEWAY_FILE), "http://192.168.50.1:8090\n").unwrap();
        assert_eq!(TrustStore::open(&dir).hosts(), vec!["10.0.0.1"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_blocks_unknown_and_allows_trusted() {
        let dir = tmp("check");
        TrustStore::open(&dir).add("172.16.68.6").unwrap();
        assert_eq!(
            check(&dir, "http://172.16.68.6:8090/login.xml"),
            Verdict::Trusted
        );
        assert_eq!(
            check(&dir, "http://10.9.9.9/php/uid.php"),
            Verdict::Untrusted {
                host: "10.9.9.9".into()
            }
        );
        assert!(matches!(
            check(&dir, "garbage url"),
            Verdict::Untrusted { .. }
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let dir = tmp("comments");
        fs::write(dir.join(TRUST_FILE), "# note\n\n  10.1.1.9  \n#10.2.2.2\n").unwrap();
        assert_eq!(TrustStore::open(&dir).hosts(), vec!["10.1.1.9"]);
        let _ = fs::remove_dir_all(&dir);
    }
}
