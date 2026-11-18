//! Wi-Fi helpers.
//!
//! `ccp` only ever (re)connects to networks the user explicitly allowed with
//! `ccp wifi add <SSID>`. It never turns the Wi-Fi radio on, never joins a network you
//! didn't list, and does nothing at all when the list is empty.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// Polls for a valid local IPv4 route every `poll_interval` until `timeout` expires
pub fn wait_for_ipv4(timeout: Duration, poll_interval: Duration) -> Option<Ipv4Addr> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Some(ip) = crate::probe::current_local_ipv4() {
            return Some(ip);
        }
        std::thread::sleep(poll_interval);
    }
    None
}

// ---------------------------------------------------------------------------
// Pure parsing / selection (platform independent, unit-tested everywhere)
// ---------------------------------------------------------------------------

/// Profile names from `netsh wlan show profiles`.
pub fn parse_wlan_profiles(profiles_output: &str) -> Vec<String> {
    let mut profiles = Vec::new();
    let mut in_profiles_section = false;

    for line in profiles_output.lines() {
        if line.trim().contains("----") {
            in_profiles_section = true;
            continue;
        }

        if let Some(idx) = line.find(':') {
            let left = line[..idx].trim().to_lowercase();
            let right = line[idx + 1..].trim();
            let usable = !right.is_empty() && !right.eq_ignore_ascii_case("<none>");

            if usable
                && (in_profiles_section || left.contains("profile") || left.contains("profil"))
            {
                profiles.push(right.to_string());
            }
        }
    }
    profiles
}

/// SSIDs from `netsh wlan show networks`.
pub fn parse_visible_ssids(networks_output: &str) -> Vec<String> {
    networks_output
        .lines()
        .filter_map(|line| {
            let idx = line.find(':')?;
            let left = line[..idx].trim().to_lowercase();
            let right = line[idx + 1..].trim();
            (left.starts_with("ssid") && !right.is_empty()).then(|| right.to_string())
        })
        .collect()
}

/// Chooses the saved profile to connect to: only SSIDs in `allowed`, in the order the
/// user listed them, and (when a scan is available) only ones currently in range.
pub fn pick_allowed_profile(
    profiles_output: &str,
    networks_output: Option<&str>,
    allowed: &[String],
) -> Option<String> {
    let profiles = parse_wlan_profiles(profiles_output);
    let visible = networks_output.map(parse_visible_ssids);

    allowed.iter().find_map(|wanted| {
        let profile = profiles
            .iter()
            .find(|p| p.eq_ignore_ascii_case(wanted.trim()))?;
        match &visible {
            Some(v) if !v.iter().any(|s| s.eq_ignore_ascii_case(profile)) => None,
            _ => Some(profile.clone()),
        }
    })
}

// ---------------------------------------------------------------------------
// Platform glue. Returns `true` if a connect command reported success.
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[cfg(target_os = "windows")]
pub fn connect_allowed(ssids: &[String]) -> bool {
    use std::process::Command;

    if ssids.is_empty() {
        return false;
    }

    let Ok(profiles_output) = Command::new("netsh")
        .args(["wlan", "show", "profiles"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    else {
        return false;
    };
    let profiles_stdout = String::from_utf8_lossy(&profiles_output.stdout).to_string();

    let networks_stdout = Command::new("netsh")
        .args(["wlan", "show", "networks"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string());

    let Some(profile) = pick_allowed_profile(&profiles_stdout, networks_stdout.as_deref(), ssids)
    else {
        return false;
    };

    Command::new("netsh")
        .args(["wlan", "connect", &format!("name={profile}")])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
pub fn connect_allowed(ssids: &[String]) -> bool {
    use std::process::Command;

    ssids.iter().any(|ssid| {
        Command::new("nmcli")
            .args(["-w", "10", "dev", "wifi", "connect", ssid.as_str()])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

#[cfg(target_os = "macos")]
fn get_macos_wifi_device() -> String {
    use std::process::Command;
    if let Ok(output) = Command::new("networksetup")
        .arg("-listallhardwareports")
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut found_wifi = false;
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.contains("Wi-Fi") || trimmed.contains("AirPort") {
                found_wifi = true;
            } else if found_wifi
                && trimmed.starts_with("Device:")
                && let Some(dev) = trimmed.split(':').nth(1)
            {
                let dev = dev.trim();
                if !dev.is_empty() {
                    return dev.to_string();
                }
            }
        }
    }
    "en0".to_string()
}

#[cfg(target_os = "macos")]
pub fn connect_allowed(ssids: &[String]) -> bool {
    use std::process::Command;

    let dev = get_macos_wifi_device();
    ssids.iter().any(|ssid| {
        Command::new("networksetup")
            .args(["-setairportnetwork", dev.as_str(), ssid.as_str()])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
pub fn connect_allowed(_ssids: &[String]) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILES: &str = "
Profiles on interface Wi-Fi:

Group policy profiles (read only)
---------------------------------
    <None>

User profiles
-------------
    All User Profile     : Guest_WiFi
    All User Profile     : Campus_Hostel_Net
    All User Profile     : College_Classroom_WiFi
    All User Profile     : Home_Network
";

    const NETWORKS_AT_COLLEGE: &str = "
Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : College_Classroom_WiFi
    Network type            : Infrastructure
SSID 2 : Random_Cafe
    Network type            : Infrastructure
";

    fn allowed(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_profiles_and_skips_none_placeholder() {
        let p = parse_wlan_profiles(PROFILES);
        assert_eq!(
            p,
            vec![
                "Guest_WiFi",
                "Campus_Hostel_Net",
                "College_Classroom_WiFi",
                "Home_Network"
            ]
        );
    }

    #[test]
    fn parses_visible_ssids() {
        assert_eq!(
            parse_visible_ssids(NETWORKS_AT_COLLEGE),
            vec!["College_Classroom_WiFi", "Random_Cafe"]
        );
    }

    #[test]
    fn only_picks_allowed_networks_that_are_in_range() {
        let allow = allowed(&["Campus_Hostel_Net", "College_Classroom_WiFi"]);
        // At college the hostel network is out of range -> the classroom one is chosen.
        assert_eq!(
            pick_allowed_profile(PROFILES, Some(NETWORKS_AT_COLLEGE), &allow).as_deref(),
            Some("College_Classroom_WiFi")
        );
    }

    #[test]
    fn never_picks_a_network_the_user_did_not_allow() {
        // "Guest_WiFi" and "Home_Network" match old keyword heuristics ("wifi"), but
        // were never allowed, so nothing is chosen.
        let allow = allowed(&["Some_Other_SSID"]);
        assert_eq!(
            pick_allowed_profile(PROFILES, Some(NETWORKS_AT_COLLEGE), &allow),
            None
        );
        assert_eq!(pick_allowed_profile(PROFILES, None, &[]), None);
    }

    #[test]
    fn does_not_connect_blindly_when_nothing_allowed_is_in_range() {
        let allow = allowed(&["Campus_Hostel_Net"]);
        assert_eq!(
            pick_allowed_profile(PROFILES, Some(NETWORKS_AT_COLLEGE), &allow),
            None
        );
    }

    #[test]
    fn falls_back_to_the_saved_profile_when_scan_is_unavailable() {
        let allow = allowed(&["campus_hostel_net"]);
        assert_eq!(
            pick_allowed_profile(PROFILES, None, &allow).as_deref(),
            Some("Campus_Hostel_Net"),
            "case-insensitive match, original casing returned"
        );
    }

    #[test]
    fn respects_the_order_the_user_listed_networks_in() {
        let networks = "SSID 1 : Campus_Hostel_Net\nSSID 2 : College_Classroom_WiFi\n";
        let allow = allowed(&["College_Classroom_WiFi", "Campus_Hostel_Net"]);
        assert_eq!(
            pick_allowed_profile(PROFILES, Some(networks), &allow).as_deref(),
            Some("College_Classroom_WiFi")
        );
    }
}
