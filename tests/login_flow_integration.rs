//! End-to-end tests of the login flow against a mock captive portal:
//! verification, the circuit breaker, and the trusted-gateway guard.

mod common;

use ccp::daemon::{backoff_secs, run_daemon};
use ccp::probe::{
    LoginError, build_fast_client, build_login_client, login_and_verify, wait_until_unlocked,
};
use ccp::state::DaemonState;
use ccp::trust::TrustStore;
use common::*;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

// run_daemon reads CCP_PROBE_URL from the process environment.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn with_probe_url<T>(url: &str, f: impl FnOnce() -> T) -> T {
    unsafe { std::env::set_var("CCP_PROBE_URL", url) };
    let out = f();
    unsafe { std::env::remove_var("CCP_PROBE_URL") };
    out
}

/// A portal whose internet only opens after a successful login POST.
fn portal_that_unlocks_after_login() -> (MockPortal, Arc<AtomicBool>) {
    let logged_in = Arc::new(AtomicBool::new(false));
    let flag = logged_in.clone();
    let portal = MockPortal::start(move |req, port| {
        if req.starts_with("POST") {
            flag.store(true, Ordering::SeqCst);
            http("200 OK", "Content-Type: text/xml\r\n", SOPHOS_LIVE)
        } else if flag.load(Ordering::SeqCst) {
            internet_ok()
        } else {
            redirect_to_portal(port)
        }
    });
    (portal, logged_in)
}

/// A portal that says "logged in" but never actually opens the internet.
fn portal_that_lies() -> MockPortal {
    MockPortal::start(|req, port| {
        if req.starts_with("POST") {
            http("200 OK", "Content-Type: text/xml\r\n", SOPHOS_LIVE)
        } else {
            redirect_to_portal(port)
        }
    })
}

#[test]
fn login_is_only_a_success_when_the_internet_really_opens() {
    let (portal, _) = portal_that_unlocks_after_login();
    let url = format!("http://127.0.0.1:{}/httpclient.html", portal.port);
    let probe_client = build_fast_client(false).unwrap();
    let login_client = build_login_client().unwrap();

    let _g = ENV_LOCK.lock().unwrap();
    let result = with_probe_url(&portal.probe_url(), || {
        login_and_verify(
            &login_client,
            &probe_client,
            &format!("{url}?:8090"),
            "u",
            "p",
        )
    });
    // Not :8090 -> generic form login at that exact URL; the mock accepts any POST.
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(portal.count("POST"), 1);
}

#[test]
fn a_portal_that_says_ok_but_stays_locked_is_reported_as_still_locked() {
    let portal = portal_that_lies();
    let url = format!("http://127.0.0.1:{}/httpclient.html", portal.port);
    let probe_client = build_fast_client(false).unwrap();
    let login_client = build_login_client().unwrap();

    let _g = ENV_LOCK.lock().unwrap();
    let result = with_probe_url(&portal.probe_url(), || {
        login_and_verify(&login_client, &probe_client, &url, "u", "p")
    });
    assert_eq!(result, Err(LoginError::StillLocked));
}

#[test]
fn bad_credentials_are_a_distinct_error_and_never_verified() {
    let portal = MockPortal::start(|_, _| http("200 OK", "", SOPHOS_BAD_PASSWORD));
    let url = format!("http://127.0.0.1:{}/login.xml", portal.port);
    let probe_client = build_fast_client(false).unwrap();
    let login_client = build_login_client().unwrap();

    let result = login_and_verify(&login_client, &probe_client, &url, "u", "wrong");
    assert!(
        matches!(result, Err(LoginError::BadCredentials(_))),
        "{result:?}"
    );
    assert_eq!(portal.count("GET"), 0, "must not probe after a rejection");
}

#[test]
fn a_dead_portal_is_a_network_error_not_a_credential_error() {
    // Nothing is listening here.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let probe_client = build_fast_client(false).unwrap();
    let login_client = build_login_client().unwrap();
    let url = format!("http://127.0.0.1:{port}/login.xml");
    let result = login_and_verify(&login_client, &probe_client, &url, "u", "p");
    assert!(matches!(result, Err(LoginError::Network(_))), "{result:?}");
}

#[test]
fn wait_until_unlocked_tolerates_a_slow_portal() {
    // Locked for the first two probes, open on the third.
    let hits = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let h = hits.clone();
    let portal = MockPortal::start(move |_, port| {
        if h.fetch_add(1, Ordering::SeqCst) < 2 {
            redirect_to_portal(port)
        } else {
            internet_ok()
        }
    });
    let client = build_fast_client(false).unwrap();
    assert!(wait_until_unlocked(
        &client,
        &portal.probe_url(),
        5,
        Duration::from_millis(20)
    ));
}

#[test]
fn daemon_logs_in_verifies_and_counts_one_login() {
    let (portal, _) = portal_that_unlocks_after_login();
    let dir = tmp_dir("daemon_ok");
    TrustStore::open(&dir).add("127.0.0.1").unwrap();

    let _g = ENV_LOCK.lock().unwrap();
    let res = with_probe_url(&portal.probe_url(), || {
        run_daemon(&dir, "user", "pass", true, false)
    });
    assert!(res.is_ok(), "{res:?}");

    let state = DaemonState::load(&dir.join("state.json"));
    assert_eq!(state.total_logins, 1);
    assert_eq!(state.failure_streak, 0);
    assert!(!state.halted_bad_credentials);
    assert!(state.last_status_message.starts_with("Authenticated"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn daemon_does_not_count_a_login_that_did_not_open_the_internet() {
    let portal = portal_that_lies();
    let dir = tmp_dir("daemon_lies");
    TrustStore::open(&dir).add("127.0.0.1").unwrap();

    let _g = ENV_LOCK.lock().unwrap();
    let res = with_probe_url(&portal.probe_url(), || {
        run_daemon(&dir, "user", "pass", true, false)
    });
    assert!(res.is_ok());

    let state = DaemonState::load(&dir.join("state.json"));
    assert_eq!(state.total_logins, 0, "an unverified login must not count");
    assert_eq!(state.failure_streak, 1);
    assert!(!state.halted_bad_credentials, "one miss is not yet a halt");
    assert!(state.last_status_message.contains("still locked"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn daemon_halts_instead_of_resubmitting_forever_when_login_never_sticks() {
    let portal = portal_that_lies();
    let dir = tmp_dir("daemon_halts");
    TrustStore::open(&dir).add("127.0.0.1").unwrap();
    let state_path = dir.join("state.json");

    let _g = ENV_LOCK.lock().unwrap();
    let pass = |n: u32| {
        with_probe_url(&portal.probe_url(), || {
            run_daemon(&dir, "user", "pass", true, false)
                .unwrap_or_else(|e| panic!("pass {n}: {e}"))
        });
        DaemonState::load(&state_path)
    };

    // The streak is persisted, so it survives daemon restarts (each pass here is a
    // fresh process-equivalent: once=true starts from disk state only).
    let s1 = pass(1);
    assert_eq!(s1.still_locked_streak, 1);
    assert!(!s1.halted_bad_credentials);
    let s2 = pass(2);
    assert_eq!(s2.still_locked_streak, 2);
    assert!(!s2.halted_bad_credentials);
    let s3 = pass(3);
    assert_eq!(s3.still_locked_streak, 3);
    assert!(
        s3.halted_bad_credentials,
        "third unverified login must halt"
    );
    assert!(s3.last_status_message.contains("Halted"));
    assert_eq!(s3.total_logins, 0);

    // Once halted, further passes must not touch the portal at all.
    let posts_before = portal.count("POST");
    let s4 = pass(4);
    assert!(s4.halted_bad_credentials);
    assert_eq!(
        portal.count("POST"),
        posts_before,
        "no more attempts while halted"
    );
    assert_eq!(posts_before, 3);

    // `ccp set` (reset) resumes it.
    DaemonState::reset_circuit_breaker(&state_path);
    let after_reset = DaemonState::load(&state_path);
    assert!(!after_reset.halted_bad_credentials);
    assert_eq!(after_reset.still_locked_streak, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn untrusted_portal_never_receives_credentials() {
    let (portal, _) = portal_that_unlocks_after_login();
    let dir = tmp_dir("daemon_untrusted"); // trust list is empty on purpose

    let _g = ENV_LOCK.lock().unwrap();
    let res = with_probe_url(&portal.probe_url(), || {
        run_daemon(&dir, "user", "hunter2", true, false)
    });
    assert!(res.is_ok());

    assert_eq!(portal.count("POST"), 0, "credentials must not be sent");
    let state = DaemonState::load(&dir.join("state.json"));
    assert_eq!(
        state.pending_untrusted_gateway.as_deref(),
        Some("127.0.0.1")
    );
    assert_eq!(state.total_logins, 0);
    assert!(
        !state.halted_bad_credentials,
        "blocking is not a credential failure"
    );
    assert!(state.last_status_message.contains("ccp trust 127.0.0.1"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn trusting_the_blocked_portal_lets_the_next_pass_log_in() {
    let (portal, _) = portal_that_unlocks_after_login();
    let dir = tmp_dir("daemon_trust_then_login");

    let _g = ENV_LOCK.lock().unwrap();
    with_probe_url(&portal.probe_url(), || {
        run_daemon(&dir, "user", "pass", true, false).unwrap()
    });
    assert_eq!(portal.count("POST"), 0);

    TrustStore::open(&dir).add("127.0.0.1").unwrap(); // what `ccp trust` does

    with_probe_url(&portal.probe_url(), || {
        run_daemon(&dir, "user", "pass", true, false).unwrap()
    });
    assert_eq!(portal.count("POST"), 1);
    let state = DaemonState::load(&dir.join("state.json"));
    assert_eq!(state.total_logins, 1);
    assert_eq!(
        state.pending_untrusted_gateway, None,
        "cleared after a successful login"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn backoff_schedule_is_exponential_and_capped() {
    let schedule: Vec<u64> = (0..9).map(backoff_secs).collect();
    assert_eq!(schedule, vec![5, 5, 10, 20, 40, 80, 160, 300, 300]);
}
