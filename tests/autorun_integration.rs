use ccp::daemon::run_daemon;
use ccp::instance::{acquire, is_daemon_running};
use ccp::state::DaemonState;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Mutex;

static TEST_MUTEX: Mutex<()> = Mutex::new(());

fn read_full_http_request(stream: &mut std::net::TcpStream) -> String {
    let mut data = Vec::new();
    let mut buf = [0u8; 1024];

    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                data.extend_from_slice(&buf[..n]);
                if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&data[..pos]);
                    let mut content_length = 0;
                    for line in headers.lines() {
                        if line.to_lowercase().starts_with("content-length:")
                            && let Some(val) = line.split(':').nth(1)
                        {
                            content_length = val.trim().parse::<usize>().unwrap_or(0);
                        }
                    }
                    let body_len = data.len() - (pos + 4);
                    if body_len >= content_length {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }

    String::from_utf8_lossy(&data).to_string()
}

#[test]
fn test_integration_instance_lock_mutual_exclusion() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let tmp_dir = std::env::temp_dir().join(format!("ccp_test_int_lock_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let lock_file = tmp_dir.join("daemon.lock");

    let _ = std::fs::remove_file(&lock_file);
    assert!(!is_daemon_running(&lock_file));

    let lock1 = acquire(&lock_file).expect("Failed to acquire lock1");
    assert!(is_daemon_running(&lock_file));

    let lock2 = acquire(&lock_file);
    assert!(lock2.is_err(), "Second acquire should fail");

    drop(lock1);
    assert!(!is_daemon_running(&lock_file));

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_integration_state_atomic_and_circuit_breaker() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let tmp_dir = std::env::temp_dir().join(format!("ccp_test_int_state_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let state_file = tmp_dir.join("state.json");

    let state = DaemonState {
        pid: 9999,
        last_probe_epoch: 500,
        last_login_epoch: 400,
        active_gateway: Some("http://10.1.1.9:8090/login.xml".to_string()),
        last_local_ip: Some("10.1.1.50".to_string()),
        failure_streak: 4,
        still_locked_streak: 0,
        halted_bad_credentials: true,
        last_status_message: "Halted (bad credentials)".to_string(),
        total_logins: 12,
        pending_untrusted_gateway: None,
    };

    assert!(state.save_atomic(&state_file).is_ok());

    let loaded = DaemonState::load(&state_file);
    assert_eq!(loaded.pid, 9999);
    assert!(loaded.halted_bad_credentials);
    assert_eq!(loaded.failure_streak, 4);

    DaemonState::reset_circuit_breaker(&state_file);
    let after_reset = DaemonState::load(&state_file);
    assert!(!after_reset.halted_bad_credentials);
    assert_eq!(after_reset.failure_streak, 0);

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_integration_daemon_once_dry_run() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let tmp_dir = std::env::temp_dir().join(format!("ccp_test_int_daemon_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);

    // Run daemon in once & dry_run mode
    let res = run_daemon(&tmp_dir, "testuser", "testpassword", true, true);
    assert!(res.is_ok(), "daemon once dry_run should succeed: {:?}", res);

    let state = DaemonState::load(&tmp_dir.join("state.json"));
    assert_eq!(state.pid, std::process::id());

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_integration_daemon_circuit_breaker_on_bad_password() {
    let _guard = TEST_MUTEX.lock().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind mock server");
    let port = listener.local_addr().unwrap().port();
    let probe_url_str = format!("http://127.0.0.1:{port}/probe");

    let handle = std::thread::spawn(move || {
        // Step 1: Probe request -> 302 Found redirect to /login.xml
        if let Ok((mut stream1, _)) = listener.accept() {
            let _ = read_full_http_request(&mut stream1);
            let redirect_response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/httpclient.html\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream1.write_all(redirect_response.as_bytes());
            let _ = stream1.flush();
        }

        // Step 2: Accept POST /login.xml and reply with Sophos failure XML
        if let Ok((mut stream2, _)) = listener.accept() {
            let _ = read_full_http_request(&mut stream2);
            let xml_body = "<requestresponse><status><![CDATA[FAIL]]></status><message><![CDATA[Make sure your password is correct]]></message></requestresponse>";
            let login_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                xml_body.len(),
                xml_body
            );
            let _ = stream2.write_all(login_response.as_bytes());
            let _ = stream2.flush();
        }
    });

    let tmp_dir =
        std::env::temp_dir().join(format!("ccp_test_circuit_breaker_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    // Credentials may only go to trusted portals; the mock portal listens on 127.0.0.1.
    ccp::trust::TrustStore::open(&tmp_dir)
        .add("127.0.0.1")
        .unwrap();

    unsafe {
        std::env::set_var("CCP_PROBE_URL", &probe_url_str);
    }
    let res = run_daemon(&tmp_dir, "testuser", "badpass", true, false);
    unsafe {
        std::env::remove_var("CCP_PROBE_URL");
    }

    assert!(
        res.is_ok(),
        "run_daemon should succeed cleanly on once=true: {:?}",
        res
    );
    handle.join().unwrap();

    let state_file = tmp_dir.join("state.json");
    let state = DaemonState::load(&state_file);
    assert!(
        state.halted_bad_credentials,
        "Circuit breaker should be halted on bad credentials"
    );
    assert_eq!(state.failure_streak, 1);

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_integration_lock_file_readable_while_held() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let tmp_dir =
        std::env::temp_dir().join(format!("ccp_test_int_readlock_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let lock_file = tmp_dir.join("daemon.lock");

    let _ = std::fs::remove_file(&lock_file);
    assert!(!is_daemon_running(&lock_file));

    let lock = acquire(&lock_file).expect("Failed to acquire lock");
    assert!(is_daemon_running(&lock_file));

    // Under Windows share_mode(1) and Unix, readers can open and read the file while the lock is held
    let read_result = std::fs::read_to_string(&lock_file);
    assert!(
        read_result.is_ok(),
        "Lock file must be readable while held: {:?}",
        read_result
    );
    let content = read_result.unwrap();
    let pid: u32 = content
        .trim()
        .parse()
        .expect("Lock file must contain valid PID");
    assert_eq!(pid, std::process::id());

    drop(lock);
    assert!(!is_daemon_running(&lock_file));

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_integration_daemon_live_credential_reload() {
    let _guard = TEST_MUTEX.lock().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind mock server");
    let port = listener.local_addr().unwrap().port();
    let probe_url_str = format!("http://127.0.0.1:{port}/probe");

    let handle = std::thread::spawn(move || {
        // Step 1: Probe request -> 302 Found redirect
        if let Ok((mut stream1, _)) = listener.accept() {
            let _ = read_full_http_request(&mut stream1);
            let redirect_response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/httpclient.html\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream1.write_all(redirect_response.as_bytes());
            let _ = stream1.flush();
        }

        // Step 2: Accept POST /login.xml and verify reloaded credentials were used
        if let Ok((mut stream2, _)) = listener.accept() {
            let req_str = read_full_http_request(&mut stream2);
            assert!(
                req_str.contains("fresh_user") && req_str.contains("fresh_pass"),
                "Daemon must use live reloaded credentials from credentials.txt: {}",
                req_str
            );

            let xml_body = "<requestresponse><status><![CDATA[LIVE]]></status><message><![CDATA[You have successfully logged in]]></message></requestresponse>";
            let login_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                xml_body.len(),
                xml_body
            );
            let _ = stream2.write_all(login_response.as_bytes());
            let _ = stream2.flush();
        }

        // Step 3: after a "successful" login the daemon re-probes to prove the internet is up
        if let Ok((mut stream3, _)) = listener.accept() {
            let _ = read_full_http_request(&mut stream3);
            let _ = stream3.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nsuccess\n",
            );
            let _ = stream3.flush();
        }
    });

    let tmp_dir = std::env::temp_dir().join(format!("ccp_test_live_creds_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    // Credentials may only go to trusted portals; the mock portal listens on 127.0.0.1.
    ccp::trust::TrustStore::open(&tmp_dir)
        .add("127.0.0.1")
        .unwrap();

    // Write updated credentials.txt to config_dir
    let creds_path = tmp_dir.join("credentials.txt");
    std::fs::write(&creds_path, "fresh_user\nfresh_pass\n").unwrap();

    unsafe {
        std::env::set_var("CCP_PROBE_URL", &probe_url_str);
    }
    // Pass old credentials into run_daemon, verify it picks up fresh credentials from credentials.txt
    let res = run_daemon(&tmp_dir, "stale_user", "stale_pass", true, false);
    unsafe {
        std::env::remove_var("CCP_PROBE_URL");
    }

    assert!(res.is_ok(), "run_daemon should succeed: {:?}", res);
    handle.join().unwrap();

    let state = DaemonState::load(&tmp_dir.join("state.json"));
    assert_eq!(state.failure_streak, 0);
    assert_eq!(state.total_logins, 1);
    assert!(!state.halted_bad_credentials);

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_integration_daemon_expanded_circuit_breaker_keywords() {
    let _guard = TEST_MUTEX.lock().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind mock server");
    let port = listener.local_addr().unwrap().port();
    let probe_url_str = format!("http://127.0.0.1:{port}/probe");

    let handle = std::thread::spawn(move || {
        // Step 1: Probe request -> 302 Found redirect
        if let Ok((mut stream1, _)) = listener.accept() {
            let _ = read_full_http_request(&mut stream1);
            let redirect_response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/httpclient.html\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream1.write_all(redirect_response.as_bytes());
            let _ = stream1.flush();
        }

        // Step 2: Sophos failure XML with "Account expired"
        if let Ok((mut stream2, _)) = listener.accept() {
            let _ = read_full_http_request(&mut stream2);
            let xml_body = "<requestresponse><status><![CDATA[FAIL]]></status><message><![CDATA[Your account expired on 2026-11-01]]></message></requestresponse>";
            let login_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                xml_body.len(),
                xml_body
            );
            let _ = stream2.write_all(login_response.as_bytes());
            let _ = stream2.flush();
        }
    });

    let tmp_dir = std::env::temp_dir().join(format!("ccp_test_exp_breaker_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    // Credentials may only go to trusted portals; the mock portal listens on 127.0.0.1.
    ccp::trust::TrustStore::open(&tmp_dir)
        .add("127.0.0.1")
        .unwrap();

    unsafe {
        std::env::set_var("CCP_PROBE_URL", &probe_url_str);
    }
    let res = run_daemon(&tmp_dir, "testuser", "pass", true, false);
    unsafe {
        std::env::remove_var("CCP_PROBE_URL");
    }

    assert!(
        res.is_ok(),
        "run_daemon should succeed cleanly on once=true"
    );
    handle.join().unwrap();

    let state = DaemonState::load(&tmp_dir.join("state.json"));
    assert!(
        state.halted_bad_credentials,
        "Circuit breaker should halt on 'account expired'"
    );
    assert_eq!(state.failure_streak, 1);

    let _ = std::fs::remove_dir_all(&tmp_dir);
}
