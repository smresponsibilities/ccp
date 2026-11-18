#![allow(dead_code)] // each integration-test crate uses a different subset

//! A small multi-request HTTP server that plays the part of a campus captive portal.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

pub fn read_http_request(stream: &mut TcpStream) -> String {
    let mut data = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                data.extend_from_slice(&buf[..n]);
                if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&data[..pos]).to_lowercase();
                    let content_length = headers
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if data.len() - (pos + 4) >= content_length {
                        break;
                    }
                }
            }
        }
    }
    String::from_utf8_lossy(&data).to_string()
}

pub fn http(status: &str, extra_headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

pub struct MockPortal {
    pub port: u16,
    /// First line of every request received ("GET /probe HTTP/1.1", "POST /login.xml ...").
    pub requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl MockPortal {
    /// `handler(full_request_text, port)` returns the raw HTTP response.
    pub fn start<F>(handler: F) -> Self
    where
        F: Fn(&str, u16) -> String + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock portal");
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));

        let (stop2, requests2) = (stop.clone(), requests.clone());
        let handle = std::thread::spawn(move || {
            for conn in listener.incoming() {
                if stop2.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut stream) = conn else { continue };
                let req = read_http_request(&mut stream);
                requests2
                    .lock()
                    .unwrap()
                    .push(req.lines().next().unwrap_or("").to_string());
                let resp = handler(&req, port);
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });

        Self {
            port,
            requests,
            stop,
            handle: Some(handle),
        }
    }

    pub fn probe_url(&self) -> String {
        format!("http://127.0.0.1:{}/probe", self.port)
    }

    pub fn count(&self, prefix: &str) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.starts_with(prefix))
            .count()
    }
}

impl Drop for MockPortal {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port)); // wake the accept loop
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

pub const SOPHOS_LIVE: &str = "<requestresponse><status><![CDATA[LIVE]]></status><message><![CDATA[You have successfully logged in]]></message></requestresponse>";
pub const SOPHOS_BAD_PASSWORD: &str = "<requestresponse><status><![CDATA[FAIL]]></status><message><![CDATA[Make sure your password is correct]]></message></requestresponse>";

pub fn redirect_to_portal(port: u16) -> String {
    http(
        "302 Found",
        &format!("Location: http://127.0.0.1:{port}/httpclient.html\r\n"),
        "",
    )
}

pub fn internet_ok() -> String {
    http("200 OK", "", "success\n")
}

pub fn tmp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ccp_it_{name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
