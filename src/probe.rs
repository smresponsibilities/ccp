use reqwest::blocking::Client;
use reqwest::header::{CACHE_CONTROL, CONNECTION, PRAGMA, USER_AGENT};
use reqwest::redirect::Policy;
use std::net::{IpAddr, Ipv4Addr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::LazyLock;
use std::time::Duration;

/// Canonical Firefox endpoint returning "success\n" (HTTP 200) when unlocked
pub const FIREFOX_SUCCESS_URL: &str = "http://detectportal.firefox.com/success.txt";
pub const FIREFOX_EXPECTED_BODY: &str = "success";
/// Fallback Google connectivity check endpoint returning HTTP 204 No Content when unlocked
pub const GSTATIC_204_URL: &str = "http://connectivitycheck.gstatic.com/generate_204";
/// Official Microsoft NCSI connectivity check endpoint returning "Microsoft Connect Test"
pub const MSFT_CONNECTTEST_URL: &str = "http://www.msftconnecttest.com/connecttest.txt";
pub const MSFT_EXPECTED_BODY: &str = "Microsoft Connect Test";

static META_REFRESH_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"(?i)<meta[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*url\s*=\s*["']?([^"'\s>]+)"#,
    )
    .unwrap()
});

static FORM_ACTION_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"(?i)<form[^>]*action\s*=\s*["']([^"']+)["']"#).unwrap());

static JS_REDIRECT_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"(?i)(?:window\.|document\.|self\.|top\.)?location(?:\.href|\s*\.\s*replace|\s*\.\s*assign)?\s*(?:=|\()\s*["']([^"']+)["']"#).unwrap()
});

static GENERAL_URL_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"https?://[a-zA-Z0-9.-]+(?::[0-9]+)?(?:/[^\s"'<>`\\]*)?"#).unwrap()
});

static XML_MESSAGE_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"(?is)<message>(?:\s*<!\[CDATA\[)?(.*?)(?:\]\]>\s*)?</message>"#).unwrap()
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    /// Internet is already unlocked ("success" received or HTTP 204)
    OnlineUnlocked,
    /// Captive portal intercepted the probe; contains dynamically discovered gateway base URL
    /// and target login URL (e.g. "/login.xml" for Sophos or preserved "/php/uid.php?..." for Palo Alto)
    LockedPortal {
        gateway_base: String,
        login_xml_url: String,
    },
    /// Wi-Fi interface has no IPv4 route or is disconnected
    InterfaceOffline,
    /// Wi-Fi is connected (has local IP) but probe timed out
    ProbeTimeoutOrError(String),
}

/// Returns the target probe URL, allowing override via `CCP_PROBE_URL`
pub fn probe_target_url() -> String {
    if let Ok(override_url) = std::env::var("CCP_PROBE_URL") {
        let trimmed = override_url.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    FIREFOX_SUCCESS_URL.to_string()
}

/// Zero-packet (<0.1ms) check for active local IPv4 route via UDP socket connect
pub fn current_local_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        // `is_link_local` already covers 169.254.0.0/16 (APIPA "no DHCP" addresses).
        IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_link_local() => Some(ip),
        _ => None,
    }
}

fn is_compatible_gateway_subnet(
    gw_ipv4: Ipv4Addr,
    local_ip: Ipv4Addr,
    port: u16,
    path: &str,
) -> bool {
    if gw_ipv4.is_loopback() || local_ip.is_loopback() {
        return true;
    }

    let gw_oct = gw_ipv4.octets();
    let loc_oct = local_ip.octets();

    let is_10 = gw_oct[0] == 10 && loc_oct[0] == 10;
    let is_172 = gw_oct[0] == 172
        && (16..=31).contains(&gw_oct[1])
        && loc_oct[0] == 172
        && (16..=31).contains(&loc_oct[1]);
    let is_192 = gw_oct[0..3] == loc_oct[0..3] && gw_oct[0..2] == [192, 168];

    if !(is_10 || is_172 || is_192) {
        return false;
    }

    if gw_oct[0..2] == [192, 168] {
        let has_portal_port = port == 8090 || port == 6082;
        let has_portal_path = path != "/" && !path.is_empty();
        if !has_portal_port && !has_portal_path {
            return false;
        }
    }

    true
}

/// Checks if a gateway host:port is reachable via a fast 400ms TCP connection check
pub fn is_gateway_reachable(gateway: &str) -> bool {
    let normalized = normalize_gateway_base(gateway);
    if let Ok(parsed) = url::Url::parse(&normalized)
        && let Some(host) = parsed.host_str()
    {
        let port = parsed
            .port()
            .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });

        // 1. Direct IP check fast-path (no DNS lookup)
        if let Ok(ip) = host.parse::<IpAddr>() {
            if let IpAddr::V4(gw_ipv4) = ip
                && let Some(local_ip) = current_local_ipv4()
                && !is_compatible_gateway_subnet(gw_ipv4, local_ip, port, parsed.path())
            {
                return false;
            }

            let sock_addr = std::net::SocketAddr::new(ip, port);
            return TcpStream::connect_timeout(&sock_addr, Duration::from_millis(400)).is_ok();
        }

        // 2. Hostname resolution with IPv4 preference
        let addr_str = format!("{}:{}", host, port);
        if let Ok(addrs) = addr_str.to_socket_addrs() {
            let mut sorted_addrs: Vec<std::net::SocketAddr> = addrs.collect();
            sorted_addrs.sort_by_key(|sa| if sa.is_ipv4() { 0 } else { 1 });
            for addr in sorted_addrs {
                if let IpAddr::V4(gw_ipv4) = addr.ip()
                    && let Some(local_ip) = current_local_ipv4()
                    && !is_compatible_gateway_subnet(gw_ipv4, local_ip, port, parsed.path())
                {
                    continue;
                }

                if TcpStream::connect_timeout(&addr, Duration::from_millis(400)).is_ok() {
                    return true;
                }
            }
        }
    }
    false
}

fn client_builder(
    follow_redirects: bool,
    connect_timeout: Duration,
    total_timeout: Duration,
) -> reqwest::blocking::ClientBuilder {
    Client::builder()
        .no_proxy() // Bypass Windows WinHTTP / WPAD proxy lag
        .local_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)) // Force IPv4 (no AAAA timeout)
        .tcp_nodelay(true)
        .pool_max_idle_per_host(0) // Matches Firefox LOAD_FRESH_CONNECTION
        // Campus portals use self-signed certificates. Credentials are only ever sent
        // to hosts in the trust list (see `trust`), which limits the exposure to an
        // on-path attacker impersonating a gateway you already trust.
        .danger_accept_invalid_certs(true)
        .redirect(if follow_redirects {
            Policy::limited(3)
        } else {
            Policy::none() // Matches Firefox redirectionLimit = 0
        })
        .connect_timeout(connect_timeout)
        .timeout(total_timeout)
}

/// Builds a zero-lag HTTP client configured identically to Firefox's URLFetcher
/// (short timeouts: this is for connectivity probes, not for logging in).
pub fn build_fast_client(follow_redirects: bool) -> Result<Client, reqwest::Error> {
    client_builder(
        follow_redirects,
        Duration::from_millis(1200),
        Duration::from_millis(2500),
    )
    .build()
}

/// Client for the login POST. Portals under load can take several seconds to answer,
/// so this is more patient than the probe client.
pub fn build_login_client() -> Result<Client, reqwest::Error> {
    client_builder(false, Duration::from_secs(3), Duration::from_secs(10)).build()
}

fn is_ignored_host(host: &str) -> bool {
    let h = host.to_lowercase();
    let ignored = [
        "detectportal.firefox.com",
        "1.1.1.1",
        "connectivitycheck.gstatic.com",
        "clients3.google.com",
        "msftconnecttest.com",
        "www.msftconnecttest.com",
        "msftncsi.com",
        "example.com",
        "w3.org",
        "www.w3.org",
        "one.one.one.one",
        "cloudflare.com",
        "mozilla.org",
        "firefox.com",
        "google.com",
        "apple.com",
        "microsoft.com",
    ];
    ignored
        .iter()
        .any(|&ig| h == ig || h.ends_with(&format!(".{ig}")))
}

fn is_private_or_local_ip(host: &str) -> bool {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        let octets = ip.octets();
        octets[0] == 10
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            || (octets[0] == 192 && octets[1] == 168)
            || ip.is_loopback()
    } else {
        false
    }
}

fn is_valid_portal_target(parsed: &url::Url) -> bool {
    let Some(host) = parsed.host_str() else {
        return false;
    };
    if is_ignored_host(host) {
        return false;
    }

    let h_lower = host.to_lowercase();
    if h_lower.ends_with(".xml")
        || h_lower.ends_with(".html")
        || h_lower.ends_with(".htm")
        || h_lower.ends_with(".php")
        || h_lower.ends_with(".jsp")
        || h_lower.ends_with(".asp")
        || h_lower.ends_with(".cgi")
    {
        return false;
    }

    if host == "localhost" || is_private_or_local_ip(host) {
        return true;
    }

    let port = parsed
        .port()
        .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
    let addr_str = format!("{}:{}", host, port);
    if let Ok(mut addrs) = addr_str.to_socket_addrs() {
        return addrs.any(|sa| match sa.ip() {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                octets[0] == 10
                    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                    || (octets[0] == 192 && octets[1] == 168)
                    || ipv4.is_loopback()
            }
            IpAddr::V6(ipv6) => ipv6.is_loopback(),
        });
    }

    false
}

fn format_gateway_base(scheme: &str, host: &str, port: Option<u16>, full_context: &str) -> String {
    if let Some(p) = port {
        format!("{scheme}://{host}:{p}")
    } else if full_context.contains(":8090") {
        format!("{scheme}://{host}:8090")
    } else {
        format!("{scheme}://{host}")
    }
}

pub fn normalize_gateway_base(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{}", trimmed)
    }
}

/// Resolves the gateway base (scheme://host[:port]) and the exact login URL.
///
/// 1. If the extracted redirect URL has a non-root path/query (e.g. Palo Alto /php/uid.php?...)
///    and does NOT end with /httpclient.html, the exact full URL is preserved as the login target.
/// 2. If the URL has no path, ends with /httpclient.html (Sophos landing page), or is a bare host:port,
///    the login target is format!("{gateway_base}/login.xml").
pub fn resolve_login_target(raw_redirect_or_html: &str) -> Option<(String, String)> {
    let text = raw_redirect_or_html.trim();
    if text.is_empty() {
        return None;
    }

    // 1. Direct URL parse attempt
    if let Ok(parsed) = url::Url::parse(text)
        && (parsed.scheme() == "http" || parsed.scheme() == "https")
        && is_valid_portal_target(&parsed)
    {
        return Some(determine_login_target(&parsed, text));
    }

    // 2. Scan for URLs inside HTML redirect/form constructs
    let mut candidates = Vec::new();

    for caps in META_REFRESH_RE.captures_iter(text) {
        if let Some(m) = caps.get(1) {
            candidates.push((120, m.as_str().to_string()));
        }
    }

    for caps in FORM_ACTION_RE.captures_iter(text) {
        if let Some(m) = caps.get(1) {
            candidates.push((110, m.as_str().to_string()));
        }
    }

    for caps in JS_REDIRECT_RE.captures_iter(text) {
        if let Some(m) = caps.get(1) {
            candidates.push((110, m.as_str().to_string()));
        }
    }

    for m in GENERAL_URL_RE.find_iter(text) {
        let raw_url = m
            .as_str()
            .trim_end_matches(&[')', ']', ';', ',', '\'', '"', '\\'][..]);
        if raw_url.contains(":8090")
            || raw_url.contains("httpclient")
            || raw_url.contains("login.xml")
            || raw_url.contains("/php/uid.php")
            || raw_url.contains("fgtauth")
        {
            candidates.push((100, raw_url.to_string()));
        }
    }

    candidates.sort_by_key(|a| std::cmp::Reverse(a.0));

    for (_, raw_cand) in candidates {
        let normalized = if raw_cand.starts_with("http://") || raw_cand.starts_with("https://") {
            raw_cand
        } else {
            if raw_cand.starts_with('/') {
                continue;
            }
            let host_part = raw_cand
                .split(&['/', ':', '?', '#'][..])
                .next()
                .unwrap_or("");
            if host_part == "localhost" || host_part.parse::<Ipv4Addr>().is_ok() {
                format!("http://{}", raw_cand)
            } else {
                continue;
            }
        };

        if let Ok(parsed) = url::Url::parse(&normalized)
            && (parsed.scheme() == "http" || parsed.scheme() == "https")
            && is_valid_portal_target(&parsed)
        {
            return Some(determine_login_target(&parsed, &normalized));
        }
    }

    // 3. Fallback: Host[:port] without scheme (e.g. "172.16.68.6:8090" or "10.1.1.9:8090/login")
    let host_part = text.split(&['/', ':', '?', '#'][..]).next().unwrap_or("");
    if host_part == "localhost" || host_part.parse::<Ipv4Addr>().is_ok() {
        let with_scheme = format!("http://{}", text);
        if let Ok(parsed) = url::Url::parse(&with_scheme)
            && (parsed.scheme() == "http" || parsed.scheme() == "https")
            && is_valid_portal_target(&parsed)
        {
            return Some(determine_login_target(&parsed, &with_scheme));
        }
    }

    None
}

fn determine_login_target(parsed: &url::Url, raw_str: &str) -> (String, String) {
    let scheme = parsed.scheme();
    let host = parsed.host_str().unwrap_or("localhost");
    let port = parsed.port();
    let gateway_base = format_gateway_base(scheme, host, port, raw_str);

    let path = parsed.path();
    let is_sophos_landing = parsed.port() == Some(8090)
        || raw_str.contains(":8090")
        || path.ends_with("/httpclient.html")
        || path == "httpclient.html"
        || path.ends_with("/login.xml");

    let login_url = if is_sophos_landing {
        format!("{}/login.xml", gateway_base.trim_end_matches('/'))
    } else {
        // For ALL non-Sophos portals (including root path http://172.16.1.1/ or /php/uid.php?...),
        // preserve the exact full redirect URL
        raw_str.to_string()
    };

    (gateway_base, login_url)
}

/// Extracts scheme://host[:port] gateway base from a URL string or an HTML body
pub fn extract_gateway_base(url_or_html: &str) -> Option<String> {
    resolve_login_target(url_or_html).map(|(base, _)| base)
}

fn resolve_fallback_gateway(fallback_gateway: Option<&str>, err_context: &str) -> ProbeResult {
    if let Some(fb) = fallback_gateway {
        if is_gateway_reachable(fb) {
            if let Some((gateway_base, login_xml_url)) = resolve_login_target(fb) {
                return ProbeResult::LockedPortal {
                    gateway_base,
                    login_xml_url,
                };
            }
        } else {
            return ProbeResult::ProbeTimeoutOrError(format!(
                "{}: cached gateway {} is unreachable on current network",
                err_context, fb
            ));
        }
    }
    ProbeResult::ProbeTimeoutOrError(err_context.to_string())
}

fn send_probe_request(
    client: &Client,
    url: &str,
) -> Result<reqwest::blocking::Response, reqwest::Error> {
    client
        .get(url)
        .header(CACHE_CONTROL, "no-cache")
        .header(PRAGMA, "no-cache")
        .header(CONNECTION, "close")
        .header(
            USER_AGENT,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
        )
        .send()
}

/// Probes a specific URL using the Firefox CaptiveDetect algorithm with GStatic and MSFT fallbacks
pub fn probe_url(client: &Client, url: &str, fallback_gateway: Option<&str>) -> ProbeResult {
    let res = send_probe_request(client, url);
    let probe_result = match res {
        Ok(resp) => parse_probe_response(resp),
        Err(primary_err) => ProbeResult::ProbeTimeoutOrError(primary_err.to_string()),
    };

    // When url == FIREFOX_SUCCESS_URL, if req.send() fails OR if parse_probe_response returns
    // ProbeResult::ProbeTimeoutOrError(_) (e.g. unrecognized 403/502 response without a redirect),
    // automatically try GSTATIC_204_URL and then MSFT_CONNECTTEST_URL before fallback_gateway!
    if url == FIREFOX_SUCCESS_URL && matches!(probe_result, ProbeResult::ProbeTimeoutOrError(_)) {
        // 1. Try GSTATIC_204_URL
        if let Ok(resp) = send_probe_request(client, GSTATIC_204_URL) {
            let res2 = parse_probe_response(resp);
            if !matches!(res2, ProbeResult::ProbeTimeoutOrError(_)) {
                return res2;
            }
        }

        // 2. Try MSFT_CONNECTTEST_URL
        if let Ok(resp) = send_probe_request(client, MSFT_CONNECTTEST_URL) {
            let res3 = parse_probe_response(resp);
            if !matches!(res3, ProbeResult::ProbeTimeoutOrError(_)) {
                return res3;
            }
        }
    }

    if let ProbeResult::ProbeTimeoutOrError(err_msg) = probe_result {
        resolve_fallback_gateway(fallback_gateway, &err_msg)
    } else {
        probe_result
    }
}

fn parse_probe_response(resp: reqwest::blocking::Response) -> ProbeResult {
    let status = resp.status();

    // HTTP 204 No Content indicates Internet is unlocked
    if status.as_u16() == 204 {
        return ProbeResult::OnlineUnlocked;
    }

    if status.is_success() {
        let body = resp.text().unwrap_or_default();
        let trimmed = body.trim();
        if trimmed == FIREFOX_EXPECTED_BODY || trimmed == MSFT_EXPECTED_BODY {
            return ProbeResult::OnlineUnlocked;
        }

        if let Some((gateway_base, login_xml_url)) = resolve_login_target(&body) {
            return ProbeResult::LockedPortal {
                gateway_base,
                login_xml_url,
            };
        }
    } else if status.is_redirection() || status.as_u16() == 511 {
        if let Some(loc) = resp.headers().get(reqwest::header::LOCATION)
            && let Ok(loc_str) = loc.to_str()
        {
            let full_loc = if let Ok(u) = url::Url::parse(loc_str) {
                u.to_string()
            } else if resp.url().host_str().is_some_and(|h| !is_ignored_host(h))
                && let Ok(joined) = resp.url().join(loc_str)
            {
                joined.to_string()
            } else {
                loc_str.to_string()
            };

            if let Some((gateway_base, login_xml_url)) = resolve_login_target(&full_loc) {
                return ProbeResult::LockedPortal {
                    gateway_base,
                    login_xml_url,
                };
            }
        }
        let body = resp.text().unwrap_or_default();
        if let Some((gateway_base, login_xml_url)) = resolve_login_target(&body) {
            return ProbeResult::LockedPortal {
                gateway_base,
                login_xml_url,
            };
        }
    }

    let err_msg = format!(
        "Portal intercepted request (status {}) but gateway URL could not be resolved",
        status
    );
    ProbeResult::ProbeTimeoutOrError(err_msg)
}

/// Executes dynamic gateway discovery according to Firefox CaptiveDetect specifications
pub fn probe_network(client: &Client, fallback_gateway: Option<&str>) -> ProbeResult {
    let has_override = std::env::var("CCP_PROBE_URL").is_ok();
    if !has_override && current_local_ipv4().is_none() {
        return ProbeResult::InterfaceOffline;
    }
    let target = probe_target_url();
    probe_url(client, &target, fallback_gateway)
}

/// Extracts the message text inside <message><![CDATA[...]]></message> or <message>...</message>
pub fn extract_xml_message(body: &str) -> Option<String> {
    if let Some(caps) = XML_MESSAGE_RE.captures(body)
        && let Some(m) = caps.get(1)
    {
        let msg = m.as_str().trim();
        if !msg.is_empty() {
            return Some(msg.to_string());
        }
    }
    None
}

/// Validates portal authentication responses, supporting Sophos XML, Cyberoam,
/// and original main:src/main.rs HTTP status codes (200, 301, 302, 303).
pub fn validate_portal_response(status_code: u16, body: &str) -> Result<String, String> {
    let body_lower = body.to_lowercase();
    let extracted_msg = extract_xml_message(body);

    // 1. Explicit XML status failure checks
    if body_lower.contains("<status>fail</status>")
        || body_lower.contains("[cdata[fail]]")
        || body_lower.contains("<status>login</status>")
        || body_lower.contains("[cdata[login]]")
    {
        let msg = extracted_msg.unwrap_or_else(|| "Portal returned FAIL status".to_string());
        return Err(format!("Portal rejected login: {}", msg));
    }

    // 2. Failure keywords check (checked BEFORE success keywords)
    let failure_keywords = [
        "invalid username",
        "invalid user name",
        "invalid password",
        "incorrect password",
        "authentication failed",
        "login failed",
        "wrong password",
        "invalid credentials",
        "maximum login limit",
        "make sure your password is correct",
        "account expired",
        "access denied",
        "not signed in",
        "keep me signed in",
        "stay signed in",
        "sign in to",
    ];

    for keyword in &failure_keywords {
        if body_lower.contains(keyword) {
            let msg = extracted_msg.unwrap_or_else(|| keyword.to_string());
            return Err(format!("Portal rejected login: {}", msg));
        }
    }

    let has_success_keyword = body_lower.contains("<status>live</status>")
        || body_lower.contains("[cdata[live]]")
        || body_lower.contains("you are signed in")
        || body_lower.contains("successfully logged in");

    // If XML message exists but body does not contain success keyword, treat as error
    if let Some(msg) = &extracted_msg
        && !has_success_keyword
    {
        return Err(format!("Portal rejected login: {}", msg));
    }

    // 3. Success keyword check
    if has_success_keyword {
        return Ok(extracted_msg.unwrap_or_else(|| "Authentication successful".to_string()));
    }

    // 4. Fallback matching main:src/main.rs (HTTP 200 | 301 | 302 | 303 for non-Sophos HTML portals)
    let is_sophos_xml = body_lower.contains("<requestresponse>") || body_lower.contains("<status>");
    if !is_sophos_xml && matches!(status_code, 200 | 301 | 302 | 303) {
        return Ok("Login request completed.".to_string());
    }

    Err(format!(
        "Portal rejected login: Unexpected response (HTTP {})",
        status_code
    ))
}

/// Wrapper for validate_portal_response assuming HTTP 200
pub fn validate_sophos_response(body: &str) -> Result<String, String> {
    validate_portal_response(200, body)
}

/// Submits url-encoded credentials to the target login URL.
/// Keys and values (including special characters like &, =, +, #, %) are properly URL-encoded.
pub fn submit_login_post(
    client: &Client,
    url: &str,
    username: &str,
    password: &str,
) -> Result<reqwest::blocking::Response, reqwest::Error> {
    let is_sophos = url.contains("login.xml") || url.contains(":8090");

    if is_sophos {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);

        let params = [
            ("mode", "191"),
            ("username", username),
            ("password", password),
            ("a", &now_ms.to_string()),
            ("producttype", "0"),
            ("inputStr", ""),
            ("escapeUser", username),
            ("preauthid", ""),
            ("user", username),
            ("passwd", password),
            ("ok", "Login"),
        ];

        client
            .post(url)
            .header(CACHE_CONTROL, "no-cache")
            .header(CONNECTION, "close")
            .form(&params)
            .send()
    } else {
        // Exact 6 form parameters from main:src/main.rs (Palo Alto / generic)
        let params = [
            ("inputStr", ""),
            ("escapeUser", username),
            ("preauthid", ""),
            ("user", username),
            ("passwd", password),
            ("ok", "Login"),
        ];

        client
            .post(url)
            .header(CACHE_CONTROL, "no-cache")
            .header(CONNECTION, "close")
            .form(&params)
            .send()
    }
}

/// Why a login attempt did not end with working internet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginError {
    /// The portal rejected the username/password (or says the account is unusable).
    /// Retrying with the same credentials can only risk a lockout.
    BadCredentials(String),
    /// The portal refused for another reason (session limit, transient error, ...).
    Rejected(String),
    /// The request failed before the portal gave a verdict (timeout, refused, ...).
    Network(String),
    /// The portal answered "OK" but the network is still behind it afterwards.
    StillLocked,
}

impl std::fmt::Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoginError::BadCredentials(m) | LoginError::Rejected(m) => write!(f, "{m}"),
            LoginError::Network(m) => write!(f, "Network error during login: {m}"),
            LoginError::StillLocked => write!(
                f,
                "The portal accepted the login but the internet is still locked"
            ),
        }
    }
}

impl std::error::Error for LoginError {}

/// `true` when a portal rejection message means the credentials themselves are bad, as
/// opposed to a transient problem. This is what trips the daemon's circuit breaker.
pub fn is_credential_rejection(message: &str) -> bool {
    let lower = message.to_lowercase();
    [
        "invalid username",
        "invalid user name",
        "invalid password",
        "incorrect password",
        "wrong password",
        "invalid credentials",
        "make sure your password is correct",
        "authentication failed",
        "login failed",
        "account expired",
        "access denied",
        "portal returned fail status",
    ]
    .iter()
    .any(|k| lower.contains(k))
}

/// POSTs the credentials and interprets the portal's answer. Does **not** check that
/// the internet actually came up; use [`login_and_verify`] for that.
///
/// If a plain-HTTP portal refuses the connection, one HTTPS retry is made (never the
/// other way round, and never after a timeout, to avoid double-submitting).
pub fn attempt_login(
    client: &Client,
    login_url: &str,
    username: &str,
    password: &str,
) -> Result<String, LoginError> {
    let resp = match submit_login_post(client, login_url, username, password) {
        Ok(r) => r,
        Err(e) if e.is_connect() && login_url.starts_with("http://") => {
            let https_url = login_url.replacen("http://", "https://", 1);
            submit_login_post(client, &https_url, username, password)
                .map_err(|e2| LoginError::Network(format!("{e}; HTTPS retry also failed: {e2}")))?
        }
        Err(e) => return Err(LoginError::Network(e.to_string())),
    };

    let status = resp.status().as_u16();
    let body = resp.text().unwrap_or_default();

    validate_portal_response(status, &body).map_err(|msg| {
        if is_credential_rejection(&msg) {
            LoginError::BadCredentials(msg)
        } else {
            LoginError::Rejected(msg)
        }
    })
}

/// Polls `probe_target` until the network reports "unlocked" or attempts run out.
/// Portals often take a moment to open the firewall after a successful login.
pub fn wait_until_unlocked(
    client: &Client,
    probe_target: &str,
    attempts: u32,
    delay: Duration,
) -> bool {
    for attempt in 0..attempts {
        if probe_url(client, probe_target, None) == ProbeResult::OnlineUnlocked {
            return true;
        }
        if attempt + 1 < attempts {
            std::thread::sleep(delay);
        }
    }
    false
}

/// Confirms the internet is really reachable (about 4 seconds of patience).
pub fn verify_unlocked(client: &Client) -> bool {
    wait_until_unlocked(client, &probe_target_url(), 6, Duration::from_millis(700))
}

/// Logs in, then proves it worked. A portal page that merely *looks* successful no
/// longer counts as success: it must be followed by a working connection.
pub fn login_and_verify(
    login_client: &Client,
    probe_client: &Client,
    login_url: &str,
    username: &str,
    password: &str,
) -> Result<String, LoginError> {
    let message = attempt_login(login_client, login_url, username, password)?;
    if verify_unlocked(probe_client) {
        Ok(message)
    } else {
        Err(LoginError::StillLocked)
    }
}

/// Authenticates and prints progress (CLI-friendly wrapper around [`attempt_login`]).
/// Prefer [`login_and_verify`] in new code.
pub fn post_login(
    client: &Client,
    login_xml_url: &str,
    username: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Authenticating at: {}", login_xml_url);
    match attempt_login(client, login_xml_url, username, password) {
        Ok(msg) => {
            println!("Login request completed: {}", msg);
            Ok(())
        }
        Err(e) => {
            eprintln!("{e}");
            Err(Box::new(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    pub fn read_full_http_request(stream: &mut TcpStream) -> String {
        let _ = stream.set_nodelay(true);
        let mut data = Vec::new();
        let mut buf = [0u8; 1024];
        let mut content_length: Option<usize> = None;
        let mut header_len: Option<usize> = None;

        loop {
            let n = stream.read(&mut buf).unwrap_or(0);
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);

            if header_len.is_none()
                && let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n")
            {
                let h_end = pos + 4;
                header_len = Some(h_end);
                let header_str = String::from_utf8_lossy(&data[..h_end]);
                for line in header_str.lines() {
                    if let Some(idx) = line.find(':') {
                        let key = line[..idx].trim().to_lowercase();
                        if key == "content-length" {
                            content_length = line[idx + 1..].trim().parse::<usize>().ok();
                        }
                    }
                }
            }

            if let Some(h_end) = header_len {
                let required_total = h_end + content_length.unwrap_or(0);
                if data.len() >= required_total {
                    break;
                }
            }
        }

        String::from_utf8_lossy(&data).to_string()
    }

    fn spawn_mock_server(raw_response: &'static str) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind mock listener");
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}/probe");
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = read_full_http_request(&mut stream);
                let _ = stream.write_all(raw_response.as_bytes());
                let _ = stream.flush();
            }
        });
        (url, handle)
    }

    #[test]
    fn test_firefox_probe_online() {
        let (url, handle) = spawn_mock_server(
            "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nsuccess\n",
        );
        let client = build_fast_client(false).expect("Client build failed");
        let result = probe_url(&client, &url, None);
        handle.join().unwrap();
        assert_eq!(result, ProbeResult::OnlineUnlocked);
    }

    #[test]
    fn test_probe_204_no_content() {
        let (url, handle) =
            spawn_mock_server("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
        let client = build_fast_client(false).expect("Client build failed");
        let result = probe_url(&client, &url, None);
        handle.join().unwrap();
        assert_eq!(result, ProbeResult::OnlineUnlocked);
    }

    #[test]
    fn test_firefox_probe_302_redirect() {
        let (url, handle) = spawn_mock_server(
            "HTTP/1.1 302 Found\r\nLocation: http://172.16.68.6:8090/httpclient.html?u=http://detectportal.firefox.com/success.txt\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        let client = build_fast_client(false).expect("Client build failed");
        let result = probe_url(&client, &url, None);
        handle.join().unwrap();
        assert_eq!(
            result,
            ProbeResult::LockedPortal {
                gateway_base: "http://172.16.68.6:8090".to_string(),
                login_xml_url: "http://172.16.68.6:8090/login.xml".to_string(),
            }
        );
    }

    #[test]
    fn test_firefox_probe_html_js_redirect() {
        let body = "<script>window.location=\"https://10.1.1.9:8090/httpclient.html\"</script>";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let (url, handle) = spawn_mock_server(Box::leak(resp.into_boxed_str()));
        let client = build_fast_client(false).expect("Client build failed");
        let result = probe_url(&client, &url, None);
        handle.join().unwrap();
        assert_eq!(
            result,
            ProbeResult::LockedPortal {
                gateway_base: "https://10.1.1.9:8090".to_string(),
                login_xml_url: "https://10.1.1.9:8090/login.xml".to_string(),
            }
        );
    }

    #[test]
    fn test_resolve_login_target_palo_alto_vs_sophos() {
        // Palo Alto style redirect: preserves exact full URL with path and query
        let pa_location = "https://172.16.1.1:6082/php/uid.php?vsys=1&rule=0";
        let pa_result = resolve_login_target(pa_location);
        assert_eq!(
            pa_result,
            Some((
                "https://172.16.1.1:6082".to_string(),
                "https://172.16.1.1:6082/php/uid.php?vsys=1&rule=0".to_string()
            ))
        );

        // Sophos style redirect: ends with /httpclient.html, resolves to /login.xml
        let sophos_location =
            "http://172.16.68.6:8090/httpclient.html?u=http://detectportal.firefox.com/success.txt";
        let sophos_result = resolve_login_target(sophos_location);
        assert_eq!(
            sophos_result,
            Some((
                "http://172.16.68.6:8090".to_string(),
                "http://172.16.68.6:8090/login.xml".to_string()
            ))
        );

        // Bare gateway: resolves to /login.xml
        let bare = "http://172.16.68.6:8090";
        let bare_result = resolve_login_target(bare);
        assert_eq!(
            bare_result,
            Some((
                "http://172.16.68.6:8090".to_string(),
                "http://172.16.68.6:8090/login.xml".to_string()
            ))
        );

        // Non-Sophos root path: preserves "http://172.16.1.1/"
        let root_path = "http://172.16.1.1/";
        let root_result = resolve_login_target(root_path);
        assert_eq!(
            root_result,
            Some((
                "http://172.16.1.1".to_string(),
                "http://172.16.1.1/".to_string()
            ))
        );

        // Sophos port 8090 non-httpclient path resolves to /login.xml
        let sophos_non_client = "http://172.16.68.6:8090/index.html";
        let sophos_non_client_res = resolve_login_target(sophos_non_client);
        assert_eq!(
            sophos_non_client_res,
            Some((
                "http://172.16.68.6:8090".to_string(),
                "http://172.16.68.6:8090/login.xml".to_string()
            ))
        );
    }

    #[test]
    fn test_resolve_login_target_rejects_w3_doctype() {
        let html_with_doctype = r#"<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>Test</title></head>
<body>Hello world</body>
</html>"#;
        assert_eq!(resolve_login_target(html_with_doctype), None);
    }

    #[test]
    fn test_extract_gateway_base_variants() {
        // Meta refresh
        let meta = r#"<meta http-equiv="refresh" content="0; url=http://172.16.68.6:8090/httpclient.html">"#;
        assert_eq!(
            extract_gateway_base(meta),
            Some("http://172.16.68.6:8090".to_string())
        );

        // Single quotes window.location
        let js = "window.location.href='https://192.168.1.1:8090/login';";
        assert_eq!(
            extract_gateway_base(js),
            Some("https://192.168.1.1:8090".to_string())
        );

        // Raw IP without scheme
        let ip_port = "172.16.68.6:8090";
        assert_eq!(
            extract_gateway_base(ip_port),
            Some("http://172.16.68.6:8090".to_string())
        );
    }

    #[test]
    fn test_current_local_ipv4_non_panicking() {
        let _ = current_local_ipv4();
    }

    #[test]
    fn test_validate_sophos_response_live_cdata() {
        let xml = "<requestresponse><status><![CDATA[LIVE]]></status><message><![CDATA[You are signed in as testuser]]></message></requestresponse>";
        let res = validate_sophos_response(xml);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), "You are signed in as testuser");
    }

    #[test]
    fn test_validate_sophos_response_live_plain() {
        let xml = "<requestresponse><status>LIVE</status><message>You have successfully logged in</message></requestresponse>";
        let res = validate_sophos_response(xml);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), "You have successfully logged in");
    }

    #[test]
    fn test_validate_sophos_response_signed_in() {
        let body = "<html><body>You are signed in as testuser</body></html>";
        let res = validate_sophos_response(body);
        assert!(res.is_ok());
    }

    #[test]
    fn test_validate_portal_response_signed_in_false_positives() {
        // "You are not signed in" must be rejected
        let body1 = "<html><body>You are not signed in. Please log in.</body></html>";
        assert!(validate_sophos_response(body1).is_err());

        // "Keep me signed in" must be rejected
        let body2 = "<form><input type='checkbox'>Keep me signed in</form>";
        assert!(validate_sophos_response(body2).is_err());

        // "Stay signed in" must be rejected
        let body3 = "<html><body>Stay signed in to this network</body></html>";
        assert!(validate_sophos_response(body3).is_err());
    }

    #[test]
    fn test_validate_sophos_response_wrong_password() {
        let xml = "<requestresponse><status><![CDATA[FAIL]]></status><message><![CDATA[Make sure your password is correct]]></message></requestresponse>";
        let res = validate_sophos_response(xml);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            "Portal rejected login: Make sure your password is correct"
        );
    }

    #[test]
    fn test_validate_sophos_response_max_login_limit() {
        let xml = "<requestresponse><status><![CDATA[FAIL]]></status><message><![CDATA[Maximum login limit reached for your account]]></message></requestresponse>";
        let res = validate_sophos_response(xml);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            "Portal rejected login: Maximum login limit reached for your account"
        );
    }

    #[test]
    fn test_validate_portal_response_status_codes() {
        // Fallback for non-Sophos portals: HTTP 200 without failure keywords
        let non_sophos_html =
            "<html><body>Welcome to Palo Alto Networks Captive Portal</body></html>";
        let res = validate_portal_response(200, non_sophos_html);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), "Login request completed.");

        // HTTP 302 redirect on login success
        let res_302 = validate_portal_response(302, "");
        assert!(res_302.is_ok());

        // HTTP 200 with explicit failure keyword
        let failure_html = "<html><body>Authentication failed. Please try again.</body></html>";
        let res_fail = validate_portal_response(200, failure_html);
        assert!(res_fail.is_err());
        assert_eq!(
            res_fail.unwrap_err(),
            "Portal rejected login: authentication failed"
        );
    }

    #[test]
    fn test_cached_gateway_reachability() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let active_gw = format!("http://127.0.0.1:{}", port);
        assert!(is_gateway_reachable(&active_gw));

        drop(listener);
        assert!(!is_gateway_reachable(&active_gw));
    }

    #[test]
    fn test_ccp_probe_url_env_override() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let override_val = "http://127.0.0.1:9999/test-probe";
        unsafe {
            std::env::set_var("CCP_PROBE_URL", override_val);
        }
        assert_eq!(probe_target_url(), override_val);
        unsafe {
            std::env::remove_var("CCP_PROBE_URL");
        }
        assert_eq!(probe_target_url(), FIREFOX_SUCCESS_URL);
    }

    #[test]
    fn test_url_encoded_credentials_special_chars() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind mock listener");
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}/login.xml");

        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let request = read_full_http_request(&mut stream);

                // Verify the form payload encodes special characters like & and =
                assert!(
                    request.contains("password=P%40ss%26word%3D1%2B2%253"),
                    "Request body did not properly url-encode password. Raw request:\n{}",
                    request
                );

                let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: 104\r\nConnection: close\r\n\r\n<requestresponse><status><![CDATA[LIVE]]></status><message><![CDATA[OK]]></message></requestresponse>";
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });

        let client = build_fast_client(false).unwrap();
        let result = submit_login_post(&client, &url, "user1", "P@ss&word=1+2%3");
        assert!(result.is_ok());
        handle.join().unwrap();
    }

    #[test]
    fn test_submit_login_post_palo_alto_params() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind mock listener");
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}/php/uid.php");

        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let request = read_full_http_request(&mut stream);

                // Verify exact 6 params from main:src/main.rs (without mode=191)
                assert!(
                    !request.contains("mode=191"),
                    "Palo Alto target should not contain mode=191"
                );
                assert!(request.contains("user=user1"));
                assert!(request.contains("passwd=P%40ss%26word%3D1%2B2%253"));
                assert!(request.contains("ok=Login"));

                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });

        let client = build_fast_client(false).unwrap();
        let result = submit_login_post(&client, &url, "user1", "P@ss&word=1+2%3");
        assert!(result.is_ok());
        handle.join().unwrap();
    }

    #[test]
    fn test_resolve_login_target_rejects_external_and_relative_filenames() {
        // External URLs with login.xml must be rejected
        assert_eq!(
            resolve_login_target("https://evil.example.org/login.xml"),
            None
        );
        assert_eq!(
            resolve_login_target("http://evil.example.org:8090/httpclient.html"),
            None
        );

        // Relative HTML constructs without private IP must be rejected (not converted to http://login.xml)
        assert_eq!(resolve_login_target(r#"<form action="login.xml">"#), None);
        assert_eq!(
            resolve_login_target(r#"<script>window.location="httpclient.html"</script>"#),
            None
        );
        assert_eq!(
            resolve_login_target(r#"<form action="/php/uid.php">"#),
            None
        );
    }

    #[test]
    fn test_is_compatible_gateway_subnet() {
        use std::str::FromStr;

        // Campus routed 10.x.x.x
        let loc_10 = Ipv4Addr::from_str("10.20.1.5").unwrap();
        let gw_10 = Ipv4Addr::from_str("10.1.1.9").unwrap();
        assert!(is_compatible_gateway_subnet(
            gw_10,
            loc_10,
            8090,
            "/login.xml"
        ));

        // Campus routed 172.16-31
        let loc_172 = Ipv4Addr::from_str("172.18.5.12").unwrap();
        let gw_172 = Ipv4Addr::from_str("172.16.68.6").unwrap();
        assert!(is_compatible_gateway_subnet(
            gw_172,
            loc_172,
            8090,
            "/login.xml"
        ));

        // Home 192.168.1.x: generic router without portal port/path must be rejected
        let loc_192 = Ipv4Addr::from_str("192.168.1.50").unwrap();
        let gw_192 = Ipv4Addr::from_str("192.168.1.1").unwrap();
        assert!(!is_compatible_gateway_subnet(gw_192, loc_192, 80, "/"));
        assert!(!is_compatible_gateway_subnet(gw_192, loc_192, 80, ""));

        // Home 192.168.1.x: portal with explicit port 8090 or path is accepted
        assert!(is_compatible_gateway_subnet(
            gw_192,
            loc_192,
            8090,
            "/login.xml"
        ));

        // Mismatched subnets (e.g. campus 10.x vs home 192.168.x) must be rejected
        assert!(!is_compatible_gateway_subnet(
            gw_192,
            loc_10,
            8090,
            "/login.xml"
        ));
    }
}
