use ccp::config::{self, Settings};
use ccp::daemon;
use ccp::logger;
use ccp::probe::{self, LoginError, ProbeResult};
use ccp::state::DaemonState;
use ccp::trust::{self, TrustStore, Verdict};
use ccp::wifi;
use std::env;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

type CliResult = Result<(), Box<dyn std::error::Error>>;

const USAGE: &str = "\
ccp - campus captive portal auto-login

Usage:
  ccp                              Log in now using saved credentials
  ccp set                          Save username and password
  ccp start | stop | status        Control the background daemon
  ccp autostart enable [--now]     Start the daemon at every login (disable: ccp autostart disable)
  ccp daemon [--once] [--dry-run]  Run the daemon loop in the foreground
  ccp trust [HOST]                 Allow sending credentials to a portal (no HOST: approve the one the daemon blocked, or list)
  ccp untrust HOST                 Stop trusting a portal
  ccp wifi add|remove SSID         Let ccp (re)connect to this Wi-Fi network by itself
  ccp wifi list | clear            Show / clear that list (empty = ccp never touches Wi-Fi)
  ccp logs [-n N]                  Show the last N lines of the daemon log (default 30)
  ccp --version | --help";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> CliResult {
    let args: Vec<String> = env::args().skip(1).collect();
    let dir = config::config_dir();
    let rest = &args[args.len().min(1)..];

    match args.first().map(String::as_str) {
        None => login(&dir),
        Some("set") => cmd_set(&dir),
        Some("start") => cmd_start(&dir),
        Some("stop") => daemon::stop_daemon(&dir).map_err(Into::into),
        Some("status") => {
            daemon::print_status(&dir);
            Ok(())
        }
        Some("daemon") => cmd_daemon(&dir, rest),
        Some("autostart") => cmd_autostart(&dir, rest),
        Some("trust") => cmd_trust(&dir, rest),
        Some("untrust") => cmd_untrust(&dir, rest),
        Some("wifi") => cmd_wifi(&dir, rest),
        Some("logs") => cmd_logs(&dir, rest),
        Some("--version" | "-V" | "version") => {
            println!("ccp {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("--help" | "-h" | "help") => {
            println!("{USAGE}");
            Ok(())
        }
        Some(_) => {
            eprintln!("{USAGE}");
            Err("Invalid command line arguments.".into())
        }
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_set(dir: &Path) -> CliResult {
    let mut username = String::new();

    print!("Username: ");
    io::stdout().flush()?;
    io::stdin().read_line(&mut username)?;

    let username = username.trim();
    let password = rpassword::prompt_password("Password: ")?;

    if username.is_empty() || password.is_empty() {
        return Err("Username and password cannot be empty.".into());
    }

    config::save_credentials(dir, username, &password)?;

    // Reset daemon circuit breaker on new credentials
    DaemonState::reset_circuit_breaker(&dir.join("state.json"));

    println!("Credentials saved successfully.");
    if TrustStore::open(dir).hosts().is_empty() {
        println!(
            "Next: connect to your campus Wi-Fi and run `ccp` once. It will ask you to approve your login portal."
        );
    }
    Ok(())
}

fn cmd_start(dir: &Path) -> CliResult {
    config::load_credentials(dir)?;
    daemon::start_background_daemon(dir).map_err(Into::into)
}

fn cmd_daemon(dir: &Path, args: &[String]) -> CliResult {
    let creds = config::load_credentials(dir)?;

    let once = args.iter().any(|a| a == "--once");
    let dry_run = args.iter().any(|a| a == "--dry-run");

    if let Err(e) = daemon::run_daemon(dir, &creds.username, &creds.password, once, dry_run) {
        // The daemon's stderr is detached, so leave a trace in the log too.
        logger::log(dir, &format!("Daemon error: {e}"));
        return Err(e.into());
    }
    Ok(())
}

fn cmd_autostart(dir: &Path, args: &[String]) -> CliResult {
    let usage_err = || -> CliResult {
        eprintln!("Usage: ccp autostart [enable [--now]|disable]");
        Err("Invalid autostart arguments.".into())
    };

    match args.first().map(String::as_str) {
        Some("enable") => {
            let start_now = args.iter().any(|a| a == "--now" || a == "-n");
            daemon::set_autostart(dir, true)?;

            if start_now {
                daemon::start_background_daemon(dir)
                    .map_err(|e| format!("Failed to start background daemon: {e}"))?;
            } else {
                println!(
                    "Auto-start configured. The daemon will automatically launch on your next system restart/login."
                );
                println!(
                    "Tip: Run 'ccp start' or use 'ccp autostart enable --now' to start the daemon immediately."
                );
            }
            Ok(())
        }
        Some("disable") => daemon::set_autostart(dir, false).map_err(Into::into),
        _ => usage_err(),
    }
}

fn cmd_trust(dir: &Path, args: &[String]) -> CliResult {
    let store = TrustStore::open(dir);

    match args.first().map(String::as_str) {
        Some("--list" | "list") => print_trusted(&store),
        Some(target) => {
            let host = trust::host_of(target).ok_or("That doesn't look like a host or URL.")?;
            if store.add(&host)? {
                println!("Trusted {host}. Credentials may now be sent to it.");
            } else {
                println!("{host} was already trusted.");
            }
        }
        None => {
            let state = DaemonState::load(&dir.join("state.json"));
            match state
                .pending_untrusted_gateway
                .filter(|h| !store.is_trusted(h))
            {
                Some(host) => {
                    println!("The background daemon found a login portal it did not trust: {host}");
                    println!(
                        "Only approve it if it is really your campus network: your password will be sent to it."
                    );
                    if confirm(&format!("Trust {host}?")) {
                        store.add(&host)?;
                        println!(
                            "Trusted {host}. The daemon will pick this up within ~30 seconds."
                        );
                    } else {
                        println!("Not trusted.");
                    }
                }
                None => print_trusted(&store),
            }
        }
    }
    Ok(())
}

fn print_trusted(store: &TrustStore) {
    let hosts = store.hosts();
    if hosts.is_empty() {
        println!("No trusted portals yet. Run `ccp` on campus Wi-Fi to approve one.");
    } else {
        println!("Trusted portals (credentials may be sent to these):");
        for h in hosts {
            println!("  {h}");
        }
    }
}

fn cmd_untrust(dir: &Path, args: &[String]) -> CliResult {
    let Some(target) = args.first() else {
        eprintln!("Usage: ccp untrust HOST");
        return Err("Missing host.".into());
    };
    if TrustStore::open(dir).remove(target)? {
        println!("No longer trusting {target}.");
    } else {
        println!("{target} was not in the trusted list.");
    }
    Ok(())
}

fn cmd_wifi(dir: &Path, args: &[String]) -> CliResult {
    let mut settings = Settings::load(dir);
    let name = args.get(1..).unwrap_or(&[]).join(" ");

    match args.first().map(String::as_str) {
        Some("add") if !name.is_empty() => {
            if settings.add_ssid(&name) {
                settings.save(dir)?;
                println!("ccp may now reconnect to \"{name}\" by itself.");
            } else {
                println!("\"{name}\" is already in the list.");
            }
        }
        Some("remove") if !name.is_empty() => {
            if settings.remove_ssid(&name) {
                settings.save(dir)?;
                println!("Removed \"{name}\".");
            } else {
                println!("\"{name}\" was not in the list.");
            }
        }
        Some("clear") => {
            settings.wifi_ssids.clear();
            settings.save(dir)?;
            println!("Wi-Fi auto-join is now off.");
        }
        Some("list") | None => {
            if settings.wifi_ssids.is_empty() {
                println!("Wi-Fi auto-join is off. ccp never connects to Wi-Fi on its own.");
                println!("Enable it for your campus network: ccp wifi add \"<SSID>\"");
            } else {
                println!("ccp may reconnect to (in this order):");
                for s in &settings.wifi_ssids {
                    println!("  {s}");
                }
            }
        }
        _ => {
            eprintln!("Usage: ccp wifi add|remove SSID | ccp wifi list | ccp wifi clear");
            return Err("Invalid wifi arguments.".into());
        }
    }
    Ok(())
}

fn cmd_logs(dir: &Path, args: &[String]) -> CliResult {
    let n = args
        .iter()
        .position(|a| a == "-n")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(30);

    let lines = logger::tail(dir, n);
    if lines.is_empty() {
        println!(
            "No log entries yet. (The daemon writes to {})",
            dir.join(logger::LOG_FILE).display()
        );
    } else {
        for line in lines {
            println!("{line}");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// One-shot login (`ccp`)
// ---------------------------------------------------------------------------

fn login(dir: &Path) -> CliResult {
    let creds = config::load_credentials(dir)?;

    let state_path = dir.join("state.json");
    if DaemonState::load(&state_path).halted_bad_credentials {
        let msg = "Automatic login is paused because the portal rejected your credentials. \
                   Run `ccp set` to update them (this also resumes the daemon).";
        return Err(msg.into());
    }

    let cached_gateway = get_cached_gateway(dir);
    let probe_client = probe::build_fast_client(false)?;
    let login_client = probe::build_login_client()?;
    let mut tried_wifi = false;

    loop {
        // Zero-lag probe pipeline
        match probe::probe_network(&probe_client, cached_gateway.as_deref()) {
            ProbeResult::OnlineUnlocked => {
                println!("Already connected and authenticated!");
                return Ok(());
            }

            ProbeResult::LockedPortal {
                gateway_base,
                login_xml_url,
            } => {
                println!("Portal detected at: {gateway_base}");
                ensure_trusted(dir, &login_xml_url)?;

                println!("Authenticating at: {login_xml_url}");
                return match probe::login_and_verify(
                    &login_client,
                    &probe_client,
                    &login_xml_url,
                    &creds.username,
                    &creds.password,
                ) {
                    Ok(msg) => {
                        set_cached_gateway(dir, &login_xml_url);
                        println!("Logged in: internet is reachable. ({msg})");
                        Ok(())
                    }
                    Err(LoginError::BadCredentials(msg)) => {
                        DaemonState::mark_bad_credentials(
                            &state_path,
                            &format!("Halted (bad credentials): {msg}"),
                        );
                        Err(format!(
                            "{msg}\nAutomatic login is now paused so your account isn't locked out. Run `ccp set` with the correct password."
                        )
                        .into())
                    }
                    Err(e) => Err(e.into()),
                };
            }

            ProbeResult::InterfaceOffline => {
                let ssids = Settings::load(dir).wifi_ssids;
                if tried_wifi || ssids.is_empty() {
                    let msg = if ssids.is_empty() {
                        "Not connected to any network. Connect to your campus Wi-Fi, or run `ccp wifi add \"<SSID>\"` so ccp can do it for you."
                    } else {
                        "Interface still offline after Wi-Fi connect attempt."
                    };
                    return Err(msg.into());
                }
                tried_wifi = true;

                println!("Wi-Fi interface offline or disconnected. Connecting to Wi-Fi...");
                let _ = wifi::connect_allowed(&ssids);

                print!("Waiting for IPv4 route...");
                io::stdout().flush()?;
                match wifi::wait_for_ipv4(Duration::from_millis(6000), Duration::from_millis(200)) {
                    Some(ip) => println!(" Connected ({ip})"),
                    None => {
                        println!();
                        return Err("Timed out waiting for IPv4 route.".into());
                    }
                }
            }

            ProbeResult::ProbeTimeoutOrError(err_msg) => {
                return Err(format!("Network probe error: {err_msg}").into());
            }
        }
    }
}

/// Credentials only go to portals the user approved. Interactive runs can approve on
/// the spot; non-interactive ones (scripts, the daemon) must use `ccp trust`.
fn ensure_trusted(dir: &Path, login_url: &str) -> CliResult {
    let Verdict::Untrusted { host } = trust::check(dir, login_url) else {
        return Ok(());
    };

    if !(io::stdin().is_terminal() && io::stdout().is_terminal()) {
        let msg = format!(
            "Portal host {host} is not trusted. Run `ccp trust {host}` to allow sending your credentials to it."
        );
        return Err(msg.into());
    }

    println!();
    println!("The login portal at {host} is not in your trusted list.");
    println!(
        "Only continue if this is your campus network: your username and password will be sent to it."
    );
    if confirm(&format!("Trust {host} and log in?")) {
        TrustStore::open(dir).add(&host)?;
        println!("Trusted {host}.");
        Ok(())
    } else {
        Err("Login cancelled: portal not trusted.".into())
    }
}

fn confirm(question: &str) -> bool {
    print!("{question} [y/N]: ");
    let _ = io::stdout().flush();
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim().to_lowercase().as_str(), "y" | "yes")
}

fn get_cached_gateway(dir: &Path) -> Option<String> {
    let content = fs::read_to_string(dir.join("cached_gateway.txt")).ok()?;
    let trimmed = content.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn set_cached_gateway(dir: &Path, gateway: &str) {
    let _ = fs::create_dir_all(dir);
    let _ = fs::write(dir.join("cached_gateway.txt"), gateway);
}
