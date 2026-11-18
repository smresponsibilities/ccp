# CCP — Campus Captive Portal Auto-Authenticator

When moving between Hostel and College blocks, laptops roam across different Wi-Fi access points and subnets, dropping connections and requiring repetitive captive portal logins. On Windows, default proxy discovery (WPAD), IPv6 timeouts, and console subprocess calls also cause multi-second lag.

**ccp** is a cross-platform CLI and background daemon that:
- **Detects captive portals in milliseconds** using Firefox's `CaptiveDetect` plain-HTTP redirect discovery (`http://detectportal.firefox.com/success.txt` -> `gstatic` -> `msftconnecttest`).
- **Works across Hostel and College subnets** automatically (supports both Palo Alto `/php/uid.php` and Sophos/Cyberoam `:8090/login.xml` portals with zero hardcoded gateway IPs).
- **Runs natively on Windows without WSL** (zero console popups, IPv4-bound sockets, optional automatic reconnect to the campus Wi-Fi you choose).
- **Automates login in the background** (`ccp start` / `ccp autostart enable`) with 2-second subnet roam detection, wake-from-sleep recovery, and a circuit breaker that stops retrying when logins fail, so your campus account is never locked out.
- **Verifies every login.** A portal page that merely *says* "success" is not enough: `ccp` re-checks that the internet is really reachable before it counts a login as done.
- **Only sends your password to portals you approved** (see [Security model](#security-model)), so a café or evil-twin network can never receive it.

---

## 30-Second Quick Setup (Windows — No Dependencies)

Just open PowerShell and run:
```powershell
irm https://raw.githubusercontent.com/smresponsibilities/ccp/main/install.ps1 | iex
ccp set                         # save your campus username and password
ccp                             # on campus Wi-Fi: log in once and approve your portal [y/N]
ccp autostart enable --now      # keep you logged in from now on
```
> **No Rust, no Cargo, no Git, and no WSL required.** That's it! `ccp` will automatically roam and authenticate in the background on every boot.

---

## Installation

### 1. Windows (One-Line PowerShell Install)
Open PowerShell and run:
```powershell
irm https://raw.githubusercontent.com/smresponsibilities/ccp/main/install.ps1 | iex
```
*`ccp` is downloaded, installed, and added to your PATH immediately—usable in the same terminal.*

### 2. Direct Windows `.exe` Download
Download [`ccp-windows-amd64.zip`](https://github.com/smresponsibilities/ccp/releases/latest/download/ccp-windows-amd64.zip), extract `ccp.exe`, and double-click or run from command prompt.

### 3. macOS, Linux & WSL (One-Line Install)
Open Terminal and run:
```bash
curl -fsSL https://raw.githubusercontent.com/smresponsibilities/ccp/main/install.sh | bash
```

### 4. Build From Source (Cargo)
For developers or users compiling from source:
```bash
git clone https://github.com/smresponsibilities/ccp.git
cd ccp
cargo build --release
```
Requires Rust 1.89 or newer (checked in CI).

> **Checksums:** the install scripts download the `.sha256` file published next to each release asset and refuse to install if it doesn't match (set `CCP_SKIP_VERIFY=1` to override). This catches corrupted or tampered downloads; it can't help if the release itself were compromised.

---

## Usage Methods

Choose the mode that fits your routine best:

---

### Method 1: Simple Manual Mode (Zero Background Processes)
If you prefer not having any background process running at all:
1. **Save your credentials once:**
   ```bash
   ccp set
   ```
2. **Authenticate whenever needed:**
   ```bash
   ccp
   ```
   - If already online: exits almost instantly (`Already connected and authenticated!`).
   - If behind a captive portal: detects the gateway, asks you to approve it the first time, logs in, and confirms the internet really works.
   - If disconnected from Wi-Fi: reconnects to a network you allowed with `ccp wifi add "<SSID>"` (it never joins networks you didn't list), then logs in.

---

### Method 2: Background Daemon (Current Session Only — Without Startup)
If you want automatic roaming between Hostel and College during your current session, but don't want it starting automatically on system boot:
```bash
# Start background roaming daemon right now
ccp start

# Check real-time daemon state, local IP, gateway, and login count
ccp status

# Stop background daemon whenever you want
ccp stop
```

---

### Method 3: Full Auto-Start on System Boot (Permanent "Set & Forget")
If you never want to think about captive portals again:
```bash
# Option A: Enable boot startup AND start daemon immediately right now
ccp autostart enable --now

# Option B: Enable boot startup only (starts on next restart/login)
ccp autostart enable

# Check status anytime
ccp status

# Disable boot startup anytime
ccp autostart disable
```

---

### How the Background Daemon Works
1. **2-Second Roam Detection**: Checks the local IPv4 route every 2 seconds using a zero-packet local UDP socket check (<0.1ms). The moment your IP changes between Hostel and College, it probes and logs in immediately.
2. **Wake-from-Sleep Detection**: If more than ~10 seconds of wall-clock time passed between two checks (the machine was asleep), it re-probes immediately instead of waiting for the next keep-alive.
3. **Periodic Keep-Alive**: Verifies connectivity every 30 seconds while online.
4. **Verified Logins**: After submitting your credentials it re-probes for up to ~4 seconds. Only a working connection counts as a login.
5. **Account Lockout Protection (Circuit Breaker)**: The daemon halts further attempts if the portal rejects your password (e.g., after a campus password change), **or** if the portal says "logged in" three times in a row but the internet stays locked. The counter survives restarts. Running `ccp set` with your password resets the breaker and resumes the daemon without restarting it. Failed attempts that aren't credential problems back off 5 s, 10 s, 20 s ... up to 5 minutes.
6. **Wi-Fi Reconnect (opt-in)**: With `ccp wifi add "<SSID>"`, when there is no network the daemon tries those networks (about every 10 s, backing off to 2 min). It never turns the Wi-Fi radio on and never joins a network you didn't list. With an empty list it never touches Wi-Fi.
7. **Log**: Everything it does is recorded in `ccp.log` (`ccp logs`). Passwords are never logged.

---

## Security model

`ccp` finds your login page from whatever redirect the network sends. Without a safeguard, *any* private-network captive portal could receive your campus password.

- **Trusted portals only.** Credentials are only sent to hosts in `trusted_gateways.txt`. The first time you run `ccp` interactively on a new portal it asks `[y/N]`. The background daemon never asks: it records the blocked host, shows it in `ccp status`, and waits for you to run `ccp trust`.
- **Upgrading?** The gateway you last logged into is trusted automatically, so existing installs keep working.
- **Roaming between Hostel and College** means approving each portal once (`ccp` on each, or `ccp trust <host>`).
- **Opt-out:** `CCP_TRUST_ANY=1` restores the old "send to any portal" behaviour. Not recommended.
- **Storage:** credentials live in `~/.config/ccp/credentials.txt` (directory `0700`, file `0600` on Unix, and loosened permissions are repaired on read). On Windows they rely on your user profile's folder permissions. They are plain text, so use a password you don't reuse elsewhere.
- **Known limit:** campus portals use self-signed HTTPS certificates, so certificate checks are disabled for the portal connection, and Sophos logins are plain HTTP by design. An attacker who can impersonate a gateway you *already trust* (e.g. ARP spoofing on the same LAN) could still capture your login. Trust lists stop the far more common case of a wrong network.

---

## Script & CLI Parameter Reference

### 1. Installation Scripts Parameters

| Script | Parameter / Env Variable | Default | Description |
| :--- | :--- | :--- | :--- |
| **`install.ps1`** | `-Version` (`$env:CCP_VERSION`) | Latest release | Specifies release tag to install (e.g. `v0.2.0`). |
| | `-Repo` (`$env:CCP_REPO`) | `smresponsibilities/ccp` | Target GitHub repository (`owner/repo`). |
| | `-InstallDir` (`$env:INSTALL_DIR`) | `$env:USERPROFILE\.ccp\bin` | Directory where `ccp.exe` is placed and added to PATH. |
| | `$env:CCP_DOWNLOAD_BASE` | *(GitHub releases)* | Download from a mirror instead (expects the asset and its `.sha256` there). |
| | `$env:CCP_SKIP_VERIFY` | *(unset)* | Set to `1` to skip checksum verification. |
| **`install.sh`** | `CCP_VERSION` | Latest release | Specifies release tag to install (e.g. `v0.2.0`). |
| | `CCP_REPO` | `smresponsibilities/ccp` | Target GitHub repository (`owner/repo`). |
| | `INSTALL_DIR` | `$HOME/.local/bin` | Directory where `ccp` binary is placed. |
| | `CCP_DOWNLOAD_BASE` | *(GitHub releases)* | Download from a mirror instead (expects the asset and its `.sha256` there). |
| | `CCP_SKIP_VERIFY` | *(unset)* | Set to `1` to skip checksum verification. |

### 2. CLI Commands & Options

| Command | Arguments / Flags | Description | Example |
| :--- | :--- | :--- | :--- |
| **`ccp`** | *(none)* | Manual authentication mode. Discovers the captive portal, asks you to approve it the first time, logs in and verifies the internet works, or exits immediately if already connected. | `ccp` |
| **`ccp set`** | *(none)* | Saves campus Wi-Fi username and password locally (`0600` permissions on Unix). Resets the circuit breaker. | `ccp set` |
| **`ccp start`** | *(none)* | Starts the autonomous background daemon detached in the background with no console window. | `ccp start` |
| **`ccp stop`** | *(none)* | Authoritatively stops the running background daemon and releases its lock. | `ccp stop` |
| **`ccp status`** | *(none)* | Displays operational status, PID, local IPv4, active gateway, login count and last login time, circuit breaker, trusted/blocked portals and Wi-Fi auto-join list. | `ccp status` |
| **`ccp trust`** | *(none)* | Approves the portal the daemon blocked (asks first); with nothing blocked, lists trusted portals. | `ccp trust` |
| | `HOST` (host, `host:port` or URL) | Trusts a portal explicitly. | `ccp trust 172.16.68.6` |
| | `--list` | Lists trusted portals. | `ccp trust --list` |
| **`ccp untrust`** | `HOST` | Stops trusting a portal. | `ccp untrust 172.16.68.6` |
| **`ccp wifi`** | `add SSID` / `remove SSID` | Manages the Wi-Fi networks `ccp` may reconnect to on its own (default: none). | `ccp wifi add "College WiFi"` |
| | `list` / `clear` | Shows the list / turns auto-join off. | `ccp wifi list` |
| **`ccp logs`** | `-n N` | Prints the last N (default 30) lines of the daemon log. | `ccp logs -n 100` |
| **`ccp --version`** | | Prints the version. | `ccp --version` |
| **`ccp autostart`** | `enable` | Registers auto-start on boot (Windows Registry / macOS LaunchAgent / Linux systemd). Starts on next login/boot. | `ccp autostart enable` |
| | `enable --now` (or `-n`) | Registers auto-start on boot **AND** immediately launches the background daemon right now without waiting for reboot. | `ccp autostart enable --now` |
| | `disable` | Disables and cleans up OS boot auto-start registration. | `ccp autostart disable` |
| **`ccp daemon`** | *(none)* | Runs daemon roaming loop in foreground (polls route every 2s, keep-alive every 30s). | `ccp daemon` |
| | `--once` | Runs one single check iteration and exits immediately. | `ccp daemon --once` |
| | `--dry-run` | Probes network and discovers portal without submitting login credentials. | `ccp daemon --once --dry-run` |

---

## How to Test & Verify

### Test 1: Real-Life Auto-Start Test (Windows — No Code Required)
To verify that Windows itself launches `ccp` automatically on system login:
1. Enable autostart and stop the daemon so you know it's off:
   ```powershell
   ccp autostart enable
   ccp stop
   ccp status    # Displays: State: Stopped
   ```
2. **Sign Out of Windows**: Press `Win + X` → **Shut down or sign out** → **Sign out** (or press `Ctrl + Alt + Del` → **Sign out**).
3. Sign back into Windows to reach your desktop.
4. Open PowerShell and check status:
   ```powershell
   ccp status
   ```
   **Expected Output:** `State: Running` with an active PID and detected Local IP. This proves Windows launched `ccp` in the background on startup!
5. **Visual check via Task Manager**: Press `Ctrl + Shift + Esc` → click the **Startup apps** tab → look for **`CCP_AutoAuth`** with status **`Enabled`**.

### Test 2: Background Daemon Lifecycle Test (Works On or Off Campus)
```bash
ccp start
ccp status
ccp start   # Verifies single-instance lock ("ccp daemon is already running.")
ccp stop
ccp status
```

### Test 3: Foreground Dry-Run Verification (Safe Simulation)
To test portal detection logic in the foreground without sending login credentials or starting background services:
```bash
ccp daemon --once --dry-run
```

### Test 4: Portal Login & Fast-Exit Benchmark (On Campus Wi-Fi)
1. Save credentials:
   ```bash
   ccp set
   ```
2. Log out of the captive portal in your browser (or reconnect to Hostel/College Wi-Fi) and run:
   ```bash
   ccp
   ```
   Verify it prints the discovered gateway (`Portal detected at: ...`), asks you to approve it (first time only), and ends with `Logged in: internet is reachable.`
3. Run `ccp` a second time while already online to measure the fast-exit latency:
   - **Windows PowerShell**:
     ```powershell
     (Measure-Command { ccp }).TotalMilliseconds
     ```
   - **macOS / Linux / WSL**:
     ```bash
     time ccp
     ```

### Test 5: Auto Wi-Fi Reconnect When Disconnected
0. Tell `ccp` which network it may rejoin: `ccp wifi add "<your campus SSID>"`
1. Open your OS Wi-Fi menu and click **Disconnect** from the campus Wi-Fi network (keep Wi-Fi hardware turned on).
2. Run:
   ```bash
   ccp
   ```
3. Verify `ccp` detects `Wi-Fi interface offline or disconnected. Connecting to Wi-Fi...`, reconnects to the SSID you allowed, obtains an IPv4 address, and logs into the portal.

### Test 6: Automated Test Suite (75 Unit & Mock Portal Integration Tests — Works Off Campus)
For developers verifying the codebase: spins up local TCP mock servers simulating Firefox 302 redirects, Palo Alto `/php/uid.php` and Sophos `:8090/login.xml` authentication, URL-encoding of special characters in passwords, login verification (including portals that claim success but stay locked), the circuit breaker, the trusted-portal guard, Wi-Fi allow-list selection, and the single-instance lock:
```bash
cargo test --all-targets -- --nocapture
```

---

## Uninstallation

If you ever want to completely remove `ccp` and your saved credentials:

- **Windows (PowerShell)**:
  ```powershell
  ccp autostart disable
  ccp stop
  Remove-Item -Recurse -Force "$env:USERPROFILE\.ccp", "$env:USERPROFILE\.config\ccp" -ErrorAction SilentlyContinue
  ```

- **macOS / Linux**:
  ```bash
  ccp autostart disable
  ccp stop
  rm -rf ~/.local/bin/ccp ~/.config/ccp ~/Library/LaunchAgents/com.garvittsingla.ccp.plist ~/.config/systemd/user/ccp.service
  ```
