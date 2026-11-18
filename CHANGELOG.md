# Changelog

## 0.2.0

### Security
- **Credentials are only sent to trusted portals.** New `trusted_gateways.txt`, managed with
  `ccp trust` / `ccp untrust`. Existing installs trust the gateway they last logged into.
  The daemon never sends to an unknown portal; it records it so `ccp status` / `ccp trust`
  can approve it. (`CCP_TRUST_ANY=1` restores the old behaviour.)
- Config directory is `0700` and credentials are written atomically with `0600`; a
  credentials file with looser permissions is tightened when read.
- Install scripts verify the release's SHA-256 and fail closed; release assets now ship a
  `.sha256`. GitHub Actions are pinned to commit SHAs and run with least privilege.

### Reliability
- **Logins are verified.** After the portal accepts a login, `ccp` re-probes until the
  internet is really reachable. Previously any 200/30x page without a known error phrase
  counted as success, so an unrecognised error wording could re-submit a bad password every
  30 s indefinitely.
- New circuit-breaker trigger: three "accepted but still locked" results halt automatic
  login. The counter is persisted, so restarts can't reset it.
- Manual `ccp` now honours and sets the circuit breaker (it used to bypass it).
- The login request gets its own, longer timeout (10 s instead of 2.5 s) and is never
  retried over HTTPS after a mere timeout (no double submit).
- Unix single-instance lock is now a real `flock` (it was a PID file with a start-up race);
  both platforms retry briefly so `ccp status` can't make a starting daemon think it lost.
- Wake-from-sleep is actually detected (wall-clock jump) instead of only IP changes.
- A single config directory (`CCP_CONFIG_DIR` overrides it); older locations still work.

### Behaviour changes
- **Wi-Fi auto-join is opt-in** (`ccp wifi add "<SSID>"`). `ccp` no longer turns the radio
  on, joins "any Wi-Fi-looking" profile, or retries every 10 s forever (now backs off to 2 min).
- Errors print once, with a non-zero exit code.

### New
- `ccp trust`, `ccp untrust`, `ccp wifi`, `ccp logs`, `ccp --version`, `ccp --help`.
- `ccp.log` (rotating, never contains passwords); richer `ccp status`.
- `CCP_DOWNLOAD_BASE` / `CCP_SKIP_VERIFY` for the install scripts.

### Housekeeping
- `rust-version = 1.89` (verified in CI), release profile with LTO + strip, `--locked` in CI.
- Fixed a clippy lint that failed the repo's own `-D warnings` gate on current Rust.
- 35 -> 75 tests, including end-to-end daemon tests against a mock portal.
