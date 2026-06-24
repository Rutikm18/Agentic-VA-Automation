# Probe service installers (T12)

Packages the compiled binary (T11) as a background service per OS, with a **least-privilege
default** and a single config file for the enroll token. Manager URL + cert/signing pins are
baked into the binary, so an install only needs the one-time token.

## Config (all platforms)
The binary loads a `KEY=VALUE` file on startup (`probe/config.py: _load_env_file`):

| OS | Path |
|----|------|
| Linux | `/etc/netagent/netagent.env` |
| macOS | `/Library/Application Support/netagent/netagent.env` |
| Windows | `%ProgramData%\netagent\netagent.env` |

Override with `PROBE_CONFIG=/path`. Typically holds just `PROBE_ENROLL_TOKEN=…` (remove after
first enrollment). Verified: the binary reads `PROBE_MANAGER_URL`/`PROBE_ENROLL_TOKEN` from it.

## Build & install

**Linux (.deb/.rpm)** — `gem install fpm`, then on Linux:
```bash
packaging/linux/build_linux.sh dist/netagent-linux-x86_64 1.0.0 amd64
sudo apt install ./netagent-1.0.0-amd64.deb     # or: rpm -i …
sudoedit /etc/netagent/netagent.env ; systemctl start netagent
```
Runs as the unprivileged **`netagent`** system user. Connect-scan needs no privileges; for
ICMP/ARP discovery grant **only** `CAP_NET_RAW` (uncomment in `netagent.service`) — never full root.

**macOS (.pkg)** — on macOS:
```bash
packaging/macos/build_pkg.sh dist/netagent-macos-arm64 1.0.0
sudo installer -pkg netagent-1.0.0-macos-arm64.pkg -target /
sudo vi "/Library/Application Support/netagent/netagent.env"
```
Installs a LaunchDaemon (auto-start, KeepAlive). **Validated here**: the `.pkg` builds and its
payload places the binary, plist, and config template correctly.

**Windows (.msi or script)** — on Windows, as Administrator:
```powershell
# quick: sc.exe-based installer
packaging\windows\install-service.ps1 -Binary .\netagent-windows-x64.exe -EnrollToken "<token>"
# production: WiX → signed .msi (packaging\windows\netagent.wxs)
```
Runs as **`LocalService`** (least privilege). Data dir ACL'd to SYSTEM/Admins.

## Signing / notarization (needs your certs)
| OS | Step |
|----|------|
| macOS | `productsign --sign 'Developer ID Installer: <Org>'` → `notarytool submit --wait` → `stapler staple` |
| Windows | `signtool sign /fd SHA256 /tr <ts> /td SHA256 /f cert.pfx .msi` (EV cert → instant SmartScreen rep) |
| Linux | `dpkg-sig` / `rpmsign`, or serve from a GPG-signed apt/yum repo |

Unsigned packages that install a scanner service get flagged by Gatekeeper/SmartScreen/EDR —
sign everything and allowlist during onboarding. CI wiring lives in
`.github/workflows/build-probe.yml` (build → sign → upload).

## Least-privilege summary
| OS | Account | Raw-socket discovery |
|----|---------|----------------------|
| Linux | `netagent` system user | opt-in `CAP_NET_RAW` only |
| macOS | root (LaunchDaemon) | available (note: tighten if connect-scan suffices) |
| Windows | `LocalService` | not granted (connect-scan) |
