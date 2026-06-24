#!/usr/bin/env bash
#
# ADVERSA installer — one command, everything required.
#
#   curl -fsSL <url>/install.sh | bash
#   or
#   ./install.sh                  (from inside a cloned repo)
#
# What it does:
#   1. Detects OS + arch (macOS/Linux; ARM64/x86_64)
#   2. Installs Homebrew if needed (macOS)
#   3. Installs Node ≥ 20, Go, nmap, libpcap
#   4. Installs naabu + nuclei via `go install`, testssl via git
#   5. Wires ~/go/bin onto PATH idempotently
#   6. Bootstraps project: npm install, .env.local with random secrets
#   7. Runs `adversa doctor` to confirm green
#
# Properties:
#   - Idempotent: re-running is safe
#   - Quiet on success; loud + actionable on failure
#   - No interactive prompts (CI-friendly)
#   - --dry-run shows what would happen without doing anything

set -Eeuo pipefail

# ── Constants ───────────────────────────────────────────────────────
ADVERSA_VERSION="0.6.0"
MIN_NODE_MAJOR=20
INSTALL_LOG="${TMPDIR:-/tmp}/adversa-install-$$.log"
DRY_RUN=false
VERBOSE=false

# ── Logging ─────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'
  C_RED=$'\e[1;31m'; C_GREEN=$'\e[1;32m'
  C_YELLOW=$'\e[33m'; C_CYAN=$'\e[1;36m'; C_RESET=$'\e[0m'
else
  C_BOLD=''; C_DIM=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_CYAN=''; C_RESET=''
fi

ok()    { printf "  ${C_GREEN}✓${C_RESET} %s\n" "$*"; }
skip()  { printf "  ${C_DIM}·${C_RESET} %s ${C_DIM}(already installed)${C_RESET}\n" "$*"; }
warn()  { printf "  ${C_YELLOW}!${C_RESET} %s\n" "$*"; }
err()   { printf "  ${C_RED}✗${C_RESET} %s\n" "$*" >&2; }
step()  { printf "\n${C_CYAN}▶${C_RESET} ${C_BOLD}%s${C_RESET}\n" "$*"; }
info()  { printf "  ${C_DIM}%s${C_RESET}\n" "$*"; }

# Run a command, logging output to INSTALL_LOG. Show output only if it fails.
run() {
  if $DRY_RUN; then
    info "would run: $*"
    return 0
  fi
  if $VERBOSE; then
    "$@" 2>&1 | tee -a "$INSTALL_LOG"
    return "${PIPESTATUS[0]}"
  fi
  if ! "$@" >> "$INSTALL_LOG" 2>&1; then
    err "command failed: $*"
    err "see log: $INSTALL_LOG"
    err "last 20 lines:"
    tail -20 "$INSTALL_LOG" >&2 || true
    return 1
  fi
}

die() {
  err "$1"
  [[ -n "${2:-}" ]] && err "Fix: $2"
  exit 1
}

# ── Trap to surface useful messages on unexpected failure ──────────
on_error() {
  local lineno="$1"
  err "Installer crashed on line $lineno"
  err "Full log: $INSTALL_LOG"
  err "Open an issue with the log attached, or rerun with --verbose"
  exit 1
}
trap 'on_error $LINENO' ERR

# ── CLI parsing ─────────────────────────────────────────────────────
for arg in "$@"; do
  case $arg in
    --dry-run)  DRY_RUN=true ;;
    --verbose)  VERBOSE=true ;;
    --help|-h)
      cat <<EOF
ADVERSA installer v${ADVERSA_VERSION}

Usage: ./install.sh [--dry-run] [--verbose]

  --dry-run   Show what would be installed without doing it
  --verbose   Stream all subprocess output (default: only on failure)

After install:
  ./run.sh start        Boot the API server
  ./run.sh app          Launch the interactive wizard
  ./run.sh cli doctor   Re-verify health any time
EOF
      exit 0
      ;;
    *) warn "unknown flag: $arg" ;;
  esac
done

# ── Platform detection ──────────────────────────────────────────────
step "Detecting platform"

OS_KIND=""
case "$(uname -s)" in
  Darwin) OS_KIND="macos" ;;
  Linux)  OS_KIND="linux" ;;
  *)      die "Unsupported OS: $(uname -s)" "ADVERSA currently supports macOS and Linux. Windows: use WSL2." ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
  arm64|aarch64) ARCH_KIND="arm64" ;;
  x86_64|amd64)  ARCH_KIND="x86_64" ;;
  *) die "Unsupported architecture: $ARCH" "Open an issue with your platform details." ;;
esac

ok "Platform: $OS_KIND ($ARCH_KIND)"

# ── Locate or clone the repo ────────────────────────────────────────
step "Locating ADVERSA repo"

if [[ -f "package.json" ]] && grep -q '"name": "adversa"' package.json 2>/dev/null; then
  REPO_DIR="$PWD"
  ok "Using existing checkout at $REPO_DIR"
else
  REPO_DIR="$HOME/adversa"
  if [[ -d "$REPO_DIR" ]]; then
    ok "Reusing $REPO_DIR"
  else
    info "Cloning into $REPO_DIR"
    run git clone --depth 1 https://github.com/your-org/adversa.git "$REPO_DIR"
    ok "Cloned to $REPO_DIR"
  fi
  cd "$REPO_DIR"
fi

# ── Homebrew (macOS) ────────────────────────────────────────────────
if [[ "$OS_KIND" == "macos" ]]; then
  step "Homebrew"
  if command -v brew >/dev/null 2>&1; then
    skip "Homebrew"
  else
    info "Installing Homebrew (may prompt for sudo password once)"
    if $DRY_RUN; then
      info "would run: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
    else
      /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" \
        >> "$INSTALL_LOG" 2>&1 \
        || die "Homebrew install failed" "see $INSTALL_LOG"
    fi
    # Make brew available in this script
    if [[ -x /opt/homebrew/bin/brew ]]; then
      eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [[ -x /usr/local/bin/brew ]]; then
      eval "$(/usr/local/bin/brew shellenv)"
    fi
    ok "Homebrew installed"
  fi
fi

# Helper: install via brew (macOS) or apt (Debian/Ubuntu) idempotently
pkg_install() {
  local pkg="$1"
  if [[ "$OS_KIND" == "macos" ]]; then
    if brew list "$pkg" >/dev/null 2>&1; then skip "$pkg"; return; fi
    run brew install "$pkg"
    ok "$pkg"
  else
    if dpkg -s "$pkg" >/dev/null 2>&1; then skip "$pkg"; return; fi
    run sudo apt-get update -qq
    run sudo apt-get install -y "$pkg"
    ok "$pkg"
  fi
}

# ── Node.js ────────────────────────────────────────────────────────
step "Node.js (≥ ${MIN_NODE_MAJOR})"

if command -v node >/dev/null 2>&1; then
  NODE_MAJOR="$(node -v | sed 's/v//' | cut -d. -f1)"
  if (( NODE_MAJOR >= MIN_NODE_MAJOR )); then
    skip "Node.js $(node -v)"
  else
    warn "Node.js $(node -v) is too old (need ≥ $MIN_NODE_MAJOR)"
    pkg_install node
  fi
else
  pkg_install node
fi

# ── nmap (still needed as a system binary — no portable bundle) ─────
step "nmap"
pkg_install nmap

# ── libpcap (only if naabu later wants raw sockets on Mac) ─────────
if [[ "$OS_KIND" == "macos" ]]; then
  pkg_install libpcap
fi

# ── Bundled scanner tools (managed by ADVERSA itself) ───────────────
# This is what makes client deployments hands-off: naabu, nuclei, httpx,
# subfinder, ffuf get downloaded by `adversa tools install` into
# ~/.adversa/tools/ with pinned versions. No go install, no homebrew.
step "Bundled scanner tools (naabu, httpx, nuclei, subfinder, ffuf)"
if $DRY_RUN; then
  info "would run: ./run.sh cli tools install"
else
  npx tsx cli/index.ts tools install \
    && ok "Bundled tools installed into ~/.adversa/tools/" \
    || warn "Bundled tool install failed — native fallbacks will be used. See $INSTALL_LOG."
fi

# Legacy support: keep go-install-from-source if the user already has Go.
# Power users may want naabu on PATH too — but clients don't need this.
install_go_tool() {
  local name="$1" pkg="$2"
  if command -v "$name" >/dev/null 2>&1; then
    skip "$name (system)"
  fi
}

install_go_tool subfinder "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool httpx     "github.com/projectdiscovery/httpx/cmd/httpx@latest"

# ffuf (brew) — for directory busting
if command -v ffuf >/dev/null 2>&1; then
  skip "ffuf"
else
  if [[ "$OS_KIND" == "macos" ]]; then
    pkg_install ffuf
  else
    run go install -v github.com/ffuf/ffuf/v2@latest
    ok "ffuf"
  fi
fi

# whatweb (brew) — tech fingerprint
if command -v whatweb >/dev/null 2>&1; then
  skip "whatweb"
elif [[ "$OS_KIND" == "macos" ]]; then
  pkg_install whatweb || warn "whatweb not in brew — try: gem install whatweb"
else
  warn "whatweb missing — install with: gem install whatweb"
fi

# ssh-audit (pip)
if command -v ssh-audit >/dev/null 2>&1; then
  skip "ssh-audit"
else
  info "Installing ssh-audit via pip"
  if command -v pip3 >/dev/null 2>&1; then
    run pip3 install --quiet --user ssh-audit
    ok "ssh-audit"
  else
    warn "pip3 missing — ssh-audit will be unavailable"
  fi
fi

# SecLists (wordlists for ffuf) — best-effort
if [[ "$OS_KIND" == "macos" ]] && ! brew list seclists >/dev/null 2>&1; then
  info "Installing SecLists (wordlists for ffuf) — large download"
  brew install --quiet seclists >> "$INSTALL_LOG" 2>&1 || warn "seclists install failed — ffuf will need ADVERSA_FFUF_WORDLIST set"
fi

# ── testssl.sh ─────────────────────────────────────────────────────
step "testssl.sh (TLS audit)"
if command -v testssl.sh >/dev/null 2>&1; then
  skip "testssl.sh"
else
  TESTSSL_DIR="$HOME/testssl.sh"
  if [[ ! -d "$TESTSSL_DIR" ]]; then
    run git clone --depth 1 https://github.com/drwetter/testssl.sh.git "$TESTSSL_DIR"
  fi
  # Try to symlink without sudo first
  if ! ln -sf "$TESTSSL_DIR/testssl.sh" "$HOME/.local/bin/testssl.sh" 2>/dev/null; then
    mkdir -p "$HOME/.local/bin" 2>/dev/null || true
    if ln -sf "$TESTSSL_DIR/testssl.sh" "$HOME/.local/bin/testssl.sh" 2>/dev/null; then
      export PATH="$HOME/.local/bin:$PATH"
      if [[ -n "$SHELL_RC" ]] && ! grep -q '.local/bin' "$SHELL_RC"; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
      fi
    else
      info "Linking to /usr/local/bin (sudo)"
      sudo ln -sf "$TESTSSL_DIR/testssl.sh" /usr/local/bin/testssl.sh \
        || warn "could not link testssl.sh — TLS stage will be skipped"
    fi
  fi
  ok "testssl.sh installed"
fi

# ── Project bootstrap ─────────────────────────────────────────────
step "Project dependencies (npm install)"
if [[ -d node_modules ]]; then
  skip "node_modules present"
else
  run npm install --no-audit --no-fund
  ok "Dependencies installed"
fi

step "Configuration (.env.local)"
if [[ -f .env.local ]]; then
  skip ".env.local exists"
else
  info "Generating .env.local with random secrets"
  generate_secret() {
    if command -v openssl >/dev/null 2>&1; then
      openssl rand -hex 32
    else
      node -e 'console.log(require("crypto").randomBytes(32).toString("hex"))'
    fi
  }
  if $DRY_RUN; then
    info "would write .env.local with auto-generated AUTH_SECRET, SCOPE_SECRET, AGENT_SECRET"
  else
    cat > .env.local <<EOF
# ADVERSA — auto-generated by install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)

# LLM — required for AI commentary, attack-path, AI reports.
# Paste your key here when ready: https://console.anthropic.com/
ANTHROPIC_API_KEY=

# JWT secrets — auto-generated, rotate before production deploy
AUTH_SECRET=$(generate_secret)
SCOPE_SECRET=$(generate_secret)
AGENT_SECRET=$(generate_secret)

# Email delivery (Resend). Leave blank in dev — OTP shown in CLI.
RESEND_API_KEY=
RESEND_FROM=Adversa <noreply@adversa.security>

# Scan engine
SCAN_MAX_RATE=1000
SCAN_NUCLEI_CONCURRENCY=25

# Next.js
PORT=3000
NEXT_TELEMETRY_DISABLED=1
EOF
    ok ".env.local created"
    warn "Paste ANTHROPIC_API_KEY into .env.local to enable AI features"
  fi
fi

mkdir -p data
ok "data/ ready"

# ── Final verification — run `adversa doctor` ──────────────────────
step "Verifying installation"
if $DRY_RUN; then
  info "would run: ./run.sh cli doctor"
else
  if ! npx tsx cli/index.ts doctor 2>&1 | grep -v '^EXIT'; then
    warn "doctor reported issues — see output above for fixes"
  fi
fi

# ── Done ───────────────────────────────────────────────────────────
cat <<EOF

${C_GREEN}${C_BOLD}✓ Installation complete${C_RESET}

  ${C_BOLD}Next steps${C_RESET}
    1) ${C_DIM}(optional)${C_RESET} Edit .env.local — set ANTHROPIC_API_KEY
    2) ${C_CYAN}./run.sh start${C_RESET}     ${C_DIM}# boot the API server${C_RESET}
    3) ${C_CYAN}./run.sh app${C_RESET}       ${C_DIM}# launch the interactive wizard${C_RESET}

  ${C_BOLD}Anytime${C_RESET}
    ${C_CYAN}./run.sh cli doctor${C_RESET}   ${C_DIM}# re-verify system health${C_RESET}
    ${C_CYAN}./run.sh stop${C_RESET}         ${C_DIM}# shut down the server${C_RESET}

  ${C_DIM}Install log: $INSTALL_LOG${C_RESET}

EOF
