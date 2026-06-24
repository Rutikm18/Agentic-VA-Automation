#!/usr/bin/env bash
# ADVERSA — one-stop runner script
# Usage: ./run.sh <command>
#   check     verify Node + scanner tools + env vars
#   setup     install npm deps, create .env.local if missing
#   start     launch the Next.js API server (port 3000)
#   stop      kill the API server if it's running
#   cli ...   pass remaining args to the CLI (e.g. ./run.sh cli scan 10.0.0.5)
#   demo      end-to-end demo: server + login + scan on 127.0.0.1
#   help      print this help

set -euo pipefail

# ── Resolve script directory (so we can run from anywhere) ──────────
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# ── ANSI colors ─────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'; C_RED=$'\e[1;31m'
  C_GREEN=$'\e[1;32m'; C_YELLOW=$'\e[33m'; C_CYAN=$'\e[1;36m'; C_RESET=$'\e[0m'
else
  C_BOLD=''; C_DIM=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_CYAN=''; C_RESET=''
fi

ok()   { printf "  ${C_GREEN}✓${C_RESET} %s\n" "$*"; }
warn() { printf "  ${C_YELLOW}!${C_RESET} %s\n" "$*"; }
fail() { printf "  ${C_RED}✗${C_RESET} %s\n" "$*"; }
info() { printf "  ${C_DIM}%s${C_RESET}\n" "$*"; }
hdr()  { printf "\n${C_CYAN}── %s ──${C_RESET}\n\n" "$*"; }

PID_FILE=".adversa-server.pid"
LOG_FILE=".adversa-server.log"

# ── check: verify prerequisites ─────────────────────────────────────
cmd_check() {
  hdr "Checking prerequisites"

  local missing=0

  # Node.js ≥ 20
  if command -v node >/dev/null 2>&1; then
    local v
    v=$(node -v | sed 's/v//' | cut -d. -f1)
    if (( v >= 20 )); then
      ok "Node.js $(node -v)"
    else
      fail "Node.js $(node -v) — need ≥ 20"
      missing=1
    fi
  else
    fail "Node.js not installed"
    missing=1
  fi

  # npm
  if command -v npm >/dev/null 2>&1; then
    ok "npm $(npm -v)"
  else
    fail "npm not installed"
    missing=1
  fi

  echo
  info "Scanner tools (missing tools just skip their stage — not fatal)"

  for tool in naabu nmap nuclei testssl.sh; do
    if command -v "$tool" >/dev/null 2>&1; then
      ok "$tool found at $(command -v "$tool")"
    else
      warn "$tool not installed (related scan stage will be skipped)"
    fi
  done

  echo
  info "Environment"

  if [[ -f .env.local ]]; then
    ok ".env.local present"
    # Check key env vars are non-empty
    for key in ANTHROPIC_API_KEY AUTH_SECRET SCOPE_SECRET AGENT_SECRET; do
      if grep -q "^${key}=." .env.local 2>/dev/null; then
        ok "$key set"
      else
        warn "$key not set in .env.local"
      fi
    done
  else
    fail ".env.local missing — run: ./run.sh setup"
    missing=1
  fi

  # Node modules
  if [[ -d node_modules ]]; then
    ok "node_modules present"
  else
    warn "node_modules missing — run: ./run.sh setup"
  fi

  echo
  if (( missing > 0 )); then
    fail "Some critical prerequisites are missing."
    exit 1
  fi
  ok "Ready to run."
}

# ── setup: delegate to the smart installer ──────────────────────────
cmd_setup() {
  exec ./install.sh "$@"
}

# ── doctor: full system health check via the CLI ────────────────────
cmd_doctor() {
  npx tsx cli/index.ts doctor "$@"
}

# ── start: launch the dev server in background ──────────────────────
cmd_start() {
  hdr "Starting ADVERSA API server"

  if [[ -f $PID_FILE ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    warn "Server already running (PID $(cat "$PID_FILE"))"
    info "Logs:  tail -f $LOG_FILE"
    info "Stop:  ./run.sh stop"
    return
  fi

  if [[ ! -d node_modules ]]; then
    fail "node_modules missing — run: ./run.sh setup"
    exit 1
  fi

  info "Booting Next.js (npm run dev)…"
  nohup npm run dev > "$LOG_FILE" 2>&1 &
  echo $! > "$PID_FILE"

  # Wait for server to respond on port 3000 (max 30s)
  local port=3000
  local waited=0
  while (( waited < 30 )); do
    if curl -fsS "http://localhost:${port}" >/dev/null 2>&1 \
       || curl -fsS "http://localhost:${port}/api/auth/me" >/dev/null 2>&1 \
       || nc -z localhost "$port" 2>/dev/null; then
      ok "Server up at http://localhost:${port}  (PID $(cat "$PID_FILE"))"
      info "Logs:  tail -f $LOG_FILE"
      info "Stop:  ./run.sh stop"
      info "App:   ./run.sh app   ${C_DIM}(interactive menu — no commands to remember)${C_RESET}"
      return
    fi
    sleep 1
    waited=$((waited + 1))
  done

  fail "Server did not respond within 30s — check $LOG_FILE"
  exit 1
}

# ── stop: kill background server ────────────────────────────────────
cmd_stop() {
  hdr "Stopping ADVERSA API server"

  if [[ ! -f $PID_FILE ]]; then
    warn "No PID file — server not started by this script"
    info "Manual kill: pkill -f 'next dev'"
    return
  fi

  local pid
  pid=$(cat "$PID_FILE")
  if kill -0 "$pid" 2>/dev/null; then
    # next dev spawns children — kill the whole process group
    pkill -P "$pid" 2>/dev/null || true
    kill "$pid" 2>/dev/null || true
    ok "Stopped (PID $pid)"
  else
    warn "PID $pid not running"
  fi
  rm -f "$PID_FILE"
}

# ── cli: pass args through to the CLI ───────────────────────────────
cmd_cli() {
  npx tsx cli/index.ts "$@"
}

# ── app: launch the interactive wizard (no args = default menu) ────
cmd_app() {
  npx tsx cli/index.ts
}

# ── demo: end-to-end smoke test ─────────────────────────────────────
cmd_demo() {
  hdr "ADVERSA end-to-end demo"

  info "Step 1/4 — checking prerequisites"
  cmd_check
  echo

  info "Step 2/4 — starting server"
  cmd_start
  echo

  info "Step 3/4 — login (interactive)"
  info "Server is up. Now run these by hand:"
  echo
  printf "  ${C_BOLD}./run.sh cli login${C_RESET}                              ${C_DIM}# email + OTP (dev mode prints OTP)${C_RESET}\n"
  printf "  ${C_BOLD}./run.sh cli engagement create \\${C_RESET}\n"
  printf "  ${C_BOLD}    --name 'Demo' --client 'Internal' \\${C_RESET}\n"
  printf "  ${C_BOLD}    --start $(date +%%Y-%%m-%%d) --end $(date -v+7d +%%Y-%%m-%%d 2>/dev/null || date -d '+7 days' +%%Y-%%m-%%d) \\${C_RESET}\n"
  printf "  ${C_BOLD}    --scope '127.0.0.1/32'${C_RESET}\n"
  printf "  ${C_BOLD}./run.sh cli scan 127.0.0.1 --profile fast --save${C_RESET}  ${C_DIM}# watch the AI commentary${C_RESET}\n"
  printf "  ${C_BOLD}./run.sh cli findings stats${C_RESET}\n"
  printf "  ${C_BOLD}./run.sh cli ask \"summarize the top risks\"${C_RESET}\n"
  printf "  ${C_BOLD}./run.sh cli report ENG-001 -o demo-report.json${C_RESET}\n"
  echo
  info "When done:  ./run.sh stop"
}

# ── help ────────────────────────────────────────────────────────────
cmd_help() {
  cat <<EOF

${C_CYAN}ADVERSA${C_RESET} — Network VAPT Platform runner

${C_BOLD}USAGE${C_RESET}
  ./run.sh <command> [args]

${C_BOLD}COMMANDS${C_RESET}
  setup         Full install — Node, Go, scanners, deps, .env.local (idempotent)
  check         Quick prereq verify (use \`doctor\` for the full check)
  doctor        Full health check with per-component fixes
  start         Launch the Next.js API server in the background
  stop          Stop the API server
  app           Launch the interactive wizard (menu-driven, no commands to remember)
  cli <args>    Pass through to the CLI for power users (e.g. ./run.sh cli scan 10.0.0.5)
  demo          Print the full end-to-end demo sequence
  help          Show this message

${C_BOLD}TYPICAL FIRST RUN${C_RESET}
  ./run.sh setup
  # Edit .env.local — set ANTHROPIC_API_KEY for AI features
  ./run.sh check
  ./run.sh start
  ./run.sh cli login                          # email + OTP
  ./run.sh cli scan 127.0.0.1 --profile fast  # first scan

${C_BOLD}USEFUL CLI INVOCATIONS${C_RESET}
  ./run.sh cli scan 10.0.0.0/24 --profile standard --save
  ./run.sh cli findings --severity critical
  ./run.sh cli ask "what's the fastest path to domain admin?"
  ./run.sh cli engagement list
  ./run.sh cli report ENG-001 -o report.json
  ./run.sh cli admin add-user alice@acme.com --scope "10.0.0.0/16"

EOF
}

# ── Dispatch ────────────────────────────────────────────────────────
case "${1:-help}" in
  check)        cmd_check ;;
  setup)        shift; cmd_setup "$@" ;;
  doctor)       shift; cmd_doctor "$@" ;;
  start)        cmd_start ;;
  stop)         cmd_stop ;;
  app)          cmd_app ;;
  cli)          shift; cmd_cli "$@" ;;
  demo)         cmd_demo ;;
  help|-h|--help) cmd_help ;;
  *)
    fail "Unknown command: $1"
    cmd_help
    exit 1
    ;;
esac
