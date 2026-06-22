#!/usr/bin/env bash
# test_all.sh — single-command smoke test for the whole scanner_module.
#
# Runs every scanner standalone (real CLI invocation, real output) plus the
# run_scan.py orchestrator, against one target, and prints a pass/fail summary
# at the end. This is the one-command version of the manual test matrix.
#
# Usage:
#   ./test_all.sh                       # defaults to 127.0.0.1
#   ./test_all.sh 10.0.0.5              # your own authorized target
#   ./test_all.sh 10.0.0.0/24 scope.txt # CIDR + an existing scope file
#
# Credentialed collectors (ssh_collector, windows_collector) are opt-in only,
# since they need real credentials against a real host — see env vars below.

set -u
cd "$(dirname "$0")"

TARGET="${1:-127.0.0.1}"
SCOPE="${2:-}"
OUTDIR="$(mktemp -d /tmp/va_test_all.XXXXXX)"
AUTO_SCOPE=0

if [ -z "$SCOPE" ]; then
    SCOPE="$OUTDIR/scope.txt"
    echo "$TARGET" > "$SCOPE"
    AUTO_SCOPE=1
fi

PASS=0
FAIL=0
FAILED_STEPS=()

section() {
    echo
    echo "================================================================"
    echo "  $1"
    echo "================================================================"
}

run_step() {
    local label="$1"; shift
    section "$label"
    if "$@"; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        FAILED_STEPS+=("$label")
    fi
}

skip_step() {
    section "$1"
    echo "skipped — $2"
}

echo "target: $TARGET"
echo "scope:  $SCOPE$( [ "$AUTO_SCOPE" = 1 ] && echo ' (auto-created, allows only this target)' )"
echo "scratch dir: $OUTDIR"

run_step "host_discovery"  python3 -m scanner.host_discovery -t "$TARGET" -s "$SCOPE"
run_step "port_scanner"    python3 -m scanner.port_scanner   -t "$TARGET" -s "$SCOPE"
run_step "service_banner"  python3 -m scanner.service_banner -t "$TARGET" -s "$SCOPE" \
    -p 21,22,25,80,443,3306,3389,5432,6379,8080,8443
run_step "tls_scanner"     python3 -m scanner.tls_scanner    -t "$TARGET" -s "$SCOPE"
run_step "udp_scanner"     python3 -m scanner.udp_scanner    -t "$TARGET" -s "$SCOPE"
run_step "smb_scanner"     python3 -m scanner.smb_scanner    -t "$TARGET" -s "$SCOPE"
run_step "snmp_scanner"    python3 -m scanner.snmp_scanner   -t "$TARGET" -s "$SCOPE"
run_step "web_scanner"     python3 -m scanner.web_scanner    -t "$TARGET" -s "$SCOPE"
run_step "mcp_ai_scanner"  python3 -m scanner.mcp_ai_scanner -t "$TARGET" -s "$SCOPE"
run_step "db_scanner"      python3 -m scanner.db_scanner     -t "$TARGET" -s "$SCOPE"

if command -v nmap >/dev/null 2>&1; then
    run_step "nmap_wrapper (--profile fast, no root needed)" \
        python3 -m scanner.nmap_wrapper -t "$TARGET" -s "$SCOPE" --profile fast
else
    skip_step "nmap_wrapper" "nmap binary not found on PATH"
fi

run_step "mass_scan (--fallback, no root needed)" \
    python3 -m scanner.mass_scan -t "$TARGET" -s "$SCOPE" -p 1-1000 --fallback

run_step "run_scan.py orchestrator (--all --split-output)" \
    python3 run_scan.py -t "$TARGET" -s "$SCOPE" --all --split-output "$OUTDIR/runs"

# --- credentialed collectors: need real creds against a real host ---
if [ -n "${SSH_TEST_USER:-}" ] && [ -n "${SSH_TEST_KEY:-}" ]; then
    run_step "ssh_collector" python3 -m scanner.ssh_collector -t "$TARGET" -s "$SCOPE" \
        --user "$SSH_TEST_USER" --key "$SSH_TEST_KEY"
else
    skip_step "ssh_collector" \
        "set SSH_TEST_USER and SSH_TEST_KEY to test against a real authorized Linux host"
fi

if [ -n "${WIN_TEST_USER:-}" ] && [ -n "${WIN_SCAN_PASSWORD:-}" ]; then
    run_step "windows_collector" python3 -m scanner.windows_collector -t "$TARGET" -s "$SCOPE" \
        --user "$WIN_TEST_USER" --domain "${WIN_TEST_DOMAIN:-}"
else
    skip_step "windows_collector" \
        "set WIN_TEST_USER and WIN_SCAN_PASSWORD (+ optional WIN_TEST_DOMAIN) for a real Windows host"
fi

section "SUMMARY"
echo "ran cleanly: $PASS   exited with an error: $FAIL"
if [ "${#FAILED_STEPS[@]}" -gt 0 ]; then
    printf '  ! %s\n' "${FAILED_STEPS[@]}"
fi
if [ -d "$OUTDIR/runs" ]; then
    echo
    echo "orchestrator split-output (rows per scanner):"
    for f in "$OUTDIR"/runs/*.jsonl; do
        [ -e "$f" ] || continue
        printf '  %-20s %s\n' "$(basename "$f")" "$(wc -l < "$f" | tr -d ' ')"
    done
fi
echo
echo "full output saved under: $OUTDIR"
