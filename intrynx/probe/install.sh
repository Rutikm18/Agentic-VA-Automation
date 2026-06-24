#!/usr/bin/env bash
# Intrynx probe installer.
#   Docker (default):   ./install.sh
#   Native + systemd:   ./install.sh --native
# Reads configuration from ./probe.env (copy probe.env.example first).
set -euo pipefail

cd "$(dirname "$0")"
MODE="${1:-docker}"
ENV_FILE="probe.env"
IMAGE="intrynx-probe:local"
CONTAINER="intrynx-probe"
NUCLEI_VERSION="3.3.8"
HTTPX_VERSION="1.6.9"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "==> $ENV_FILE not found. Creating from example — edit it, then re-run."
  cp probe.env.example "$ENV_FILE"
  exit 1
fi

if [[ "$MODE" == "--native" || "$MODE" == "native" ]]; then
  # ── Native install (Linux + systemd) ──────────────────────────────────────
  command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
  echo "==> Installing Intrynx scan engines ..."
  sudo apt-get update -qq
  sudo apt-get install -y --no-install-recommends nmap sslscan masscan wget unzip >/dev/null 2>&1 || true

  # Additional scan-engine binaries (vuln_scan + web_scan)
  arch="$(dpkg --print-architecture)"
  for spec in "nuclei:${NUCLEI_VERSION}" "httpx:${HTTPX_VERSION}"; do
    name="${spec%%:*}"; ver="${spec##*:}"
    if ! command -v "$name" >/dev/null; then
      wget -qO "/tmp/${name}.zip" \
        "https://github.com/projectdiscovery/${name}/releases/download/v${ver}/${name}_${ver}_linux_${arch}.zip" \
        && sudo unzip -o "/tmp/${name}.zip" "${name}" -d /usr/local/bin >/dev/null && rm -f "/tmp/${name}.zip" || true
    fi
  done
  # SMB engine (smb_enum) — optional/heavy
  command -v nxc >/dev/null || pipx install netexec 2>/dev/null || pip install --user netexec 2>/dev/null || \
    echo "   (smb_enum engine unavailable — capability will be disabled)"

  PREFIX=/opt/intrynx-probe
  sudo mkdir -p "$PREFIX" /var/lib/adversa-probe
  sudo cp agent.py "$PREFIX/agent.py"
  sudo cp -r scanners "$PREFIX/scanners"
  sudo cp -r security "$PREFIX/security"
  sudo python3 -m venv "$PREFIX/.venv"
  sudo "$PREFIX/.venv/bin/pip" install --quiet -r requirements.txt
  sudo cp "$ENV_FILE" "$PREFIX/probe.env"

  sudo tee /etc/systemd/system/intrynx-probe.service >/dev/null <<UNIT
[Unit]
Description=Intrynx scanning probe
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$PREFIX
EnvironmentFile=$PREFIX/probe.env
ExecStart=$PREFIX/.venv/bin/python $PREFIX/agent.py
Restart=always
RestartSec=10
# nmap SYN scans need raw sockets:
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
UNIT

  sudo systemctl daemon-reload
  sudo systemctl enable --now intrynx-probe
  echo "==> Probe installed. Logs: journalctl -u intrynx-probe -f"
else
  # ── Docker install (default) ──────────────────────────────────────────────
  command -v docker >/dev/null || { echo "docker is required"; exit 1; }
  echo "==> Building $IMAGE (bundles all Intrynx scan engines)"
  docker build -t "$IMAGE" .
  docker rm -f "$CONTAINER" 2>/dev/null || true
  echo "==> Starting $CONTAINER"
  docker run -d --name "$CONTAINER" \
    --restart unless-stopped \
    --env-file "$ENV_FILE" \
    -v intrynx-probe-state:/var/lib/adversa-probe \
    "$IMAGE"
  echo "==> Probe running. Logs: docker logs -f $CONTAINER"
fi
