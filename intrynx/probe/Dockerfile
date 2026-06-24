FROM python:3.12-slim
WORKDIR /opt/intrynx-probe
ENV PYTHONUNBUFFERED=1 STATE_FILE=/var/lib/adversa-probe/state.json

# Pinned ProjectDiscovery tool versions.
ARG NUCLEI_VERSION=3.3.8
ARG HTTPX_VERSION=1.6.9
# Set to 0 to skip the heavy SMB/AD tool (netexec). smb_enum degrades gracefully.
ARG INSTALL_SMB=1

# ── Scan engines ──────────────────────────────────────────────────────────────
# apt: nmap (discovery/port_scan), sslscan (tls_scan), masscan (fast port sweep).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap sslscan masscan ca-certificates wget unzip \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/adversa-probe

# nuclei (vuln_scan) + httpx (web_scan) — ProjectDiscovery release binaries.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    for spec in "nuclei:${NUCLEI_VERSION}" "httpx:${HTTPX_VERSION}"; do \
      name="${spec%%:*}"; ver="${spec##*:}"; \
      wget -qO "/tmp/${name}.zip" \
        "https://github.com/projectdiscovery/${name}/releases/download/v${ver}/${name}_${ver}_linux_${arch}.zip"; \
      unzip -o "/tmp/${name}.zip" "${name}" -d /usr/local/bin; \
      chmod +x "/usr/local/bin/${name}"; rm "/tmp/${name}.zip"; \
    done

# netexec (smb_enum) — install from GitHub source (not on PyPI for all platforms).
# Best-effort: the image always builds even if this step fails.
RUN if [ "$INSTALL_SMB" = "1" ]; then \
      pip install --no-cache-dir \
        "git+https://github.com/Pennyw0rth/NetExec" \
      || echo "WARN: netexec install failed — smb_enum disabled"; \
    fi

# ── Probe code ────────────────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy every module the agent needs (toolchain was historically missing — fixed).
COPY agent.py .
COPY toolchain.py .
COPY probe_logger.py .
COPY scanners ./scanners
COPY security ./security

CMD ["python", "agent.py"]
