# ─────────────────────────────────────────────────────────────────────────────
# ADVERSA Platform — Dockerfile
# Multi-stage build:  deps → builder → runner
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: install production + dev deps ───────────────────────────────────
FROM node:22-alpine AS deps
WORKDIR /app

COPY package.json package-lock.json* ./

# ci install is reproducible; uses lockfile exactly (includes tsx + commander for CLI)
RUN npm ci

# ── Stage 2: build Next.js standalone bundle ─────────────────────────────────
FROM node:22-alpine AS builder
WORKDIR /app

# Copy deps from previous stage
COPY --from=deps /app/node_modules ./node_modules
COPY . .

ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=production

RUN npm run build

# ── Stage 3: minimal production runner ───────────────────────────────────────
FROM node:22-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# Non-root user for security
RUN addgroup --system --gid 1001 nodejs \
 && adduser  --system --uid 1001 nextjs

# Writable data directory for findings/cases JSON stores
RUN mkdir -p /app/data && chown nextjs:nodejs /app/data

# ── Scanning tools ───────────────────────────────────────────────────────────
# nmap — service/OS fingerprinting, NSE vuln scripts
RUN apk add --no-cache nmap nmap-scripts bash curl unzip ca-certificates openssl

# naabu — fast port scanner (pure-Go static binary, works on Alpine)
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') && \
    curl -sSfL "https://github.com/projectdiscovery/naabu/releases/download/v2.6.1/naabu_2.6.1_linux_${ARCH}.zip" \
      -o /tmp/naabu.zip && \
    unzip -q /tmp/naabu.zip naabu -d /usr/local/bin && \
    rm /tmp/naabu.zip && chmod +x /usr/local/bin/naabu

# nuclei — CVE/misconfiguration scanner, pre-fetch templates into /opt
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') && \
    curl -sSfL "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.2/nuclei_3.3.2_linux_${ARCH}.zip" \
      -o /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin && \
    rm /tmp/nuclei.zip && chmod +x /usr/local/bin/nuclei && \
    mkdir -p /opt/nuclei-templates /opt/.config/nuclei /opt/.local && \
    HOME=/opt nuclei -update-templates -silent 2>/dev/null || true && \
    chmod -R o+rX  /opt/nuclei-templates 2>/dev/null || true && \
    chmod -R o+rwX /opt/.config /opt/.local 2>/dev/null || true

# testssl.sh — TLS cipher/cert analysis
RUN curl -sSfL https://raw.githubusercontent.com/drwetter/testssl.sh/3.2/testssl.sh \
      -o /usr/local/bin/testssl.sh && chmod +x /usr/local/bin/testssl.sh

# Copy the standalone output (self-contained Node server)
COPY --from=builder /app/public                           ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static     ./.next/static

# ── CLI — install node_modules for tsx runner ────────────────────────────────
# Copy devDeps (tsx, commander) so the CLI works inside the container
COPY --from=deps /app/node_modules ./node_modules
COPY cli    ./cli
COPY lib    ./lib
COPY bin    ./bin
COPY tsconfig.cli.json ./

# Link 'adversa' so it's on PATH for the nextjs user too
RUN chmod +x /app/bin/adversa && ln -sf /app/bin/adversa /usr/local/bin/adversa

USER nextjs

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/ || exit 1

CMD ["node", "server.js"]
