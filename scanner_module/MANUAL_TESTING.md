# Manual Accuracy Testing Guide

How to verify each scanner one by one against **known ground truth**, and judge
accuracy yourself.

The method, for every scanner, is two questions:

1. **True positive** — did it find what is *really* there?
2. **False positive** — did it stay silent about what *isn't* there?

We set up local fixtures with known properties, snapshot the real truth
independently (so you trust your own eyes, not the "expected" notes here), then
run each scanner and compare.

All commands run from the module directory:

```bash
cd "/Users/rutikmangale/Documents/DRIVE T -Var/Security-projects/Agentic VA Scanner/scanner_module"
```

---

## STEP 0 — Set up known fixtures + scope

Paste this whole block once. It starts 3 local services with **known**
properties (plus your real MySQL on 3306 if you run one):

```bash
# scope: loopback + your LAN (so you can test against the router too)
printf '127.0.0.1\n172.18.30.0/24\n' > scope_test.txt

# Fixture A: HTTP server on 8080 with a known title
mkdir -p /tmp/vafix && printf '<html><head><title>GROUND-TRUTH-PAGE</title></head><body>hi</body></html>' > /tmp/vafix/index.html
( cd /tmp/vafix && python3 -m http.server 8080 --bind 127.0.0.1 >/tmp/vafix/http.log 2>&1 & )

# Fixture B: TLS 1.3/1.2 server on 8443
openssl req -x509 -newkey rsa:2048 -keyout /tmp/vafix/k.pem -out /tmp/vafix/c.pem -days 1 -nodes -subj "/CN=localhost" 2>/dev/null
( openssl s_server -key /tmp/vafix/k.pem -cert /tmp/vafix/c.pem -accept 8443 -www >/tmp/vafix/tls.log 2>&1 & )

# Fixture C: a fake banner service on 3389
cat > /tmp/vafix/banner.py <<'PY'
import socketserver
class H(socketserver.BaseRequestHandler):
    def handle(self):
        try: self.request.sendall(b"GROUND-TRUTH-BANNER-1.0\r\n")
        except OSError: pass
class S(socketserver.ThreadingTCPServer): allow_reuse_address=True
S(("127.0.0.1",3389),H).serve_forever()
PY
( python3 /tmp/vafix/banner.py >/tmp/vafix/banner.log 2>&1 & )
sleep 2
echo "fixtures started"
```

**Now snapshot the REAL truth independently:**

```bash
# what's actually listening on loopback:
lsof -nP -iTCP@127.0.0.1 -sTCP:LISTEN | awk 'NR==1 || /127.0.0.1/{print $1, $9}'
# confirm each fixture by hand:
curl -s http://127.0.0.1:8080/ | grep -o '<title>.*</title>'      # -> GROUND-TRUTH-PAGE
echo | openssl s_client -connect 127.0.0.1:8443 2>/dev/null | grep -i protocol   # -> TLSv1.3
nc 127.0.0.1 3389 <<< "" | head -c 40; echo                        # -> GROUND-TRUTH-BANNER-1.0
mysql --version 2>/dev/null || echo "(note your real mysql version if running on 3306)"
```

Your **answer key** is whatever is truly open. With the fixtures above plus a
running MySQL, that is: **3306 (mysql), 3389 (banner), 8080 (http), 8443 (tls)**.

---

## STEP 1 — host_discovery (is the host alive?)

```bash
python3 -m scanner.host_discovery -t 127.0.0.1 -s scope_test.txt
```

**Expect:** `"status":"open"`, `"alive": true`. The `responding_ports` list shows
ports as `open` or `refused` — both prove the host is alive.

---

## STEP 2 — port_scanner (which TCP ports are open?)

```bash
python3 -m scanner.port_scanner -t 127.0.0.1 -s scope_test.txt
```

**Accuracy check:** must report **exactly 3306, 3389, 8080, 8443** open.
- True positive: all 4 appear.
- False positive test: must **not** list ports you know are closed (22, 80, 445…).

Negative control (a port you know is closed → must print nothing):

```bash
python3 -m scanner.port_scanner -t 127.0.0.1 -s scope_test.txt -p 22
```

**Expect:** no result lines. Silence = correct (no false positive).

---

## STEP 3 — service_banner (what does each port say?)

```bash
python3 -m scanner.service_banner -t 127.0.0.1 -s scope_test.txt -p 3306,3389,8080,8443
```

**Accuracy check** (compare to your Step 0 snapshot):
- 3389 → banner `GROUND-TRUTH-BANNER-1.0` (verbatim match = accurate)
- 8080 → `HTTP/1.0 200 OK ... Server: SimpleHTTP`
- 3306 → MySQL handshake (binary, but the version string is visible)
- 8443 → a few TLS bytes (binary — correct, it is not a text service)

---

## STEP 4 — tls_scanner (TLS versions / ciphers)

```bash
python3 -m scanner.tls_scanner -t 127.0.0.1 -s scope_test.txt -p 8443
```

**Cross-verify:** compare `accepted_versions` to what `openssl s_client` reported
in Step 0 (`TLSv1.3`). Match = accurate.

Negative control (plain HTTP port is not TLS → must return nothing):

```bash
python3 -m scanner.tls_scanner -t 127.0.0.1 -s scope_test.txt -p 8080
```

**Expect:** no result. Correct negative.

---

## STEP 5 — web_scanner (HTTP fingerprint)

```bash
python3 -m scanner.web_scanner -t 127.0.0.1 -s scope_test.txt -p 8080,8443
```

**Accuracy check:** the 8080 result must show `"title": "GROUND-TRUTH-PAGE"` and
`Server: SimpleHTTP...`. The exact title you planted proves it read the real
page, not a guess.

---

## STEP 6 — db_scanner (DB protocol fingerprint)

```bash
python3 -m scanner.db_scanner -t 127.0.0.1 -s scope_test.txt
```

**Accuracy check (only if MySQL runs on 3306):** `"engine": "mysql/mariadb"` and
`server_version` must match your `mysql --version`. This is a real protocol
handshake, not banner guessing.
*No DB running → no output, which is a correct negative.*

---

## STEP 7 — udp / smb / snmp (expect NEGATIVES on localhost — that is correct)

```bash
python3 -m scanner.udp_scanner  -t 127.0.0.1 -s scope_test.txt
python3 -m scanner.smb_scanner  -t 127.0.0.1 -s scope_test.txt
python3 -m scanner.snmp_scanner -t 127.0.0.1 -s scope_test.txt
```

**Expect:** mostly `"status":"filtered"` — a Mac runs no DNS/SNMP/SMB, so the
accurate answer is "nothing here" (no false positives on absent services).

To see a **true positive**, aim UDP/SNMP at your router (often runs DNS on 53):

```bash
python3 -m scanner.udp_scanner -t 192.168.1.1 -s scope_test.txt
```

(If 53 answers → `"status":"open"` with a DNS reply.)

---

## STEP 8 — mcp_ai_scanner (deliberate false-positive lesson)

```bash
python3 -m scanner.mcp_ai_scanner -t 127.0.0.1 -s scope_test.txt
```

**Watch for this:** on macOS you will likely see **port 5000 flagged as
`ollama`/`mcp` with `auth_enforced=true`**. That is a **FALSE POSITIVE** — it is
macOS's AirPlay receiver returning 403, not an AI server. This is exactly the
kind of thing manual accuracy testing exists to catch. For a real true positive,
run `ollama serve` (port 11434) and re-scan.

---

## STEP 9 — A/B accuracy: nmap_wrapper & mass_scan vs your own scanner

Does the pure-Python scanner agree with battle-tested tools?

```bash
python3 -m scanner.nmap_wrapper -t 127.0.0.1 -s scope_test.txt --profile fast
python3 -m scanner.mass_scan    -t 127.0.0.1 -s scope_test.txt -p 1-10000 --fallback
```

**Accuracy check:** both should report the **same open ports** (3306/3389/8080/
8443) that `port_scanner` found in Step 2. Agreement across three independent
engines = high confidence.

(`nmap_wrapper` needs the `nmap` binary; `mass_scan --fallback` uses the
pure-Python sweep so it needs no `masscan` binary and no root.)

---

## STEP 10 — full pipeline (the staged funnel)

```bash
python3 pipeline.py -t 127.0.0.1 -s scope_test.txt --profile it
```

**Expect:** one clean per-host summary listing the 4 ports with services (mysql,
http, https/tls). It should reproduce your individual results above.

---

## STEP 11 — OT passive (sends nothing; observe real hosts)

```bash
python3 pipeline.py -t 192.168.1.0/24 -s scope_test.txt --profile ot --listen-seconds 20 -v
```

**Verify it is truly passive** — in a *second* terminal, watch for any outbound
packet from the tool (needs sudo; replace with your Mac's LAN IP):

```bash
sudo tcpdump -i any -n 'udp and src host 192.168.1.<your-mac-ip>' -c 5
```

**Expect:** the pipeline reports hosts it *heard* (mDNS/SSDP), while tcpdump
shows **no probe packets sent to targets** — confirming OT-safety.

---

## STEP 12 — Teardown

```bash
pkill -f "http.server 8080"; pkill -f "/tmp/vafix/banner.py"; pkill -f "openssl s_server"
rm -rf /tmp/vafix scope_test.txt
echo "cleaned up"
```

---

## What "accurate" means here

For each scanner, judge it on:

| Check | Pass condition |
|-------|----------------|
| True positive | reports the services you know are really there |
| False positive | stays silent about services that are absent |
| Fidelity | recorded banner/version/TLS facts match independent tools (`curl`, `openssl`, `nmap`, `mysql --version`) |
| Cross-engine agreement | port_scanner == nmap_wrapper == mass_scan on open ports |

The two most instructive steps are **Step 8** (catching the AirPlay false
positive) and **Step 9** (three engines agreeing). A scanner that reports a port
that is not open, or misses one that is, is what you are hunting for.
