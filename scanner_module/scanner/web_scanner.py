"""
web_scanner.py — passive HTTP(S) service fingerprinting.

METHOD (collection only): issue a single benign GET to each web port and record
factual response metadata:
  * status code, redirect location
  * response headers (Server, X-Powered-By, security headers present/absent)
  * page <title>
  * lightweight tech hints from headers/body (e.g. wordpress, nginx)
We do NOT fuzz, brute-force paths, send attack payloads, or test for injection.
This is fingerprinting, not attacking — equivalent to whatweb/httpx in observe
mode. Output is raw facts so accuracy/FP can be measured.

Uses urllib (stdlib) in an executor.
"""

from __future__ import annotations

import argparse
import asyncio
import re
import ssl
import urllib.request
import urllib.error

from .scanner_base import (
    BaseScanner, ScanResult, ScopeGuard, ResultWriter, expand_targets,
    parse_ports, setup_logging, base_argparser, main_entrypoint,
)

DEFAULT_WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 9000, 9200]
_TLS_PORTS = {443, 8443, 9443}

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)

_SECURITY_HEADERS = [
    "content-security-policy", "strict-transport-security",
    "x-frame-options", "x-content-type-options", "referrer-policy",
]

_TECH_HINTS = {
    "wordpress": [b"wp-content", b"wp-includes"],
    "drupal": [b"Drupal", b"/sites/default/"],
    "joomla": [b"Joomla", b"/components/com_"],
    "django": [b"csrfmiddlewaretoken", b"__admin_media_prefix__"],
    "laravel": [b"laravel_session"],
    "react": [b"__REACT_DEVTOOLS", b"data-reactroot"],
    "grafana": [b"grafana"],
    "kibana": [b"kbn-name", b"kibana"],
    "jenkins": [b"X-Jenkins", b"Jenkins"],
}


def _fetch(url: str, timeout: float) -> dict | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        url, headers={"User-Agent": "va-scanner/1.0"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(8192)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            status = resp.status
            final_url = resp.geturl()
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(8192)
        except Exception:
            pass
        headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        status = e.code
        final_url = url
    except Exception:
        return None

    title_m = _TITLE_RE.search(body)
    title = (title_m.group(1).decode("latin-1", "replace").strip()[:200]
             if title_m else None)

    tech = []
    hay = body + repr(headers).encode("latin-1", "replace")
    for name, sigs in _TECH_HINTS.items():
        if any(s.lower() in hay.lower() for s in sigs):
            tech.append(name)

    missing_sec = [h for h in _SECURITY_HEADERS if h not in headers]

    return {
        "status": status,
        "final_url": final_url,
        "server": headers.get("server"),
        "x_powered_by": headers.get("x-powered-by"),
        "title": title,
        "content_type": headers.get("content-type"),
        "redirect_location": headers.get("location"),
        "tech_hints": tech,
        "security_headers_present": [h for h in _SECURITY_HEADERS if h in headers],
        "security_headers_missing": missing_sec,
        "all_headers": headers,
    }


class WebScanner(BaseScanner):
    name = "web_scan"

    def __init__(self, *args, ports: list[int], **kwargs):
        super().__init__(*args, **kwargs)
        self.ports = ports

    async def _scan_port(self, target: str, port: int) -> ScanResult | None:
        scheme = "https" if port in _TLS_PORTS else "http"
        url = f"{scheme}://{target}:{port}/"
        await self.limiter.wait()
        loop = asyncio.get_running_loop()
        info = await loop.run_in_executor(None, _fetch, url, self.timeout)
        if info is None:
            return None
        return ScanResult(
            self.name, target, port=port, proto="tcp", status="open",
            data={"url": url, **info},
            evidence=(f"HTTP {info['status']} "
                      f"server={info.get('server')} "
                      f"title={info.get('title')!r}"),
        )

    async def scan_target(self, target: str) -> list[ScanResult]:
        tasks = [self._scan_port(target, p) for p in self.ports]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]


def main() -> None:
    parser = base_argparser("Passive HTTP(S) fingerprint scanner")
    parser.add_argument("-p", "--ports", default=None,
                        help="web ports (default: common web ports)")
    args = parser.parse_args()
    setup_logging(args.verbose)

    async def _run():
        ports = parse_ports(args.ports) if args.ports else DEFAULT_WEB_PORTS
        scope = ScopeGuard.from_file(args.scope)
        targets = expand_targets(args.targets)
        scanner = WebScanner(scope, rate=args.rate, concurrency=args.concurrency,
                             timeout=args.timeout, ports=ports)
        writer = ResultWriter(args.output, also_stdout=True)
        try:
            await scanner.run(targets, writer)
        finally:
            writer.close()

    main_entrypoint(_run)


if __name__ == "__main__":
    main()
