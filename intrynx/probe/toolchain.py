"""Self-provisioning scan engines for the probe.

On start (or via ``./probe install``) the probe auto-installs any missing scan
engine so capabilities light up without manual setup. Two install paths:

  * ProjectDiscovery binaries (nuclei, httpx) → downloaded for this OS/arch into
    a probe-local ``tools/bin/`` dir (no sudo, no system changes, easy cleanup).
  * System tools (nmap, masscan, sslscan, netexec) → via the platform package
    manager (brew on macOS, apt on Linux) or pip — best-effort.

Everything installed locally is removed by ``cleanup()`` (``./probe cleanup-tools``);
temp downloads are always cleaned up immediately.
"""
from __future__ import annotations

import os
import platform
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

PROBE_DIR = Path(__file__).resolve().parent
LOCAL_BIN = PROBE_DIR / "tools" / "bin"

# Pinned ProjectDiscovery versions (match the Dockerfile).
PD_VERSIONS = {"nuclei": "3.3.8", "httpx": "1.6.9"}
# Internal binary every scan_type maps to (builtin scanners have no binary).
ENGINE_BINARIES = ("nmap", "masscan", "nuclei", "httpx", "sslscan", "nxc")


# ── PATH so locally-installed binaries are found by shutil.which ────────────────

def prepend_path() -> None:
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    p = str(LOCAL_BIN)
    parts = os.environ.get("PATH", "").split(os.pathsep)
    if p not in parts:
        os.environ["PATH"] = p + os.pathsep + os.environ.get("PATH", "")


def _osarch() -> tuple[str, str]:
    os_tag = {"Linux": "linux", "Darwin": "macOS", "Windows": "windows"}.get(platform.system(), "linux")
    m = platform.machine().lower()
    arch = "arm64" if m in ("arm64", "aarch64") else "amd64"
    return os_tag, arch


def _run(cmd: list[str], timeout: int = 600) -> tuple[bool, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode == 0, (p.stderr or p.stdout or "")[-400:]
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)


def _ssl_context() -> ssl.SSLContext:
    # macOS python.org builds lack a system CA bundle for urllib; certifi (a
    # transitive dep of httpx, which the probe already requires) provides one.
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def _download(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "intrynx-probe"})
    try:
        with urllib.request.urlopen(req, timeout=180, context=_ssl_context()) as r, open(dest, "wb") as f:
            shutil.copyfileobj(r, f)
    except Exception:
        # Fall back to curl, which uses the OS trust store (handles odd CA setups).
        if not shutil.which("curl"):
            raise
        ok, detail = _run(["curl", "-fsSL", "-o", str(dest), url], timeout=180)
        if not ok:
            raise RuntimeError(f"download failed: {detail}")


# ── installers ──────────────────────────────────────────────────────────────────

def install_projectdiscovery(name: str) -> tuple[bool, str]:
    """Download a ProjectDiscovery binary into LOCAL_BIN (no sudo)."""
    version = PD_VERSIONS[name]
    os_tag, arch = _osarch()
    url = (f"https://github.com/projectdiscovery/{name}/releases/download/"
           f"v{version}/{name}_{version}_{os_tag}_{arch}.zip")
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="ix-tool-"))
    try:
        zpath = tmp / f"{name}.zip"
        _download(url, zpath)
        with zipfile.ZipFile(zpath) as z:
            member = next((m for m in z.namelist()
                           if m == name or m.endswith("/" + name)), None)
            if member is None:  # fall back to the first non-doc member
                member = next((m for m in z.namelist()
                               if not m.lower().endswith((".md", ".txt")) and "license" not in m.lower()), None)
            if member is None:
                return False, "binary not found in release archive"
            z.extract(member, tmp)
            shutil.move(str(tmp / member), str(LOCAL_BIN / name))
        (LOCAL_BIN / name).chmod(0o755)
        return True, ""
    except Exception as exc:  # noqa: BLE001 — network/zip errors are reported, not raised
        return False, str(exc)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)  # always clean up the download


def install_system(tool: str) -> tuple[bool, str]:
    """Install a system tool via the platform package manager (best-effort)."""
    if shutil.which("brew"):
        return _run(["brew", "install", tool])
    if shutil.which("apt-get"):
        sudo: list[str] = []
        if os.geteuid() != 0:  # type: ignore[attr-defined]
            if not shutil.which("sudo"):
                return False, "needs root/sudo to apt-get install"
            sudo = ["sudo", "-n"]  # non-interactive; fails fast if no cached creds
        _run(sudo + ["apt-get", "update", "-qq"])
        return _run(sudo + ["apt-get", "install", "-y", "-q", tool])
    return False, "no supported package manager (brew/apt-get)"


def install_netexec() -> tuple[bool, str]:
    """Install netexec (nxc) from GitHub source and copy the binary to LOCAL_BIN.

    netexec is not on PyPI for all platforms; install directly from the GitHub
    repo.  After pip installs it into the Python prefix's bin/, we copy the binary
    to LOCAL_BIN so our prepend_path() always finds it.
    """
    # Try pip from GitHub (works on macOS and Linux; PyPI release is lagging).
    src = "git+https://github.com/Pennyw0rth/NetExec"
    if shutil.which("pipx"):
        ok, detail = _run(["pipx", "install", src], timeout=900)
    else:
        ok, detail = _run(
            [sys.executable, "-m", "pip", "install", "--quiet", src], timeout=900
        )

    # After pip install, the nxc binary lands in the Python prefix's bin/
    # (e.g. /Library/Frameworks/Python.framework/.../bin/nxc on macOS).
    # Copy it to LOCAL_BIN so shutil.which finds it via our prepended PATH.
    if ok or shutil.which("nxc") is None:
        import importlib
        for candidate in (
            shutil.which("nxc"),
            shutil.which("nxc", path=str(Path(sys.executable).parent)),
            str(Path(sys.executable).parent / "nxc"),
        ):
            if candidate and Path(candidate).exists():
                LOCAL_BIN.mkdir(parents=True, exist_ok=True)
                shutil.copy2(candidate, str(LOCAL_BIN / "nxc"))
                (LOCAL_BIN / "nxc").chmod(0o755)
                return True, ""

    return ok, detail


_INSTALLERS = {
    "nuclei":  lambda: install_projectdiscovery("nuclei"),
    "httpx":   lambda: install_projectdiscovery("httpx"),
    "nmap":    lambda: install_system("nmap"),
    "masscan": lambda: install_system("masscan"),
    "sslscan": lambda: install_system("sslscan"),
    "nxc":     install_netexec,
}


# ── orchestration ───────────────────────────────────────────────────────────────

def missing_engines() -> list[str]:
    prepend_path()
    return [b for b in ENGINE_BINARIES if shutil.which(b) is None]


def ensure(only: list[str] | None = None, log=print) -> list[tuple[str, str]]:
    """Install every missing scan engine. Idempotent (fast when present)."""
    prepend_path()
    report: list[tuple[str, str]] = []
    for tool in ENGINE_BINARIES:
        if only and tool not in only:
            continue
        if shutil.which(tool):
            report.append((tool, "present"))
            continue
        log(f"  installing {tool} ...")
        ok, detail = _INSTALLERS[tool]()
        status = "installed" if (ok and shutil.which(tool)) else "failed"
        if status == "failed" and detail:
            log(f"    ({tool}: {detail.strip()[:160]})")
        report.append((tool, status))
    return report


def cleanup() -> None:
    """Remove probe-local installed binaries + any stray temp downloads."""
    shutil.rmtree(LOCAL_BIN, ignore_errors=True)
    for d in Path(tempfile.gettempdir()).glob("ix-tool-*"):
        shutil.rmtree(d, ignore_errors=True)
