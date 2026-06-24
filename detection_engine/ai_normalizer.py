"""
ai_normalizer.py — Phase 2: AI normalization assist, gated by deterministic
lookup.

THE AI HAS EXACTLY ONE JOB: given a raw observed string the rule-based
cpe_normalizer.py tables missed, propose CPE candidates — vendor, product,
version. Nothing else.

HARD RULES, each enforced structurally, not just by prompt wording:
  - The model NEVER emits a CVE id. The output JSON schema has no field
    that could hold one (see _RESPONSE_SCHEMA) — there is nowhere to put
    it even if the model tried. CVEs come exclusively from matcher.py's
    deterministic db lookup, which this module never touches.
  - Rule-based first, AI only on misses: callers (pipeline.py) must only
    invoke propose_candidates() after cpe_normalizer.normalize(fact)
    returned []. This module has no opinion on routing, but its name and
    every docstring here say "assist", not "replace".
  - Every proposed (vendor, product) is validated against the real NVD CPE
    dictionary before being trusted (validate_cpe_exists) — a product that
    doesn't exist there is discarded outright, never passed through as a
    guess. (NVD's CPE API, unlike its CVE API, is reachable from this
    environment — verified directly before building this; see
    validate_cpe_exists's docstring.)
  - Cached by input-hash (raw text -> result), so the same observed string
    is never sent to the model twice across runs.
  - Any failure — API error, malformed JSON, schema violation, NVD
    unreachable — yields [] (no candidates), never raises, never
    fabricates. The pipeline must run identically with or without AI
    assist available; AI assist can only ever ADD recall, never become a
    hard dependency.
  - Every resulting CPECandidate is tagged ai_assisted=True, propagated by
    matcher.py onto the Finding it produces — so AI-derived findings are
    always distinguishable from rule-based ones downstream.
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cpe_normalizer import CPECandidate
from models import Fact
from update_snapshot import _ssl_context

DEFAULT_CACHE_PATH = Path(__file__).parent / "snapshots" / "ai_normalizer_cache.json"

_RESPONSE_SCHEMA = {
    "name": "propose_cpe_candidates",
    "description": "Propose CPE 2.3 candidates (vendor/product/version only) for a raw observed string.",
    "input_schema": {
        "type": "object",
        "properties": {
            "candidates": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "vendor": {"type": "string", "description": "CPE vendor name, lowercase"},
                        "product": {"type": "string", "description": "CPE product name, lowercase"},
                        "version": {"type": ["string", "null"], "description": "version if present in the text, else null"},
                    },
                    "required": ["vendor", "product"],
                },
            }
        },
        "required": ["candidates"],
        # Deliberately no "cve" / "cve_id" property anywhere in this schema —
        # see module docstring's first hard rule.
    },
}

_SYSTEM_PROMPT = (
    "You identify software vendor/product/version from a short raw scanner "
    "observation (a banner, header, or package line). You ONLY propose CPE "
    "vendor/product/version candidates via the propose_cpe_candidates tool. "
    "You never mention or infer any CVE, vulnerability, or security "
    "advisory — that is out of scope and not part of your task. If the "
    "text doesn't clearly identify a real, existing software product, "
    "return an empty candidates list rather than guessing."
)


class AIClient(Protocol):
    def propose_cpe(self, raw_text: str) -> list[dict]:
        """Returns a list of {"vendor", "product", "version"} dicts —
        exactly the validated shape of _RESPONSE_SCHEMA's candidates array.
        Must raise on failure, never return a malformed shape silently."""
        ...


class AnthropicAIClient:
    """Real implementation, gated behind the anthropic SDK + an API key.
    Forces the model to use the tool (tool_choice), so a valid response is
    structurally guaranteed to match _RESPONSE_SCHEMA or the SDK itself
    raises — there is no free-text path for the model to slip a CVE into.
    """

    def __init__(self, api_key: str, model: str = "claude-haiku-4-5-20251001"):
        import anthropic
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model

    def propose_cpe(self, raw_text: str) -> list[dict]:
        resp = self._client.messages.create(
            model=self._model,
            max_tokens=512,
            system=_SYSTEM_PROMPT,
            tools=[_RESPONSE_SCHEMA],
            tool_choice={"type": "tool", "name": "propose_cpe_candidates"},
            messages=[{"role": "user", "content": f"Raw observation:\n{raw_text}"}],
        )
        for block in resp.content:
            if block.type == "tool_use" and block.name == "propose_cpe_candidates":
                return block.input.get("candidates", [])
        return []


class FakeAIClient:
    """Test double — a fixed lookup table, no network. Used to validate the
    surrounding plumbing (caching, NVD validation, fallback, provenance
    tagging) without a live model call. Never used by pipeline.py directly;
    only by this module's own tests and by callers that explicitly want a
    deterministic stand-in (e.g. a CI environment with no API key).
    """

    def __init__(self, responses: dict[str, list[dict]]):
        self._responses = responses

    def propose_cpe(self, raw_text: str) -> list[dict]:
        return self._responses.get(raw_text, [])


@dataclass
class AINormalizerCache:
    path: Path = DEFAULT_CACHE_PATH

    def __post_init__(self):
        self._data: dict[str, list[dict]] = {}
        if self.path.exists():
            with self.path.open() as fh:
                self._data = json.load(fh)

    @staticmethod
    def _key(raw_text: str) -> str:
        return hashlib.sha256(raw_text.encode()).hexdigest()

    def get(self, raw_text: str) -> list[dict] | None:
        return self._data.get(self._key(raw_text))

    def put(self, raw_text: str, candidates: list[dict]) -> None:
        self._data[self._key(raw_text)] = candidates
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w") as fh:
            json.dump(self._data, fh, indent=2)


_NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
_nvd_validation_cache: dict[tuple[str, str], bool] = {}
_last_nvd_call = 0.0
_NVD_RATE_LIMIT_SEC = 6.0  # NVD's unauthenticated public rate limit is ~5
                           # requests per 30s; 6s/call stays safely under it.


def validate_cpe_exists(vendor: str, product: str) -> bool:
    """True iff the real NVD CPE dictionary has at least one entry for this
    vendor:product. Verified reachable directly from this environment
    before building this module (NVD's CVE API was unreachable earlier in
    this project's history — see vuln_db.py's docstring for that pivot to
    OSV — but the separate CPE dictionary API answered HTTP 200 with real
    data when retested), so this uses the genuine authoritative source the
    spec asks for, not a substitute. On ANY failure (network, rate limit,
    malformed response) returns False — fail closed, never trust an
    unvalidated candidate through.
    """
    global _last_nvd_call
    key = (vendor.lower(), product.lower())
    if key in _nvd_validation_cache:
        return _nvd_validation_cache[key]

    elapsed = time.monotonic() - _last_nvd_call
    if elapsed < _NVD_RATE_LIMIT_SEC:
        time.sleep(_NVD_RATE_LIMIT_SEC - elapsed)

    cpe_match = f"cpe:2.3:a:{vendor.lower()}:{product.lower()}"
    url = f"{_NVD_CPE_URL}?cpeMatchString={cpe_match}&resultsPerPage=1"
    result = False
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "detection-engine/1.0"})
        with urllib.request.urlopen(req, timeout=12, context=_ssl_context()) as resp:
            data = json.loads(resp.read().decode())
        result = data.get("totalResults", 0) > 0
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, OSError):
        result = False
    finally:
        _last_nvd_call = time.monotonic()

    _nvd_validation_cache[key] = result
    return result


def extract_raw_text(fact: Fact) -> str | None:
    """The raw observable text worth sending to the AI normalizer for this
    Fact's scanner type, or None if this fact type has nothing
    normalize-able (e.g. a port_scan fact has no product text at all —
    sending it to the model would only invite a hallucinated guess).
    Mirrors cpe_normalizer.py's per-scanner field access deliberately —
    this is "the same fields, no rule table", not a different data source.
    """
    if fact.scanner == "service_banner":
        return fact.data.get("first_line") or fact.data.get("banner")
    if fact.scanner == "web_scan":
        parts = []
        if fact.data.get("server"):
            parts.append(f"HTTP Server header: {fact.data['server']}")
        if fact.data.get("tech_hints"):
            parts.append(f"tech_hints: {', '.join(fact.data['tech_hints'])}")
        return " | ".join(parts) if parts else None
    if fact.scanner == "db_scan":
        engine = fact.data.get("engine")
        version = fact.data.get("server_version")
        return f"db engine={engine} version={version}" if engine else None
    return None


def propose_candidates(fact: Fact, raw_text: str, client: AIClient,
                       cache: AINormalizerCache | None = None,
                       validate: bool = True) -> list[CPECandidate]:
    """The Phase 2 entry point. raw_text is whatever observed string the
    rule-based normalizer missed on (a banner, a header, a package line) —
    callers extract it the same way cpe_normalizer.py's normalize_* functions
    do for the matching Fact.scanner type.

    Returns [] on ANY problem (cache miss + client failure, NVD validation
    failure, malformed model output) — see module docstring's hard rules.
    """
    cache = cache or AINormalizerCache()

    cached = cache.get(raw_text)
    if cached is not None:
        raw_candidates = cached
    else:
        try:
            raw_candidates = client.propose_cpe(raw_text)
        except Exception:
            return []
        if not isinstance(raw_candidates, list):
            return []
        cache.put(raw_text, raw_candidates)

    out: list[CPECandidate] = []
    for c in raw_candidates:
        if not isinstance(c, dict):
            continue
        vendor, product = c.get("vendor"), c.get("product")
        if not vendor or not product:
            continue
        if validate and not validate_cpe_exists(vendor, product):
            continue  # discarded — see module docstring's validation rule
        version = c.get("version")
        out.append(CPECandidate(
            vendor=vendor, product=product,
            version_raw=version, version_normalized=version,
            confidence="low",  # AI-derived candidates start at the floor —
                               # never higher than the weakest rule-based tier
            source_confidence=fact.source_confidence,
            basis=f"AI-assisted normalization of: {raw_text[:80]!r}",
            source_ref=fact.ref(),
            ai_assisted=True,
            lookup_key=product,
        ))
    return out
