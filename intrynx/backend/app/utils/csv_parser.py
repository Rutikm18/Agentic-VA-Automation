import csv
import io
from typing import Any

from app.schemas.asset import AssetIn
from app.models.enums import AssetType, AssetCriticality

_FIELD_MAP = {
    "ip": "ip_address",
    "ip_address": "ip_address",
    "host": "hostname",
    "hostname": "hostname",
    "fqdn": "fqdn",
    "os": "os",
    "os_version": "os_version",
    "type": "asset_type",
    "asset_type": "asset_type",
    "criticality": "criticality",
    "owner": "owner",
    "environment": "environment",
    "env": "environment",
}


def parse_csv_assets(raw: str) -> tuple[list[AssetIn], list[str]]:
    """Parse CSV text into a list of AssetIn models and error strings."""
    reader = csv.DictReader(io.StringIO(raw.strip()))
    assets: list[AssetIn] = []
    errors: list[str] = []

    for i, row in enumerate(reader, start=2):
        normalized: dict[str, Any] = {}
        for raw_key, value in row.items():
            key = (raw_key or "").strip().lower()
            mapped = _FIELD_MAP.get(key)
            if mapped and value and value.strip():
                normalized[mapped] = value.strip()

        try:
            # Coerce enum values
            if "asset_type" in normalized:
                normalized["asset_type"] = AssetType(normalized["asset_type"].lower())
            if "criticality" in normalized:
                normalized["criticality"] = AssetCriticality(normalized["criticality"].lower())

            assets.append(AssetIn(**normalized))
        except Exception as exc:
            errors.append(f"Row {i}: {exc}")

    return assets, errors
