"""
VulnPrioritizer — ML-based vulnerability prioritisation with a deterministic
fallback.

When a trained XGBoost model is available it predicts a 0–1000 priority score
from a fixed feature vector and explains each prediction with SHAP values. When
xgboost/shap/sklearn aren't installed, or no model has been trained, it falls
back to the same weighted composite formula used by the Prompt-3 enrichment
service — so prioritisation always works, just less precisely.

Features (in fixed order):
  [cvss, epss, kev_flag, exploit_validated, asset_criticality,
   lateral_reachable_count, days_since_last_patch]
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any

import structlog

logger = structlog.get_logger()

try:
    import numpy as np
    import xgboost as xgb
    from sklearn.model_selection import train_test_split

    _HAS_XGB = True
except ImportError:  # pragma: no cover - exercised only without ML libs
    np = None  # type: ignore
    xgb = None  # type: ignore
    _HAS_XGB = False

try:
    import shap

    _HAS_SHAP = True
except ImportError:  # pragma: no cover
    shap = None  # type: ignore
    _HAS_SHAP = False


FEATURE_NAMES: list[str] = [
    "cvss",
    "epss",
    "kev_flag",
    "exploit_validated",
    "asset_criticality",
    "lateral_reachable_count",
    "days_since_last_patch",
]

# asset criticality → normalised weight (matches enrichment service).
_CRITICALITY_WEIGHT = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}


def _to_float(v: Any, default: float = 0.0) -> float:
    if v is None:
        return default
    if isinstance(v, Decimal):
        return float(v)
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def extract_features(finding: Any, asset: Any = None, context: dict | None = None) -> list[float]:
    """
    Build the model's feature vector from a Finding (+ optional Asset + extra
    context like lateral reachability and patch age). Works with SQLAlchemy
    models or any attribute/dict-bearing object.
    """
    context = context or {}
    evidence = getattr(finding, "evidence", None) or {}

    cvss = _to_float(getattr(finding, "cvss_score", None))
    epss = _to_float(getattr(finding, "epss_score", None))
    kev = 1.0 if (evidence.get("kev") or evidence.get("cisa_kev")) else 0.0
    exploit_validated = 1.0 if getattr(finding, "exploit_validated", False) else 0.0

    criticality = "medium"
    if asset is not None:
        criticality = str(getattr(getattr(asset, "criticality", None), "value",
                                  getattr(asset, "criticality", "medium")) or "medium").lower()
    asset_crit = _CRITICALITY_WEIGHT.get(criticality, 0.5)

    lateral = _to_float(context.get("lateral_reachable_count", evidence.get("lateral_reachable_count", 0)))
    days_since_patch = _to_float(context.get("days_since_last_patch",
                                             evidence.get("days_since_last_patch", 0)))

    return [cvss, epss, kev, exploit_validated, asset_crit, lateral, days_since_patch]


class VulnPrioritizer:
    def __init__(self) -> None:
        self._model: Any = None
        self._explainer: Any = None

    @property
    def is_trained(self) -> bool:
        return self._model is not None

    # ── train ─────────────────────────────────────────────────────────────────────

    def train(self, historical_findings_df: Any, target_col: str = "priority_score") -> dict[str, Any]:
        """
        Fit an XGBoost regressor on historical findings. ``historical_findings_df``
        is a pandas DataFrame containing the FEATURE_NAMES columns plus the target.
        Returns training metadata. Raises RuntimeError if xgboost is unavailable.
        """
        if not _HAS_XGB:
            raise RuntimeError("xgboost/scikit-learn not installed — cannot train; using fallback formula")

        missing = [c for c in FEATURE_NAMES if c not in historical_findings_df.columns]
        if missing:
            raise ValueError(f"training data missing feature columns: {missing}")
        if target_col not in historical_findings_df.columns:
            raise ValueError(f"training data missing target column '{target_col}'")

        x = historical_findings_df[FEATURE_NAMES].astype(float).values
        y = historical_findings_df[target_col].astype(float).values

        if len(x) >= 10:
            x_train, x_val, y_train, y_val = train_test_split(x, y, test_size=0.2, random_state=42)
        else:  # too few rows to split — train on everything
            x_train, x_val, y_train, y_val = x, x, y, y

        model = xgb.XGBRegressor(
            n_estimators=200, max_depth=5, learning_rate=0.1,
            subsample=0.9, objective="reg:squarederror", random_state=42,
        )
        model.fit(x_train, y_train)
        self._model = model
        self._explainer = shap.TreeExplainer(model) if _HAS_SHAP else None

        preds = model.predict(x_val)
        rmse = float(np.sqrt(np.mean((preds - y_val) ** 2)))
        logger.info("ai.prioritizer.trained", rows=len(x), rmse=round(rmse, 2))
        return {"rows": len(x), "rmse": rmse, "features": FEATURE_NAMES}

    # ── predict_priority ────────────────────────────────────────────────────────

    def predict_priority(self, finding: Any, asset: Any = None, context: dict | None = None) -> float:
        """Return a 0–1000 priority score. Uses the model if trained, else the formula."""
        features = extract_features(finding, asset, context)
        if self._model is not None and _HAS_XGB:
            score = float(self._model.predict(np.array([features], dtype=float))[0])
            return round(max(0.0, min(1000.0, score)), 2)
        return self.fallback_score(features)

    # ── explain_prediction ────────────────────────────────────────────────────────

    def explain_prediction(self, finding: Any, asset: Any = None, context: dict | None = None) -> dict[str, Any]:
        """
        Per-feature contribution to this prediction. Uses SHAP when available;
        otherwise returns the weighted formula contributions so the API always has
        an explanation to show.
        """
        features = extract_features(finding, asset, context)

        if self._model is not None and _HAS_SHAP and self._explainer is not None:
            shap_values = self._explainer.shap_values(np.array([features], dtype=float))[0]
            contributions = {name: round(float(v), 3) for name, v in zip(FEATURE_NAMES, shap_values)}
            return {
                "method": "shap",
                "score": self.predict_priority(finding, asset, context),
                "feature_values": dict(zip(FEATURE_NAMES, features)),
                "contributions": contributions,
                "base_value": round(float(self._explainer.expected_value), 3),
            }

        return {
            "method": "weighted_formula",
            "score": self.fallback_score(features),
            "feature_values": dict(zip(FEATURE_NAMES, features)),
            "contributions": self._formula_contributions(features),
        }

    # ── fallback formula ──────────────────────────────────────────────────────────

    _WEIGHTS = {
        "cvss": 0.25, "epss": 0.20, "kev_flag": 0.20, "exploit_validated": 0.15,
        "asset_criticality": 0.10, "lateral_reachable_count": 0.05, "days_since_last_patch": 0.05,
    }

    def _formula_contributions(self, features: list[float]) -> dict[str, float]:
        f = dict(zip(FEATURE_NAMES, features))
        norm = {
            "cvss": f["cvss"] / 10.0,
            "epss": f["epss"],
            "kev_flag": f["kev_flag"],
            "exploit_validated": f["exploit_validated"],
            "asset_criticality": f["asset_criticality"],
            "lateral_reachable_count": min(f["lateral_reachable_count"] / 50.0, 1.0),
            "days_since_last_patch": min(f["days_since_last_patch"] / 365.0, 1.0),
        }
        return {k: round(self._WEIGHTS[k] * norm[k] * 1000.0, 2) for k in FEATURE_NAMES}

    def fallback_score(self, features: list[float]) -> float:
        """Weighted composite 0–1000 (same shape as the Prompt-3 enrichment formula)."""
        return round(min(1000.0, sum(self._formula_contributions(features).values())), 2)
