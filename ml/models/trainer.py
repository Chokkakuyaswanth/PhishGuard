"""Base model, probability calibration, and out-of-sample decision thresholds."""
from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import precision_recall_curve
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from ml.features.extractor import FEATURE_ORDER

ARTIFACT_DIR = Path(__file__).parent / "artifacts"

# Thresholds are picked on a 50/50 balanced set, but production traffic is
# overwhelmingly legitimate. Clamping keeps a very separable model from
# selecting an operating point (~0.03) that flags anything off pure zero.
_MIN_SUSPICIOUS_THRESHOLD = 0.50
_MAX_SUSPICIOUS_THRESHOLD = 0.95


def build_pipeline() -> Pipeline:
    xgb = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        random_state=42,
        n_jobs=-1,
    )
    ensemble = VotingClassifier(
        estimators=[("xgb", xgb), ("rf", rf)],
        voting="soft",
    )
    return Pipeline([("scaler", StandardScaler()), ("model", ensemble)])


def train_base_model(X_train: np.ndarray, y_train: np.ndarray) -> Pipeline:
    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)
    return pipeline


def _pick_threshold(
    y_true: np.ndarray,
    scores: np.ndarray,
    target_precision: float,
    floor: float,
    ceiling: float,
) -> float:
    """Highest-recall threshold meeting target_precision, clamped to a sane operating range."""
    precision, recall, thresholds = precision_recall_curve(y_true, scores)
    chosen, chosen_recall = None, -1.0
    fallback, fallback_f1 = 0.5, -1.0

    for p, r, threshold in zip(precision[1:], recall[1:], thresholds):
        if p + r > 0:
            f1 = 2 * p * r / (p + r)
            if f1 > fallback_f1:
                fallback_f1, fallback = f1, float(threshold)
        if p >= target_precision and r > chosen_recall:
            chosen, chosen_recall = float(threshold), float(r)

    return float(min(max(chosen if chosen is not None else fallback, floor), ceiling))


def fit_calibrated_bundle(
    base_model: Pipeline,
    X_val: np.ndarray,
    y_val: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
) -> tuple[dict[str, object], dict[str, float], dict[str, object], dict[str, float]]:
    # The calibrator and the thresholds must not come from the same rows, or the
    # precision-recall curve is drawn from in-sample fits and reads optimistically.
    X_cal, X_thr, y_cal, y_thr = train_test_split(
        X_val, y_val, test_size=0.5, stratify=y_val, random_state=42
    )

    calibrator = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip")
    calibrator.fit(base_model.predict_proba(X_cal)[:, 1], y_cal)

    thr_score = calibrator.predict(base_model.predict_proba(X_thr)[:, 1])
    test_score = calibrator.predict(base_model.predict_proba(X_test)[:, 1])

    suspicious_threshold = _pick_threshold(
        y_thr, thr_score, 0.98, _MIN_SUSPICIOUS_THRESHOLD, _MAX_SUSPICIOUS_THRESHOLD
    )
    malicious_threshold = _pick_threshold(
        y_thr, thr_score, 0.995, max(suspicious_threshold, 0.80), 0.99
    )

    thresholds_cfg = {
        "suspicious": round(suspicious_threshold, 4),
        "malicious": round(malicious_threshold, 4),
        "safe": round(min(suspicious_threshold * 0.5, 0.45), 4),
    }

    bundle = {
        "base_model": base_model,
        "calibrator": calibrator,
        "thresholds": thresholds_cfg,
        "decision_thresholds": {
            "suspicious": thresholds_cfg["suspicious"],
            "malicious": thresholds_cfg["malicious"],
        },
        "feature_order": list(FEATURE_ORDER),
        "version": "calibrated-isotonic-v2",
    }

    metadata = {"thr_score": thr_score, "test_score": test_score}
    return bundle, thresholds_cfg, metadata, {
        "safe": thresholds_cfg["safe"],
        "suspicious": suspicious_threshold,
        "malicious": malicious_threshold,
    }


def save_model(bundle: dict[str, object], name: str = "phishguard_model.joblib") -> Path:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    path = ARTIFACT_DIR / name
    joblib.dump(bundle, path)
    return path


def load_model(name: str = "phishguard_model.joblib") -> dict[str, object]:
    return joblib.load(ARTIFACT_DIR / name)
