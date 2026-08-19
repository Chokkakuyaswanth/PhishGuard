"""Base model plus calibrated fusion and validation-derived thresholds."""
from __future__ import annotations

import asyncio
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_curve
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from cti.mock_adapters import MockVirusTotalAdapter, MockURLhausAdapter, MockWHOISAdapter

ARTIFACT_DIR = Path(__file__).parent / "artifacts"


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


async def _collect_cti_scores(urls: list[str]) -> np.ndarray:
    adapters = [MockVirusTotalAdapter(), MockURLhausAdapter(), MockWHOISAdapter()]
    rows = []
    for url in urls:
        results = await asyncio.gather(*(adapter.lookup(url) for adapter in adapters))
        by_source = {response.source: response for response in results}
        rows.append([
            by_source["virustotal"].score,
            by_source["urlhaus"].score,
            by_source["whois"].score,
        ])
    return np.array(rows, dtype=float)


def fit_calibrated_bundle(
    base_model: Pipeline,
    X_val: np.ndarray,
    y_val: np.ndarray,
    urls_val: list[str],
    X_test: np.ndarray,
    y_test: np.ndarray,
    urls_test: list[str],
) -> tuple[dict[str, object], dict[str, float], dict[str, object], dict[str, float]]:
    val_base_prob = base_model.predict_proba(X_val)[:, 1]
    test_base_prob = base_model.predict_proba(X_test)[:, 1]

    val_cti = asyncio.run(_collect_cti_scores(urls_val))
    test_cti = asyncio.run(_collect_cti_scores(urls_test))

    val_meta_X = np.column_stack([val_base_prob, val_cti])
    test_meta_X = np.column_stack([test_base_prob, test_cti])

    combiner = LogisticRegression(max_iter=1000, random_state=42)
    combiner.fit(val_meta_X, y_val)

    val_score = combiner.predict_proba(val_meta_X)[:, 1]
    test_score = combiner.predict_proba(test_meta_X)[:, 1]

    precision, recall, thresholds = precision_recall_curve(y_val, val_score)
    target_precision = 0.98
    chosen_threshold = None
    chosen_recall = -1.0
    fallback_threshold = 0.5
    fallback_f1 = -1.0

    for p, r, threshold in zip(precision[1:], recall[1:], thresholds):
        if p + r > 0:
            f1 = 2 * p * r / (p + r)
            if f1 > fallback_f1:
                fallback_f1 = f1
                fallback_threshold = float(threshold)
        if p >= target_precision and r >= chosen_recall:
            chosen_threshold = float(threshold)
            chosen_recall = float(r)

    suspicious_threshold = chosen_threshold if chosen_threshold is not None else fallback_threshold
    safe_threshold = float(max(0.05, min(suspicious_threshold * 0.5, 0.45)))
    thresholds_cfg = {"safe": round(safe_threshold, 4), "suspicious": round(float(suspicious_threshold), 4)}

    bundle = {
        "base_model": base_model,
        "combiner": combiner,
        "thresholds": thresholds_cfg,
        "feature_order": None,
        "version": "calibrated-bundle-v1",
    }

    metadata = {
        "val_score": val_score,
        "test_score": test_score,
        "test_cti": test_cti,
        "val_cti": val_cti,
    }
    return bundle, thresholds_cfg, metadata, {"safe": safe_threshold, "suspicious": suspicious_threshold}


def save_model(bundle: dict[str, object], name: str = "phishguard_model.joblib") -> Path:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    path = ARTIFACT_DIR / name
    joblib.dump(bundle, path)
    return path


def load_model(name: str = "phishguard_model.joblib") -> dict[str, object]:
    return joblib.load(ARTIFACT_DIR / name)
