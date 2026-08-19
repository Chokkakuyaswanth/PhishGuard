import sys
from pathlib import Path

import joblib
import numpy as np

from app.config import settings

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from ml.features.extractor import FEATURE_ORDER  # noqa: E402

_FALLBACK_THRESHOLDS = {"suspicious": 0.7679, "malicious": 0.985}


class MLService:
    _bundle = None

    @classmethod
    def load(cls) -> None:
        path = Path(settings.ml_model_path)
        if not path.exists():
            raise FileNotFoundError(
                f"Model not found at {path}. Run: python ml/train.py"
            )
        loaded = joblib.load(path)
        if isinstance(loaded, dict) and "base_model" in loaded:
            bundle = loaded
        else:
            bundle = {"base_model": loaded, "calibrator": None, "thresholds": dict(_FALLBACK_THRESHOLDS)}

        # A stale artifact silently mismatched against FEATURE_ORDER would score
        # every URL against the wrong columns, so refuse to serve it.
        trained_order = bundle.get("feature_order")
        if trained_order and list(trained_order) != list(FEATURE_ORDER):
            raise RuntimeError(
                f"Model at {path} was trained on {len(trained_order)} features but the extractor "
                f"produces {len(FEATURE_ORDER)}. Retrain with: python ml/train.py"
            )

        cls._prepare_for_inference(bundle)
        cls._bundle = bundle

    @classmethod
    def _prepare_for_inference(cls, node) -> None:
        if isinstance(node, dict):
            for value in node.values():
                cls._prepare_for_inference(value)
            return

        if isinstance(node, (list, tuple)):
            for value in node:
                cls._prepare_for_inference(value)
            return

        if hasattr(node, "n_jobs"):
            try:
                node.n_jobs = 1
            except Exception:
                pass

        if hasattr(node, "steps"):
            for _, step in node.steps:
                cls._prepare_for_inference(step)

        if hasattr(node, "estimators"):
            for estimator in node.estimators:
                if isinstance(estimator, tuple) and len(estimator) == 2:
                    cls._prepare_for_inference(estimator[1])
                else:
                    cls._prepare_for_inference(estimator)

        if hasattr(node, "estimators_"):
            for estimator in node.estimators_:
                cls._prepare_for_inference(estimator)

    @classmethod
    def predict(cls, feature_vector: np.ndarray) -> float:
        """Calibrated phishing probability — the same scale the thresholds were picked on."""
        if cls._bundle is None:
            cls.load()
        raw = cls._bundle["base_model"].predict_proba(feature_vector.reshape(1, -1))[0][1]
        calibrator = cls._bundle.get("calibrator")
        score = float(calibrator.predict([raw])[0]) if calibrator is not None else float(raw)
        return round(min(max(score, 0.0), 1.0), 4)

    @classmethod
    def is_loaded(cls) -> bool:
        return cls._bundle is not None

    @classmethod
    def version(cls) -> str | None:
        if cls._bundle is None:
            cls.load()
        return cls._bundle.get("version")

    @classmethod
    def decision_thresholds(cls) -> dict[str, float]:
        if cls._bundle is None:
            cls.load()
        if "decision_thresholds" in cls._bundle:
            return dict(cls._bundle["decision_thresholds"])

        learned = dict(cls._bundle.get("thresholds", {}))
        return {
            "suspicious": float(learned.get("suspicious", _FALLBACK_THRESHOLDS["suspicious"])),
            "malicious": float(learned.get("malicious", _FALLBACK_THRESHOLDS["malicious"])),
        }

    @classmethod
    def thresholds(cls) -> dict[str, float]:
        if cls._bundle is None:
            cls.load()
        return dict(cls._bundle.get("thresholds", _FALLBACK_THRESHOLDS))
