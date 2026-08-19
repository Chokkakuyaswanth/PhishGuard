"""Conservative URL normalization for consistent feature extraction and CTI lookup."""
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from shared.url_utils import normalize_url  # noqa: E402,F401
