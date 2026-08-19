"""The extension path must stay inside the 500 ms browser-integration target."""
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services import cti_service

TARGET_MS = 500


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as c:
        yield c


class TestExtensionLatency:
    def test_extension_budget_is_inside_the_browser_target(self):
        # The CTI budget is the dominant term; it alone must leave room for
        # feature extraction, inference, and serialization.
        assert cti_service.budget_ms_for("extension") < TARGET_MS

    def test_dashboard_may_exceed_the_extension_budget(self):
        assert cti_service.budget_ms_for("dashboard") > cti_service.budget_ms_for("extension")

    def test_extension_scan_completes_within_target(self, client):
        client.post("/api/scan", json={"url": "https://warmup.example.com", "source": "extension"})

        samples = []
        for i in range(5):
            started = time.perf_counter()
            resp = client.post(
                "/api/scan",
                json={"url": f"https://latency-probe-{i}.example.com/a/b?c={i}", "source": "extension"},
            )
            samples.append((time.perf_counter() - started) * 1000)
            assert resp.status_code == 200

        worst = max(samples)
        assert worst < TARGET_MS, f"slowest extension scan took {worst:.0f} ms (target {TARGET_MS} ms)"
