"""The scan path must stay inside its latency budget even when a provider hangs."""
import asyncio
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services import cti_service
from app.services.cti_service import budget_ms_for, enrich
from cti.base import BaseCTIAdapter, CTIResponse, CTIStatus


class HangingAdapter(BaseCTIAdapter):
    def __init__(self, source: str):
        self.source = source

    async def lookup(self, url: str) -> CTIResponse:
        await asyncio.sleep(30)
        raise AssertionError("should never complete")


class InstantAdapter(BaseCTIAdapter):
    def __init__(self, source: str):
        self.source = source

    async def lookup(self, url: str) -> CTIResponse:
        return CTIResponse(source=self.source, status=CTIStatus.LIVE, hit=False, score=0.0, details={})


class RaisingAdapter(BaseCTIAdapter):
    def __init__(self, source: str):
        self.source = source

    async def lookup(self, url: str) -> CTIResponse:
        raise RuntimeError("provider exploded")


@pytest.fixture
def patch_plan(monkeypatch):
    def _apply(plan):
        monkeypatch.setattr(cti_service, "_build_provider_plan", lambda: plan)
    return _apply


class TestBudgetSelection:
    def test_extension_gets_the_tighter_budget(self):
        assert budget_ms_for("extension") < budget_ms_for("dashboard")

    def test_api_and_dashboard_share_the_default(self):
        assert budget_ms_for("api") == budget_ms_for("dashboard")


class TestEnrichBudget:
    async def test_hanging_provider_is_cut_off_at_the_budget(self, patch_plan, monkeypatch):
        monkeypatch.setattr(cti_service.settings, "cti_budget_ms", 150)
        patch_plan({
            "virustotal": HangingAdapter("virustotal"),
            "urlhaus": HangingAdapter("urlhaus"),
            "whois": HangingAdapter("whois"),
            "dns": HangingAdapter("dns"),
        })

        started = time.perf_counter()
        responses = await enrich("https://example.com")
        elapsed_ms = (time.perf_counter() - started) * 1000

        assert elapsed_ms < 1000
        assert {r.status for r in responses} == {CTIStatus.TIMEOUT}
        assert all("budget" in (r.error or "") for r in responses)

    async def test_fast_provider_survives_a_slow_neighbour(self, patch_plan, monkeypatch):
        monkeypatch.setattr(cti_service.settings, "cti_budget_ms", 200)
        patch_plan({
            "virustotal": HangingAdapter("virustotal"),
            "urlhaus": HangingAdapter("urlhaus"),
            "whois": HangingAdapter("whois"),
            "dns": InstantAdapter("dns"),
        })

        by_source = {r.source: r for r in await enrich("https://example.com")}
        assert by_source["dns"].status == CTIStatus.LIVE
        assert by_source["whois"].status == CTIStatus.TIMEOUT

    async def test_raising_provider_becomes_an_error_response(self, patch_plan):
        patch_plan({
            "virustotal": RaisingAdapter("virustotal"),
            "urlhaus": InstantAdapter("urlhaus"),
            "whois": InstantAdapter("whois"),
            "dns": InstantAdapter("dns"),
        })

        by_source = {r.source: r for r in await enrich("https://example.com")}
        assert by_source["virustotal"].status == CTIStatus.ERROR
        assert "exploded" in by_source["virustotal"].error

    async def test_unconfigured_provider_reports_unknown(self, patch_plan):
        patch_plan({
            "virustotal": None,
            "urlhaus": InstantAdapter("urlhaus"),
            "whois": InstantAdapter("whois"),
            "dns": InstantAdapter("dns"),
        })

        by_source = {r.source: r for r in await enrich("https://example.com")}
        assert by_source["virustotal"].status == CTIStatus.UNKNOWN
