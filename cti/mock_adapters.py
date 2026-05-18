"""
Mock CTI adapters used when API keys are absent (CTI_MOCK=true).
Returns structurally correct, plausible-looking responses for local dev.
"""
from cti.base import BaseCTIAdapter, CTIResponse

_PHISH_SIGNALS = frozenset(["login", "secure", "verify", "paypal", "account", "banking", "malware"])


class MockVirusTotalAdapter(BaseCTIAdapter):
    async def lookup(self, url: str) -> CTIResponse:
        flagged = any(s in url.lower() for s in _PHISH_SIGNALS)
        malicious = 5 if flagged else 0
        total = 72
        return CTIResponse(
            source="virustotal",
            hit=flagged,
            score=round(malicious / total, 4),
            details={
                "stats": {"malicious": malicious, "harmless": total - malicious, "suspicious": 0},
                "malicious_count": malicious,
                "total_engines": total,
                "mock": True,
            },
        )


class MockURLhausAdapter(BaseCTIAdapter):
    async def lookup(self, url: str) -> CTIResponse:
        hit = any(s in url.lower() for s in ("malware", "phishing", "hack", "exploit"))
        return CTIResponse(
            source="urlhaus",
            hit=hit,
            score=1.0 if hit else 0.0,
            details={"query_status": "is_db" if hit else "no_results", "mock": True},
        )


class MockWHOISAdapter(BaseCTIAdapter):
    async def lookup(self, url: str) -> CTIResponse:
        return CTIResponse(
            source="whois",
            hit=False,
            score=0.0,
            details={
                "domain_age_days": 730,
                "registrar": "Mock Registrar LLC",
                "creation_date": "2022-01-01 00:00:00+00:00",
                "country": "US",
                "mock": True,
            },
        )
