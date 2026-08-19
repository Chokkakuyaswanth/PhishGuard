"""VirusTotal v3 URL reputation adapter."""
import asyncio
import base64
import time

import httpx

from cti.base import BaseCTIAdapter, CTIResponse, CTIStatus
from cti.http_client import get_client

VT_BASE = "https://www.virustotal.com/api/v3"
_VT_MIN_GAP = 15.1   # free tier: 4 req/min → 1 per ~15 s
_vt_lock = asyncio.Lock()
_vt_last_call: float = 0.0


class VirusTotalAdapter(BaseCTIAdapter):
    def __init__(self, api_key: str):
        self._headers = {"x-apikey": api_key}

    async def lookup(self, url: str) -> CTIResponse:
        global _vt_last_call
        url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
        started = time.perf_counter()

        def _elapsed() -> int:
            return int((time.perf_counter() - started) * 1000)

        try:
            # Free tier allows 4 req/min. Sleeping out the gap would serialize every
            # scan behind a 15 s lock, so skip the call instead and say so — the
            # decision engine already treats a non-live provider as uncorroborated.
            async with _vt_lock:
                gap = time.monotonic() - _vt_last_call
                if gap < _VT_MIN_GAP:
                    return CTIResponse(
                        source="virustotal",
                        status=CTIStatus.UNKNOWN,
                        hit=None,
                        score=None,
                        details={"status": "rate_limit_deferred", "retry_in_s": round(_VT_MIN_GAP - gap, 1)},
                        error="Skipped to stay within the VirusTotal free-tier rate limit",
                        latency_ms=_elapsed(),
                    )
                _vt_last_call = time.monotonic()

            client = await get_client()
            resp = await client.get(f"{VT_BASE}/urls/{url_id}", headers=self._headers, timeout=8.0)

            if resp.status_code == 429:
                # Push the clock forward so later scans defer instead of retrying;
                # blocking here would stall the whole scan path.
                _vt_last_call = time.monotonic() + 60
                return CTIResponse(
                    source="virustotal",
                    status=CTIStatus.ERROR,
                    hit=None,
                    score=None,
                    details={"status": "rate_limited"},
                    error="VirusTotal rate limit exceeded",
                    latency_ms=_elapsed(),
                )

            if resp.status_code == 404:
                await client.post(f"{VT_BASE}/urls", data={"url": url}, headers=self._headers, timeout=8.0)
                return CTIResponse(
                    source="virustotal",
                    status=CTIStatus.LIVE,
                    hit=False,
                    score=0.0,
                    details={"status": "submitted_for_analysis"},
                    latency_ms=_elapsed(),
                )

            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) or 1
            # Weight suspicious hits at 0.5 so partial signals aren't lost
            score = (malicious + 0.5 * suspicious) / total

            return CTIResponse(
                source="virustotal",
                status=CTIStatus.LIVE,
                hit=malicious > 0 or suspicious > 1,
                score=round(score, 4),
                details={
                    "stats": stats,
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "total_engines": total,
                },
                latency_ms=_elapsed(),
            )
        except httpx.TimeoutException:
            return CTIResponse(
                source="virustotal",
                status=CTIStatus.TIMEOUT,
                hit=None,
                score=None,
                details={},
                error="VirusTotal lookup timed out",
                latency_ms=_elapsed(),
            )
        except Exception as exc:
            return CTIResponse(
                source="virustotal",
                status=CTIStatus.ERROR,
                hit=None,
                score=None,
                details={},
                error=str(exc),
                latency_ms=_elapsed(),
            )
