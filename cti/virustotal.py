"""VirusTotal v3 URL reputation adapter."""
import base64
import httpx
from cti.base import BaseCTIAdapter, CTIResponse

VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalAdapter(BaseCTIAdapter):
    def __init__(self, api_key: str):
        self._headers = {"x-apikey": api_key}

    async def lookup(self, url: str) -> CTIResponse:
        url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(f"{VT_BASE}/urls/{url_id}", headers=self._headers)

                if resp.status_code == 404:
                    # Submit for scanning; result won't be available immediately
                    await client.post(f"{VT_BASE}/urls", data={"url": url}, headers=self._headers)
                    return CTIResponse(
                        source="virustotal", hit=False, score=0.0,
                        details={"status": "submitted_for_analysis"},
                    )

                data = resp.json()
                stats = (
                    data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) or 1
                score = malicious / total

                return CTIResponse(
                    source="virustotal",
                    hit=malicious > 0,
                    score=round(score, 4),
                    details={
                        "stats": stats,
                        "malicious_count": malicious,
                        "total_engines": total,
                    },
                )
        except Exception as exc:
            return CTIResponse(source="virustotal", hit=False, score=0.0, details={}, error=str(exc))
