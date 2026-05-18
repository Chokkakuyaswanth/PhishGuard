"""URLhaus (abuse.ch) adapter — no API key required."""
import httpx
from cti.base import BaseCTIAdapter, CTIResponse

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"


class URLhausAdapter(BaseCTIAdapter):
    async def lookup(self, url: str) -> CTIResponse:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(URLHAUS_API, data={"url": url})
            data = resp.json()
            in_db = data.get("query_status") == "is_db"
            return CTIResponse(
                source="urlhaus",
                hit=in_db,
                score=1.0 if in_db else 0.0,
                details={
                    "query_status": data.get("query_status"),
                    "threat": data.get("threat"),
                    "tags": data.get("tags", []),
                    "date_added": data.get("date_added"),
                } if in_db else {"query_status": data.get("query_status")},
            )
        except Exception as exc:
            return CTIResponse(source="urlhaus", hit=False, score=0.0, details={}, error=str(exc))
