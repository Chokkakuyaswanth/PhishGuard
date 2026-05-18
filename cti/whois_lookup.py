"""WHOIS domain age and registrar enrichment."""
import asyncio
import urllib.parse
from datetime import datetime, timezone
from typing import Optional

import whois
from cti.base import BaseCTIAdapter, CTIResponse


class WHOISAdapter(BaseCTIAdapter):
    async def lookup(self, url: str) -> CTIResponse:
        domain = urllib.parse.urlparse(url).netloc.split(":")[0].replace("www.", "")
        try:
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(None, whois.whois, domain)

            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]

            age_days: Optional[int] = None
            age_score = 0.0
            if creation:
                if creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - creation).days
                if age_days < 30:
                    age_score = 1.0
                elif age_days < 180:
                    age_score = 0.5

            return CTIResponse(
                source="whois",
                hit=age_score > 0,
                score=age_score,
                details={
                    "domain_age_days": age_days,
                    "registrar": w.registrar,
                    "creation_date": str(creation),
                    "expiration_date": str(w.expiration_date),
                    "country": w.country,
                },
            )
        except Exception as exc:
            return CTIResponse(source="whois", hit=False, score=0.0, details={}, error=str(exc))
