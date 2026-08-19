"""WHOIS domain age and registrar enrichment."""
import asyncio
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Optional
import time

import whois
from cti.base import BaseCTIAdapter, CTIResponse, CTIStatus

_IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
_WHOIS_TIMEOUT = 5.0

# Cancelling the awaiting coroutine does not stop the underlying blocking call,
# so WHOIS threads outlive their scan. On the shared default executor they
# starve loop.getaddrinfo and every DNS lookup times out behind them.
_WHOIS_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="whois")


class WHOISAdapter(BaseCTIAdapter):
    async def lookup(self, url: str) -> CTIResponse:
        started = time.perf_counter()
        netloc = urllib.parse.urlparse(url).netloc.split(":")[0]
        domain = netloc.replace("www.", "")

        # Raw IPs have no WHOIS record — treat as maximum risk
        if _IP_RE.match(domain):
            return CTIResponse(
                source="whois",
                status=CTIStatus.LIVE,
                hit=True,
                score=1.0,
                details={"domain_age_days": 0, "note": "raw IP address — no registered domain"},
                latency_ms=int((time.perf_counter() - started) * 1000),
            )

        try:
            loop = asyncio.get_running_loop()
            w = await asyncio.wait_for(
                loop.run_in_executor(_WHOIS_EXECUTOR, whois.whois, domain),
                timeout=_WHOIS_TIMEOUT,
            )

            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]

            age_days: Optional[int] = None
            age_score = 0.0
            if creation:
                if isinstance(creation, datetime) and creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)
                if isinstance(creation, datetime):
                    age_days = (datetime.now(timezone.utc) - creation).days
                    if age_days < 30:
                        age_score = 1.0
                    elif age_days < 180:
                        age_score = 0.5
                    elif age_days < 365:
                        age_score = 0.2

            return CTIResponse(
                source="whois",
                status=CTIStatus.LIVE,
                hit=age_score > 0,
                score=age_score,
                details={
                    "domain_age_days": age_days,
                    "registrar": getattr(w, "registrar", None),
                    "creation_date": str(creation) if creation else None,
                    "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                    "country": getattr(w, "country", None),
                },
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
        except asyncio.TimeoutError:
            return CTIResponse(
                source="whois",
                status=CTIStatus.TIMEOUT,
                hit=None,
                score=None,
                details={},
                error="WHOIS lookup timed out",
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
        except Exception as exc:
            return CTIResponse(
                source="whois",
                status=CTIStatus.ERROR,
                hit=None,
                score=None,
                details={},
                error=str(exc),
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
