"""Passive DNS resolution — unresolvable or thinly-hosted domains carry elevated risk."""
import asyncio
import re
import socket
import time
import urllib.parse

from cti.base import BaseCTIAdapter, CTIResponse, CTIStatus

_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_DNS_TIMEOUT = 3.0


class DNSAdapter(BaseCTIAdapter):
    async def lookup(self, url: str) -> CTIResponse:
        started = time.perf_counter()
        domain = urllib.parse.urlparse(url).netloc.split(":")[0]

        if not domain or _IP_RE.match(domain):
            return CTIResponse(
                source="dns",
                status=CTIStatus.LIVE,
                hit=bool(domain),
                score=1.0 if domain else None,
                details={"note": "raw IP address — no DNS resolution involved"},
                latency_ms=int((time.perf_counter() - started) * 1000),
            )

        try:
            loop = asyncio.get_running_loop()
            infos = await asyncio.wait_for(
                loop.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP),
                timeout=_DNS_TIMEOUT,
            )
            addresses = sorted({info[4][0] for info in infos})
            return CTIResponse(
                source="dns",
                status=CTIStatus.LIVE,
                hit=False,
                score=0.0,
                details={"resolved": True, "address_count": len(addresses), "addresses": addresses[:8]},
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
        except asyncio.TimeoutError:
            return CTIResponse(
                source="dns",
                status=CTIStatus.TIMEOUT,
                hit=None,
                score=None,
                details={},
                error="DNS resolution timed out",
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
        except socket.gaierror as exc:
            # NXDOMAIN on a URL someone is actively visiting is a strong phishing signal.
            return CTIResponse(
                source="dns",
                status=CTIStatus.LIVE,
                hit=True,
                score=0.85,
                details={"resolved": False, "reason": str(exc)},
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
        except Exception as exc:
            return CTIResponse(
                source="dns",
                status=CTIStatus.ERROR,
                hit=None,
                score=None,
                details={},
                error=str(exc),
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
