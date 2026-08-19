import sys
from pathlib import Path
import asyncio
from typing import List

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.config import settings
from cti.base import CTIResponse, CTIStatus  # noqa: E402

_PROVIDER_ORDER = ("virustotal", "urlhaus", "whois", "dns")


def _build_provider_plan():
    if settings.cti_mock:
        from cti.mock_adapters import (
            MockDNSAdapter,
            MockURLhausAdapter,
            MockVirusTotalAdapter,
            MockWHOISAdapter,
        )

        return {
            "virustotal": MockVirusTotalAdapter(),
            "urlhaus": MockURLhausAdapter(),
            "whois": MockWHOISAdapter(),
            "dns": MockDNSAdapter(),
        }

    from cti.dns_lookup import DNSAdapter
    from cti.urlhaus import URLhausAdapter
    from cti.whois_lookup import WHOISAdapter

    plan = {
        "urlhaus": URLhausAdapter(),
        "whois": WHOISAdapter(),
        "dns": DNSAdapter(),
    }

    if settings.virustotal_api_key:
        from cti.virustotal import VirusTotalAdapter

        plan["virustotal"] = VirusTotalAdapter(settings.virustotal_api_key)
    else:
        plan["virustotal"] = None

    return plan


def budget_ms_for(source: str) -> int:
    return settings.cti_budget_extension_ms if source == "extension" else settings.cti_budget_ms


async def enrich(url: str, source: str = "api") -> List[CTIResponse]:
    plan = _build_provider_plan()
    tasks: list[tuple[str, asyncio.Future]] = []
    responses: dict[str, CTIResponse] = {}

    for provider in _PROVIDER_ORDER:
        adapter = plan.get(provider)
        if adapter is None:
            responses[provider] = CTIResponse(
                source=provider,
                status=CTIStatus.UNKNOWN,
                hit=None,
                score=None,
                details={},
                error="Provider not configured",
            )
            continue
        tasks.append((provider, asyncio.ensure_future(adapter.lookup(url))))

    if tasks:
        budget_ms = budget_ms_for(source)
        budget = max(budget_ms, 1) / 1000
        await asyncio.wait([task for _, task in tasks], timeout=budget)

        for provider, task in tasks:
            if not task.done():
                task.cancel()
                responses[provider] = CTIResponse(
                    source=provider,
                    status=CTIStatus.TIMEOUT,
                    hit=None,
                    score=None,
                    details={},
                    error=f"Exceeded {budget_ms} ms CTI budget",
                )
                continue

            try:
                result = task.result()
            except asyncio.CancelledError:
                result = None
            except Exception as exc:  # adapter raised instead of returning a response
                responses[provider] = CTIResponse(
                    source=provider,
                    status=CTIStatus.ERROR,
                    hit=None,
                    score=None,
                    details={},
                    error=str(exc),
                )
                continue

            responses[provider] = result if isinstance(result, CTIResponse) else CTIResponse(
                source=provider,
                status=CTIStatus.ERROR,
                hit=None,
                score=None,
                details={},
                error="Adapter returned no response",
            )

    return [responses[provider] for provider in _PROVIDER_ORDER]
