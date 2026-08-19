"""Deterministic decision policy for ML + CTI evidence."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from app.models.scan import ScanMode
from app.models.threat import RiskLevel
from cti.base import CTIResponse, CTIStatus


DEFAULT_DECISION_THRESHOLDS = {"suspicious": 0.7679, "malicious": 0.985}


@dataclass
class DecisionOutcome:
    risk_score: float
    verdict: RiskLevel
    scan_mode: ScanMode
    explanation: list[str]


class DecisionEngine:
    @staticmethod
    def decide(
        ml_probability: float,
        cti_results: Iterable[CTIResponse],
        thresholds: dict[str, float] | None = None,
    ) -> DecisionOutcome:
        thresholds = thresholds or DEFAULT_DECISION_THRESHOLDS
        suspicious_threshold = float(thresholds.get("suspicious", DEFAULT_DECISION_THRESHOLDS["suspicious"]))
        malicious_threshold = float(thresholds.get("malicious", DEFAULT_DECISION_THRESHOLDS["malicious"]))

        score = max(0.0, min(float(ml_probability), 1.0))
        by_source = {result.source: result for result in cti_results}

        live_confirmed_hit = any(
            result.status == CTIStatus.LIVE and result.hit is True
            for name, result in by_source.items()
            if name in {"virustotal", "urlhaus"}
        )
        live_whois_hit = by_source.get("whois") is not None and (
            by_source["whois"].status == CTIStatus.LIVE and by_source["whois"].hit is True
        )
        live_dns_hit = by_source.get("dns") is not None and (
            by_source["dns"].status == CTIStatus.LIVE and by_source["dns"].hit is True
        )

        statuses = [result.status for result in by_source.values()]
        if not statuses:
            scan_mode = ScanMode.FAILED
        elif all(status == CTIStatus.LIVE for status in statuses):
            scan_mode = ScanMode.FULL
        elif all(status in {CTIStatus.UNKNOWN, CTIStatus.ERROR, CTIStatus.TIMEOUT} for status in statuses):
            scan_mode = ScanMode.ML_ONLY
        else:
            scan_mode = ScanMode.DEGRADED

        # Live CTI corroboration is the strongest signal, but a high-confidence
        # model verdict must still be able to reach MALICIOUS on its own —
        # otherwise no scan can ever exceed SUSPICIOUS while CTI is mocked.
        if live_confirmed_hit:
            risk_score = max(score, 0.97)
            verdict = RiskLevel.MALICIOUS
        elif score >= malicious_threshold:
            risk_score = max(score, 0.9) if scan_mode == ScanMode.FULL else max(score, 0.8)
            verdict = RiskLevel.MALICIOUS
        elif score >= suspicious_threshold or live_whois_hit or live_dns_hit:
            risk_score = _map_suspicious_risk(score, suspicious_threshold)
            verdict = RiskLevel.SUSPICIOUS
        else:
            risk_score = _map_no_threat_risk(score, suspicious_threshold)
            verdict = RiskLevel.NO_THREAT_DETECTED

        explanation: list[str] = []
        if score >= suspicious_threshold:
            explanation.append(f"ML detector assigned {score:.1%} phishing probability")
        elif score >= 0.5:
            explanation.append(f"ML detector assigned elevated phishing probability ({score:.1%})")

        vt = by_source.get("virustotal")
        if vt and vt.status == CTIStatus.LIVE and vt.hit:
            cnt = vt.details.get("malicious_count", "?")
            total = vt.details.get("total_engines", "?")
            explanation.append(f"VirusTotal flagged the URL ({cnt}/{total} engines)")
        elif vt and vt.status != CTIStatus.LIVE:
            explanation.append(f"VirusTotal status: {vt.status.value}")

        uh = by_source.get("urlhaus")
        if uh and uh.status == CTIStatus.LIVE and uh.hit:
            explanation.append("URLhaus has a matching malicious URL record")
        elif uh and uh.status != CTIStatus.LIVE:
            explanation.append(f"URLhaus status: {uh.status.value}")

        dns = by_source.get("dns")
        if dns and dns.status == CTIStatus.LIVE and dns.hit:
            explanation.append("Domain does not resolve in DNS")
        elif dns and dns.status != CTIStatus.LIVE:
            explanation.append(f"DNS status: {dns.status.value}")

        whois = by_source.get("whois")
        if whois and whois.status == CTIStatus.LIVE and whois.hit:
            age = whois.details.get("domain_age_days", "?")
            explanation.append(f"WHOIS reports a newly registered domain ({age} days old)")
        elif whois and whois.status != CTIStatus.LIVE:
            explanation.append(f"WHOIS status: {whois.status.value}")

        if scan_mode != ScanMode.FULL and not live_confirmed_hit:
            explanation.append(
                "Verdict rests on the model alone — live CTI corroboration was unavailable"
            )

        return DecisionOutcome(
            risk_score=round(risk_score, 4),
            verdict=verdict,
            scan_mode=scan_mode,
            explanation=explanation,
        )


def _map_no_threat_risk(score: float, suspicious_threshold: float) -> float:
    cap = 0.39
    if suspicious_threshold <= 0:
        return min(score, cap)
    normalized = max(0.0, min(score / suspicious_threshold, 1.0))
    return normalized * cap


def _map_suspicious_risk(score: float, suspicious_threshold: float) -> float:
    floor = 0.4
    cap = 0.79
    span = max(1e-6, 1.0 - suspicious_threshold)
    normalized = max(0.0, min((score - suspicious_threshold) / span, 1.0))
    return floor + normalized * (cap - floor)
