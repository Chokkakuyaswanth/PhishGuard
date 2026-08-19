"""Measure scan latency against a running backend, split by request source.

Usage (from repo root, backend already running):
    python scripts/bench_latency.py
    python scripts/bench_latency.py --url http://127.0.0.1:8000 --runs 20
"""
import argparse
import asyncio
import statistics as st
import time

import httpx

URLS = [
    "https://www.google.com",
    "https://github.com/torvalds/linux",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://docs.python.org/3/library/asyncio.html",
    "https://www.amazon.com/dp/B08N5WRWNW",
    "http://paypa1-secure-login.xyz/account/verify",
    "http://microsofft-account-verify.tk/signin",
    "http://0xc0a80001/secure/verify",
]

TARGET_MS = 500


async def measure(client: httpx.AsyncClient, api: str, url: str, source: str) -> tuple[float, dict]:
    started = time.perf_counter()
    resp = await client.post(f"{api}/api/scan", json={"url": url, "source": source}, timeout=60)
    elapsed = (time.perf_counter() - started) * 1000
    resp.raise_for_status()
    return elapsed, resp.json()


async def run_source(client: httpx.AsyncClient, api: str, source: str, runs: int) -> list[float]:
    # Warm the connection and the model so we report steady state, not cold start.
    await measure(client, api, "https://warmup.example.com", source)
    samples = []
    for i in range(runs):
        elapsed, _ = await measure(client, api, URLS[i % len(URLS)], source)
        samples.append(elapsed)
    return samples


def report(source: str, samples: list[float], target: bool) -> None:
    ordered = sorted(samples)
    p50 = st.median(ordered)
    p95 = ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))]
    over = sum(1 for s in ordered if s >= TARGET_MS)
    verdict = ""
    if target:
        verdict = f"   [{'PASS' if over == 0 else 'FAIL'} vs {TARGET_MS} ms target]"
    print(f"  {source:11} n={len(ordered):3}  p50={p50:7.1f} ms  p95={p95:7.1f} ms  max={max(ordered):7.1f} ms{verdict}")
    if target and over:
        print(f"  {'':11} {over}/{len(ordered)} scans exceeded {TARGET_MS} ms")


async def main() -> None:
    parser = argparse.ArgumentParser(description="PhishGuard scan latency benchmark")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="Backend base URL")
    parser.add_argument("--runs", type=int, default=16, help="Scans per source")
    args = parser.parse_args()

    async with httpx.AsyncClient() as client:
        try:
            health = await client.get(f"{args.url}/api/health", timeout=5)
            health.raise_for_status()
        except Exception as exc:
            raise SystemExit(f"Backend not reachable at {args.url} ({exc}). Start it first.")

        print(f"\n  Backend: {args.url}\n")
        for source in ("extension", "dashboard"):
            samples = await run_source(client, args.url, source, args.runs)
            report(source, samples, target=(source == "extension"))
        print()


if __name__ == "__main__":
    asyncio.run(main())
