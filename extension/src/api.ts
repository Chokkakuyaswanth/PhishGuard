const BACKEND_URL = 'http://localhost:8000/api'

export interface ScanTiming {
  /** Navigation-event to verdict, as the user experiences it. */
  total_ms: number
  /** Time inside fetch() alone; 0 on a cache hit. */
  fetch_ms: number
  cached: boolean
}

export interface StoredScan extends ScanResult {
  timing?: ScanTiming
}

export interface ScanOutcome {
  result: ScanResult
  fetchMs: number
  cached: boolean
}

export interface ScanResult {
  url: string
  score: number
  risk_score: number
  level: 'no_threat_detected' | 'safe' | 'suspicious' | 'malicious' | 'unknown'
  verdict: 'no_threat_detected' | 'safe' | 'suspicious' | 'malicious' | 'unknown'
  scan_mode: 'full' | 'degraded' | 'ml_only' | 'failed'
  ml_probability: number
  explanation: string[]
  indicators: Array<{ type: string; severity: string; description: string }>
}

// Per-URL cache with 60s TTL — prevents hammering the API on every navigation.
// Held in chrome.storage.session rather than a module-scope Map: MV3 tears the
// service worker down after ~30s idle, which would drop an in-memory cache long
// before its TTL expired.
const CACHE_TTL = 60_000
const CACHE_PREFIX = 'scan_cache_'

type CacheEntry = { result: ScanResult; ts: number }

async function readCache(url: string): Promise<ScanResult | null> {
  try {
    const key = CACHE_PREFIX + url
    const stored = await chrome.storage.session.get(key)
    const entry = stored[key] as CacheEntry | undefined
    if (entry && Date.now() - entry.ts < CACHE_TTL) return entry.result
    if (entry) await chrome.storage.session.remove(key)
    return null
  } catch {
    return null
  }
}

async function writeCache(url: string, result: ScanResult): Promise<void> {
  try {
    await chrome.storage.session.set({ [CACHE_PREFIX + url]: { result, ts: Date.now() } })
  } catch {
    // Session storage is best-effort; a miss only costs an extra request.
  }
}

export async function scanUrl(url: string): Promise<ScanOutcome | null> {
  const hit = await readCache(url)
  if (hit) return { result: hit, fetchMs: 0, cached: true }

  const started = performance.now()
  try {
    const resp = await fetch(`${BACKEND_URL}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, source: 'extension' }),
    })
    const fetchMs = Math.round(performance.now() - started)
    if (!resp.ok) return null
    const result: ScanResult = await resp.json()
    await writeCache(url, result)
    return { result, fetchMs, cached: false }
  } catch {
    return null
  }
}
