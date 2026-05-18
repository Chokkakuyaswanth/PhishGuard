import { useState, useEffect, useCallback } from 'react'
import { api } from '../api/client'
import type { ScanResult } from '../types'

export function useHistory(limit = 50, offset = 0) {
  const [history, setHistory] = useState<ScanResult[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [tick, setTick] = useState(0)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    api
      .history({ limit, offset })
      .then(data => { if (!cancelled) setHistory(data) })
      .catch(e => { if (!cancelled) setError(e.message) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [limit, offset, tick])

  const refresh = useCallback(() => setTick(t => t + 1), [])

  return { history, loading, error, refresh }
}
