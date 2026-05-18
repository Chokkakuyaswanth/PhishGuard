import { useState } from 'react'
import { api } from '../api/client'
import type { ScanResult } from '../types'

export function useScan(onSuccess?: () => void) {
  const [result, setResult] = useState<ScanResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function scan(url: string) {
    setLoading(true)
    setError(null)
    try {
      const res = await api.scan({ url, source: 'dashboard' })
      setResult(res)
      onSuccess?.()
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Scan failed'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return { result, loading, error, scan }
}
