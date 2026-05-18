import axios from 'axios'
import type { ScanRequest, ScanResult } from '../types'

const http = axios.create({
  baseURL: '/api',
  timeout: 30_000,
  headers: { 'Content-Type': 'application/json' },
})

export const api = {
  scan: (req: ScanRequest): Promise<ScanResult> =>
    http.post<ScanResult>('/scan', req).then(r => r.data),

  history: (params?: { limit?: number; offset?: number }): Promise<ScanResult[]> =>
    http.get<ScanResult[]>('/history', { params }).then(r => r.data),

  exportReport: (format: 'csv' | 'json'): Promise<Blob> =>
    http
      .get<Blob>(`/export/${format}`, { responseType: 'blob' })
      .then(r => r.data),

  health: (): Promise<{ status: string }> =>
    http.get<{ status: string }>('/health').then(r => r.data),
}
