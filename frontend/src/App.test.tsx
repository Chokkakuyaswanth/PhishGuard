import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import Dashboard from './pages/Dashboard'
import RiskDistChart from './components/RiskDistChart'
import * as api from './api'
import type { ScanResult, ScanStats } from './api'

vi.mock('./api', async () => {
  const actual = await vi.importActual<typeof api>('./api')
  return { ...actual, fetchHistory: vi.fn(), fetchStats: vi.fn() }
})

const mockedApi = api as unknown as {
  fetchHistory: ReturnType<typeof vi.fn>
  fetchStats: ReturnType<typeof vi.fn>
}

function makeScan(id: string, level: ScanResult['level']): ScanResult {
  return {
    id,
    url: `https://example.com/${id}`,
    score: 0.1,
    risk_score: 0.1,
    level,
    verdict: level,
    scan_mode: 'degraded',
    ml_probability: 0.1,
    scanned_at: new Date().toISOString(),
    source: 'api',
    explanation: [],
    indicators: [],
  }
}

const STATS: ScanStats = {
  total: 412,
  by_level: { no_threat_detected: 380, safe: 0, suspicious: 24, malicious: 8 },
}

describe('Dashboard counters', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('reports totals from /stats, not from the five-row activity page', async () => {
    mockedApi.fetchHistory.mockResolvedValue([
      makeScan('a', 'no_threat_detected'),
      makeScan('b', 'no_threat_detected'),
    ])
    mockedApi.fetchStats.mockResolvedValue(STATS)

    render(<MemoryRouter><Dashboard /></MemoryRouter>)

    // The regression this guards: counting the recent-activity page would
    // render 2 scans / 0 malicious instead of the real corpus totals.
    await waitFor(() => expect(screen.getByText('412')).toBeInTheDocument())
    expect(screen.getByText('24')).toBeInTheDocument()
    expect(screen.getByText('8')).toBeInTheDocument()
  })

  it('falls back to zeroes when the backend is unreachable', async () => {
    mockedApi.fetchHistory.mockRejectedValue(new Error('offline'))
    mockedApi.fetchStats.mockRejectedValue(new Error('offline'))

    render(<MemoryRouter><Dashboard /></MemoryRouter>)

    await waitFor(() => expect(screen.getByText(/No scan history is available yet/i)).toBeInTheDocument())
  })
})

describe('RiskDistChart', () => {
  it('prompts for a scan when nothing has been recorded', () => {
    render(<RiskDistChart stats={{ total: 0, by_level: { no_threat_detected: 0, safe: 0, suspicious: 0, malicious: 0 } }} />)
    expect(screen.getByText(/No scans recorded yet/i)).toBeInTheDocument()
  })

  it('renders a distribution once scans exist', () => {
    const { container } = render(<RiskDistChart stats={STATS} />)
    expect(screen.queryByText(/No scans recorded yet/i)).not.toBeInTheDocument()
    expect(container.querySelector('.recharts-responsive-container')).toBeTruthy()
  })
})
