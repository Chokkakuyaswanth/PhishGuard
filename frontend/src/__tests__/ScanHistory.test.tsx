import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import ScanHistory from '../components/ScanHistory'
import type { ScanResult } from '../types'

let _seq = 0
const makeScan = (overrides: Partial<ScanResult> = {}): ScanResult => ({
  id: `test-id-${++_seq}`,
  url: 'https://example.com',
  score: 0.1,
  level: 'safe',
  ml_probability: 0.05,
  indicators: [],
  explanation: [],
  source: 'dashboard',
  scanned_at: new Date().toISOString(),
  ...overrides,
})

describe('ScanHistory', () => {
  it('shows loading state', () => {
    render(<ScanHistory history={[]} loading={true} />)
    expect(screen.getByText(/Loading history/)).toBeInTheDocument()
  })

  it('shows empty state when no history', () => {
    render(<ScanHistory history={[]} loading={false} />)
    expect(screen.getByText(/No scans recorded/)).toBeInTheDocument()
  })

  it('renders a URL row', () => {
    const scans = [makeScan({ url: 'https://github.com' })]
    render(<ScanHistory history={scans} loading={false} />)
    expect(screen.getByText('https://github.com')).toBeInTheDocument()
  })

  it('renders multiple rows', () => {
    const scans = [
      makeScan({ url: 'https://first.com' }),
      makeScan({ url: 'https://second.com' }),
    ]
    render(<ScanHistory history={scans} loading={false} />)
    expect(screen.getByText('https://first.com')).toBeInTheDocument()
    expect(screen.getByText('https://second.com')).toBeInTheDocument()
  })

  it('shows score as percentage', () => {
    const scans = [makeScan({ score: 0.42 })]
    render(<ScanHistory history={scans} loading={false} />)
    expect(screen.getByText('42%')).toBeInTheDocument()
  })

  it('renders SAFE badge for safe scans', () => {
    const scans = [makeScan({ level: 'safe' })]
    render(<ScanHistory history={scans} loading={false} />)
    expect(screen.getByText(/SAFE/)).toBeInTheDocument()
  })

  it('renders SUSPICIOUS badge for suspicious scans', () => {
    const scans = [makeScan({ level: 'suspicious', score: 0.5 })]
    render(<ScanHistory history={scans} loading={false} />)
    expect(screen.getByText(/SUSPICIOUS/)).toBeInTheDocument()
  })

  it('renders MALICIOUS badge for malicious scans', () => {
    const scans = [makeScan({ level: 'malicious', score: 0.9 })]
    render(<ScanHistory history={scans} loading={false} />)
    expect(screen.getByText(/MALICIOUS/)).toBeInTheDocument()
  })

  it('shows just now for very recent scans', () => {
    const scans = [makeScan({ scanned_at: new Date().toISOString() })]
    render(<ScanHistory history={scans} loading={false} />)
    expect(screen.getByText('just now')).toBeInTheDocument()
  })
})
