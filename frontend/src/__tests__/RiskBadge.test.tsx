import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import RiskBadge from '../components/RiskBadge'

describe('RiskBadge', () => {
  it('renders SAFE label', () => {
    render(<RiskBadge level="safe" />)
    expect(screen.getByText(/SAFE/)).toBeInTheDocument()
  })

  it('renders SUSPICIOUS label', () => {
    render(<RiskBadge level="suspicious" />)
    expect(screen.getByText(/SUSPICIOUS/)).toBeInTheDocument()
  })

  it('renders MALICIOUS label', () => {
    render(<RiskBadge level="malicious" />)
    expect(screen.getByText(/MALICIOUS/)).toBeInTheDocument()
  })

  it('renders UNKNOWN label', () => {
    render(<RiskBadge level="unknown" />)
    expect(screen.getByText(/UNKNOWN/)).toBeInTheDocument()
  })

  it('shows score percentage when provided', () => {
    render(<RiskBadge level="safe" score={0.42} />)
    expect(screen.getByText('42%')).toBeInTheDocument()
  })

  it('omits score when not provided', () => {
    render(<RiskBadge level="safe" />)
    expect(screen.queryByText(/%/)).not.toBeInTheDocument()
  })

  it('applies correct color class for safe level', () => {
    const { container } = render(<RiskBadge level="safe" />)
    const badge = container.firstChild as HTMLElement
    expect(badge.className).toContain('soc-safe')
  })

  it('applies correct color class for malicious level', () => {
    const { container } = render(<RiskBadge level="malicious" />)
    const badge = container.firstChild as HTMLElement
    expect(badge.className).toContain('soc-malicious')
  })

  it('uses sm size class by default', () => {
    const { container } = render(<RiskBadge level="safe" />)
    const badge = container.firstChild as HTMLElement
    expect(badge.className).toContain('px-3')  // md default
  })

  it('uses lg size class when specified', () => {
    const { container } = render(<RiskBadge level="safe" size="lg" />)
    const badge = container.firstChild as HTMLElement
    expect(badge.className).toContain('px-4')
  })
})
