import type { RiskLevel } from '../types'

const STYLES: Record<RiskLevel, string> = {
  safe:       'bg-soc-safe/10 text-soc-safe border-soc-safe/30',
  suspicious: 'bg-soc-suspicious/10 text-soc-suspicious border-soc-suspicious/30',
  malicious:  'bg-soc-malicious/10 text-soc-malicious border-soc-malicious/30',
  unknown:    'bg-soc-muted/10 text-soc-muted border-soc-muted/30',
}

const LABELS: Record<RiskLevel, string> = {
  safe:       '✓ SAFE',
  suspicious: '⚠ SUSPICIOUS',
  malicious:  '✗ MALICIOUS',
  unknown:    '? UNKNOWN',
}

const SIZE: Record<'sm' | 'md' | 'lg', string> = {
  sm: 'text-xs px-2 py-0.5',
  md: 'text-sm px-3 py-1',
  lg: 'text-base px-4 py-2',
}

interface Props {
  level: RiskLevel
  score?: number
  size?: 'sm' | 'md' | 'lg'
}

export default function RiskBadge({ level, score, size = 'md' }: Props) {
  return (
    <span
      className={`inline-flex items-center gap-2 font-mono font-semibold rounded border tracking-wide ${STYLES[level]} ${SIZE[size]}`}
    >
      {LABELS[level]}
      {score !== undefined && (
        <span className="opacity-60 text-xs">{(score * 100).toFixed(0)}%</span>
      )}
    </span>
  )
}
