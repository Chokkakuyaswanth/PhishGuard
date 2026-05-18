import { useState } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import type { ScanResult } from '../types'

const SEVERITY_CLS: Record<string, string> = {
  critical: 'text-soc-malicious font-bold',
  high:     'text-orange-400',
  medium:   'text-soc-suspicious',
  low:      'text-soc-muted',
}

interface Props {
  result: ScanResult
}

export default function ThreatDetails({ result }: Props) {
  const [open, setOpen] = useState(true)
  const count = result.indicators.length

  return (
    <div className="border border-soc-border rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 bg-soc-surface hover:bg-soc-border/30 transition-colors text-left"
      >
        <span className="text-soc-text font-semibold text-sm">
          Threat Indicators
          <span className="ml-2 text-xs text-soc-muted font-normal">({count})</span>
        </span>
        {open ? (
          <ChevronDown className="w-4 h-4 text-soc-muted" />
        ) : (
          <ChevronRight className="w-4 h-4 text-soc-muted" />
        )}
      </button>

      {open && (
        <div className="px-4 pb-4 pt-3 space-y-3 bg-soc-bg/50">
          {result.explanation.length > 0 && (
            <ul className="space-y-1 text-sm text-soc-muted border-b border-soc-border pb-3">
              {result.explanation.map((line, i) => (
                <li key={i} className="flex gap-2">
                  <span className="text-soc-suspicious shrink-0">›</span>
                  {line}
                </li>
              ))}
            </ul>
          )}

          {count > 0 ? (
            result.indicators.map((ind, i) => (
              <div key={i} className="flex items-start gap-3 text-sm font-mono">
                <span className={`shrink-0 uppercase text-xs pt-0.5 ${SEVERITY_CLS[ind.severity] ?? ''}`}>
                  {ind.severity}
                </span>
                <span className="text-soc-text flex-1">{ind.description}</span>
                <span className="text-soc-muted text-xs shrink-0">{ind.source}</span>
              </div>
            ))
          ) : (
            <p className="text-soc-muted text-sm">No threat indicators detected.</p>
          )}
        </div>
      )}
    </div>
  )
}
