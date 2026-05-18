import { FileText, AlertTriangle } from 'lucide-react'
import ExportButton from '../components/ExportButton'
import RiskBadge from '../components/RiskBadge'
import { useHistory } from '../hooks/useHistory'

export default function ReportPage() {
  const { history } = useHistory(500)
  const malicious   = history.filter(h => h.level === 'malicious')
  const suspicious  = history.filter(h => h.level === 'suspicious')

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <FileText className="w-5 h-5 text-soc-accent" />
          <h1 className="text-lg font-bold text-soc-text tracking-wide">IoC Report</h1>
        </div>
        <div className="flex gap-2">
          <ExportButton format="csv" />
          <ExportButton format="json" />
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 gap-4">
        <div className="bg-soc-surface border border-soc-malicious/30 rounded-xl p-4">
          <div className="text-soc-malicious text-2xl font-bold font-mono">{malicious.length}</div>
          <div className="text-soc-muted text-sm mt-1">Malicious URLs</div>
        </div>
        <div className="bg-soc-surface border border-soc-suspicious/30 rounded-xl p-4">
          <div className="text-soc-suspicious text-2xl font-bold font-mono">{suspicious.length}</div>
          <div className="text-soc-muted text-sm mt-1">Suspicious URLs</div>
        </div>
      </div>

      {/* Malicious IoCs */}
      {malicious.length > 0 && (
        <div className="bg-soc-surface border border-soc-border rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="w-4 h-4 text-soc-malicious" />
            <h2 className="text-soc-text font-semibold text-sm">Malicious Indicators of Compromise</h2>
          </div>
          {malicious.map((item, i) => (
            <div
              key={item.id ?? i}
              className="border border-soc-malicious/20 rounded-lg p-3 font-mono text-sm"
            >
              <div className="flex items-center justify-between gap-4">
                <span className="text-soc-accent truncate">{item.url}</span>
                <RiskBadge level={item.level} score={item.score} size="sm" />
              </div>
              {item.indicators.length > 0 && (
                <div className="mt-2 text-xs text-soc-muted space-y-0.5">
                  {item.indicators.slice(0, 3).map((ind, j) => (
                    <div key={j}>› {ind.description}</div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Suspicious IoCs */}
      {suspicious.length > 0 && (
        <div className="bg-soc-surface border border-soc-border rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="w-4 h-4 text-soc-suspicious" />
            <h2 className="text-soc-text font-semibold text-sm">Suspicious URLs — Requires Review</h2>
          </div>
          {suspicious.map((item, i) => (
            <div
              key={item.id ?? i}
              className="border border-soc-suspicious/20 rounded-lg p-3 font-mono text-sm"
            >
              <div className="flex items-center justify-between gap-4">
                <span className="text-soc-accent truncate">{item.url}</span>
                <RiskBadge level={item.level} score={item.score} size="sm" />
              </div>
              {item.indicators.length > 0 && (
                <div className="mt-2 text-xs text-soc-muted space-y-0.5">
                  {item.indicators.slice(0, 3).map((ind, j) => (
                    <div key={j}>› {ind.description}</div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {!malicious.length && !suspicious.length && (
        <div className="text-soc-muted text-sm bg-soc-surface border border-soc-border rounded-xl p-5">
          No threats detected yet. Scan URLs from the Dashboard to generate a report.
        </div>
      )}
    </div>
  )
}
