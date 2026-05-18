import type { ScanResult } from '../types'
import RiskBadge from './RiskBadge'

function timeAgo(iso?: string): string {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60_000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

interface Props {
  history: ScanResult[]
  loading?: boolean
}

export default function ScanHistory({ history, loading }: Props) {
  if (loading) {
    return <div className="text-soc-muted text-sm animate-pulse">Loading history…</div>
  }
  if (!history.length) {
    return <div className="text-soc-muted text-sm">No scans recorded yet.</div>
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm font-mono">
        <thead>
          <tr className="text-soc-muted border-b border-soc-border text-left">
            <th className="py-2 pr-4 font-medium">URL</th>
            <th className="py-2 pr-4 font-medium">Risk</th>
            <th className="py-2 pr-4 font-medium">Score</th>
            <th className="py-2 font-medium">Scanned</th>
          </tr>
        </thead>
        <tbody>
          {history.map((item, i) => (
            <tr
              key={item.id ?? i}
              className="border-b border-soc-border/40 hover:bg-soc-border/20 transition-colors"
            >
              <td className="py-2.5 pr-4 max-w-xs">
                <span className="text-soc-accent truncate block" title={item.url}>
                  {item.url}
                </span>
              </td>
              <td className="py-2.5 pr-4">
                <RiskBadge level={item.level} size="sm" />
              </td>
              <td className="py-2.5 pr-4 text-soc-muted">
                {(item.score * 100).toFixed(0)}%
              </td>
              <td className="py-2.5 text-soc-muted">{timeAgo(item.scanned_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
