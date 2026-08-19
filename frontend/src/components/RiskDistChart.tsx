import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import type { RiskLevel, ScanStats } from '../api'

const LEVEL_META: Record<RiskLevel, { label: string; color: string }> = {
  no_threat_detected: { label: 'No threat', color: '#3fb950' },
  safe: { label: 'Safe', color: '#3fb950' },
  suspicious: { label: 'Suspicious', color: '#d29922' },
  malicious: { label: 'Malicious', color: '#f85149' },
}

type Props = { stats: ScanStats }

export default function RiskDistChart({ stats }: Props) {
  const data = (Object.keys(LEVEL_META) as RiskLevel[])
    .filter((level) => level !== 'safe')
    .map((level) => ({
      name: LEVEL_META[level].label,
      value: stats.by_level[level] ?? 0,
      color: LEVEL_META[level].color,
    }))
    .filter((entry) => entry.value > 0)

  if (!data.length) {
    return (
      <div className="flex h-56 items-center justify-center text-sm text-soc-muted">
        No scans recorded yet — run a scan to populate the distribution.
      </div>
    )
  }

  return (
    <div className="h-56">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie data={data} dataKey="value" nameKey="name" innerRadius="55%" outerRadius="80%" paddingAngle={2}>
            {data.map((entry) => (
              <Cell key={entry.name} fill={entry.color} stroke="transparent" />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: '#161b22',
              border: '1px solid #30363d',
              borderRadius: '0.75rem',
              color: '#e6edf3',
            }}
          />
          <Legend verticalAlign="bottom" height={24} wrapperStyle={{ fontSize: '0.75rem', color: '#8b949e' }} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  )
}
