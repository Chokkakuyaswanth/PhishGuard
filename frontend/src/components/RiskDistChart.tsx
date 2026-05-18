import {
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer,
} from 'recharts'
import type { ScanResult } from '../types'

const COLORS = {
  safe:       '#3fb950',
  suspicious: '#d29922',
  malicious:  '#f85149',
  unknown:    '#8b949e',
}

interface Props {
  history: ScanResult[]
}

export default function RiskDistChart({ history }: Props) {
  const counts = history.reduce<Record<string, number>>((acc, s) => {
    acc[s.level] = (acc[s.level] ?? 0) + 1
    return acc
  }, {})

  const data = Object.entries(counts).map(([level, count]) => ({ level, count }))

  if (!data.length) {
    return (
      <div className="text-soc-muted text-sm flex items-center justify-center h-[220px]">
        Scan URLs to populate this chart.
      </div>
    )
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie
          data={data}
          dataKey="count"
          nameKey="level"
          cx="50%"
          cy="50%"
          innerRadius={52}
          outerRadius={88}
          paddingAngle={3}
        >
          {data.map(entry => (
            <Cell
              key={entry.level}
              fill={COLORS[entry.level as keyof typeof COLORS] ?? '#8b949e'}
            />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{
            background: '#161b22',
            border: '1px solid #21262d',
            color: '#c9d1d9',
            fontFamily: 'monospace',
            fontSize: 12,
          }}
          formatter={(value: number) => [value, 'scans']}
        />
        <Legend
          formatter={v => (
            <span style={{ color: '#8b949e', fontSize: 12 }}>{v}</span>
          )}
        />
      </PieChart>
    </ResponsiveContainer>
  )
}
