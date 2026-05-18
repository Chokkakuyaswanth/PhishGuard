import { Shield, Activity } from 'lucide-react'
import ScanForm from '../components/ScanForm'
import RiskBadge from '../components/RiskBadge'
import ThreatDetails from '../components/ThreatDetails'
import RiskDistChart from '../components/RiskDistChart'
import { useScan } from '../hooks/useScan'
import { useHistory } from '../hooks/useHistory'

export default function Dashboard() {
  const { history, refresh } = useHistory(20)
  const { result, loading, error, scan } = useScan(refresh)

  const maliciousCount   = history.filter(h => h.level === 'malicious').length
  const suspiciousCount  = history.filter(h => h.level === 'suspicious').length
  const safeCount        = history.filter(h => h.level === 'safe').length

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Shield className="w-5 h-5 text-soc-accent" />
        <h1 className="text-lg font-bold text-soc-text tracking-wide">URL Threat Scanner</h1>
      </div>

      {/* Scan input */}
      <div className="bg-soc-surface border border-soc-border rounded-xl p-5">
        <ScanForm onScan={scan} loading={loading} />
        {error && (
          <p className="mt-3 text-soc-malicious text-xs font-mono">{error}</p>
        )}
      </div>

      {/* Latest scan result */}
      {result && (
        <div className="bg-soc-surface border border-soc-border rounded-xl p-5 space-y-4">
          <div className="flex items-start justify-between gap-4">
            <span
              className="font-mono text-soc-muted text-xs truncate max-w-xl"
              title={result.url}
            >
              {result.url}
            </span>
            <RiskBadge level={result.level} score={result.score} size="lg" />
          </div>

          <div className="grid grid-cols-3 gap-4 text-sm font-mono">
            <div>
              <div className="text-soc-muted text-xs mb-1">ML Probability</div>
              <div className="text-soc-text font-bold text-lg">
                {(result.ml_probability * 100).toFixed(1)}%
              </div>
            </div>
            <div>
              <div className="text-soc-muted text-xs mb-1">Risk Score</div>
              <div className="text-soc-text font-bold text-lg">
                {(result.score * 100).toFixed(0)}<span className="text-soc-muted text-sm">/100</span>
              </div>
            </div>
            <div>
              <div className="text-soc-muted text-xs mb-1">Indicators</div>
              <div className="text-soc-text font-bold text-lg">{result.indicators.length}</div>
            </div>
          </div>

          <ThreatDetails result={result} />
        </div>
      )}

      {/* Stats row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div className="bg-soc-surface border border-soc-border rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <Activity className="w-4 h-4 text-soc-accent" />
            <h2 className="text-soc-text font-semibold text-sm">Risk Distribution</h2>
          </div>
          <RiskDistChart history={history} />
        </div>

        <div className="bg-soc-surface border border-soc-border rounded-xl p-5">
          <h2 className="text-soc-text font-semibold text-sm mb-4">Session Overview</h2>
          <div className="space-y-3 text-sm font-mono">
            <div className="flex justify-between items-center">
              <span className="text-soc-muted">Total Scanned</span>
              <span className="text-soc-text font-bold">{history.length}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-soc-muted">Malicious</span>
              <span className="text-soc-malicious font-bold">{maliciousCount}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-soc-muted">Suspicious</span>
              <span className="text-soc-suspicious font-bold">{suspiciousCount}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-soc-muted">Safe</span>
              <span className="text-soc-safe font-bold">{safeCount}</span>
            </div>
            {history.length > 0 && (
              <div className="flex justify-between items-center pt-2 border-t border-soc-border">
                <span className="text-soc-muted">Threat Rate</span>
                <span className="text-soc-text font-bold">
                  {((maliciousCount + suspiciousCount) / history.length * 100).toFixed(0)}%
                </span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
