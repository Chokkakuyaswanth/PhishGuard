import { Clock } from 'lucide-react'
import ScanHistory from '../components/ScanHistory'
import ExportButton from '../components/ExportButton'
import { useHistory } from '../hooks/useHistory'

export default function HistoryPage() {
  const { history, loading } = useHistory(200)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Clock className="w-5 h-5 text-soc-accent" />
          <h1 className="text-lg font-bold text-soc-text tracking-wide">Scan History</h1>
        </div>
        <div className="flex gap-2">
          <ExportButton format="csv" />
          <ExportButton format="json" />
        </div>
      </div>

      <div className="bg-soc-surface border border-soc-border rounded-xl p-5">
        <ScanHistory history={history} loading={loading} />
      </div>
    </div>
  )
}
