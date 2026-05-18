import { Download } from 'lucide-react'
import { api } from '../api/client'

interface Props {
  format: 'csv' | 'json'
}

export default function ExportButton({ format }: Props) {
  async function handleExport() {
    try {
      const blob = await api.exportReport(format)
      const href = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = href
      anchor.download = `phishguard-ioc-report.${format}`
      anchor.click()
      URL.revokeObjectURL(href)
    } catch {
      // Non-critical: silently fail export
    }
  }

  return (
    <button
      onClick={handleExport}
      className="flex items-center gap-2 border border-soc-border rounded-lg px-4 py-2 text-sm text-soc-muted hover:text-soc-text hover:border-soc-accent transition-colors font-mono"
    >
      <Download className="w-4 h-4" />
      {format.toUpperCase()}
    </button>
  )
}
