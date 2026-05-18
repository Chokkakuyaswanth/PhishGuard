import React, { useState } from 'react'
import { Search, Shield } from 'lucide-react'

interface Props {
  onScan: (url: string) => void
  loading?: boolean
}

export default function ScanForm({ onScan, loading }: Props) {
  const [url, setUrl] = useState('')

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const trimmed = url.trim()
    if (trimmed) onScan(trimmed)
  }

  return (
    <form onSubmit={handleSubmit} className="flex gap-3">
      <div className="flex-1 relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-soc-muted pointer-events-none" />
        <input
          type="text"
          value={url}
          onChange={e => setUrl(e.target.value)}
          placeholder="https://suspicious-domain.xyz/login"
          className="w-full bg-soc-bg border border-soc-border rounded-lg pl-10 pr-4 py-3 text-soc-text font-mono text-sm placeholder-soc-muted/50 focus:outline-none focus:border-soc-accent transition-colors"
          disabled={loading}
          spellCheck={false}
          autoComplete="off"
        />
      </div>
      <button
        type="submit"
        disabled={loading === true || !url.trim()}
        className="flex items-center gap-2 bg-soc-accent text-soc-bg font-semibold px-5 py-3 rounded-lg hover:opacity-90 disabled:opacity-40 transition-opacity text-sm"
      >
        <Shield className="w-4 h-4" />
        {loading ? 'Scanning…' : 'Scan URL'}
      </button>
    </form>
  )
}
