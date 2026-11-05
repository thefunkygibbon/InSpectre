import { useEffect, useRef } from 'react'
import { Loader2 } from 'lucide-react'

// Turn raw job protocol lines (LOG:, *_DONE, *_ERROR:) into display text.
export function formatJobLine(line) {
  if (line.startsWith('LOG:')) return line.replace(/^LOG:\s*/, '')
  const err = line.match(/^(DEPLOY|RECREATE|UPDATE)_ERROR:(.*)$/)
  if (err) return '❌ ' + err[2].trim()
  if (line === 'DEPLOY_DONE') return '✅ Deployed successfully.'
  if (line === 'RECREATE_DONE') return '✅ Container restored successfully.'
  if (line.startsWith('UPDATE_DONE:')) return `${line.endsWith(':success') ? '✅' : '⚠'} Update finished: ${line.slice(12)}`
  return line
}

function lineColor(l) {
  if (l.startsWith('❌') || /✗|ROLLBACK FAILED/.test(l)) return '#ef4444'
  if (l.startsWith('✅') || l.includes('✓')) return '#22c55e'
  if (/⚠|Warning|ROLLBACK/.test(l)) return '#f59e0b'
  return 'var(--color-text-muted)'
}

export function JobLog({ lines, running, maxHeight = '40vh' }) {
  const ref = useRef(null)
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight
  }, [lines, running])
  if (!lines.length && !running) return null
  return (
    <div ref={ref} className="rounded-lg p-3 space-y-0.5 text-[11px] font-mono"
      style={{ background: 'var(--color-surface-offset)', border: '1px solid var(--color-border)', maxHeight, overflowY: 'auto' }}>
      {lines.map((l, i) => (
        <div key={i} className="whitespace-pre-wrap break-words" style={{ color: lineColor(l) }}>{l}</div>
      ))}
      {running && (
        <div className="flex items-center gap-1.5 pt-1" style={{ color: 'var(--color-text-faint)' }}>
          <Loader2 size={10} className="animate-spin" />
          Working… runs in the background on the server — safe to close this panel.
        </div>
      )}
    </div>
  )
}
