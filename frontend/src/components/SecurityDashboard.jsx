import { useState, useEffect } from 'react'
import {
  ShieldAlert, ShieldCheck, X, RefreshCw,
  AlertTriangle, Info, Clock,
} from 'lucide-react'
import { api } from '../api'

const SEV_CFG = {
  critical: { label: 'Critical', color: '#ef4444', bg: 'rgba(239,68,68,0.15)',  border: 'rgba(239,68,68,0.35)'  },
  high:     { label: 'High',     color: '#f97316', bg: 'rgba(249,115,22,0.15)', border: 'rgba(249,115,22,0.35)' },
  medium:   { label: 'Medium',   color: '#f59e0b', bg: 'rgba(245,158,11,0.15)', border: 'rgba(245,158,11,0.35)' },
  low:      { label: 'Low',      color: '#3b82f6', bg: 'rgba(59,130,246,0.15)', border: 'rgba(59,130,246,0.35)' },
  info:     { label: 'Info',     color: '#8b5cf6', bg: 'rgba(139,92,246,0.15)', border: 'rgba(139,92,246,0.35)' },
  clean:    { label: 'Clean',    color: '#22c55e', bg: 'rgba(34,197,94,0.15)',  border: 'rgba(34,197,94,0.35)'  },
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'clean']

function SevBadge({ severity }) {
  const cfg = SEV_CFG[severity] || SEV_CFG.info
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold shrink-0"
      style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.border}` }}
    >
      {severity === 'clean'    && <ShieldCheck size={10} />}
      {severity === 'critical' && <ShieldAlert size={10} />}
      {severity === 'high'     && <ShieldAlert size={10} />}
      {severity === 'medium'   && <AlertTriangle size={10} />}
      {['low', 'info'].includes(severity) && <Info size={10} />}
      {cfg.label}
    </span>
  )
}

function fmt(iso) {
  if (!iso) return '--'
  return new Date(iso).toLocaleString()
}

function fmtRelative(iso) {
  if (!iso) return '--'
  const diff = Date.now() - new Date(iso).getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1)  return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

export function SecurityDashboard({ onClose, onDeviceClick }) {
  const [data,     setData]     = useState(null)
  const [loading,  setLoading]  = useState(true)
  const [error,    setError]    = useState(null)

  async function load() {
    setLoading(true)
    setError(null)
    try {
      const d = await api.getVulnSummary()
      setData(d)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const sevCounts  = data?.severity_counts  || {}
  const totalScan  = data?.total_scanned    || 0
  const totalDev   = data?.total_devices    || 0
  const topVuln    = data?.top_vulnerable   || []
  const recentScan = data?.recent_scans     || []
  const coveragePct = totalDev > 0 ? Math.round((totalScan / totalDev) * 100) : 0

  const atRisk = ['critical', 'high', 'medium'].reduce((s, k) => s + (sevCounts[k] || 0), 0)

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 animate-fade-in"
        style={{ background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }}
        onClick={onClose}
      />

      {/* Panel */}
      <aside
        className="fixed right-0 top-0 h-full w-full max-w-md z-50 flex flex-col shadow-2xl animate-slide-in"
        style={{ background: 'var(--color-surface)', borderLeft: '1px solid var(--color-border)' }}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-5"
          style={{ borderBottom: '1px solid var(--color-border)' }}>
          <div className="flex items-center gap-3">
            <span className="w-8 h-8 rounded-lg flex items-center justify-center"
              style={{ background: 'rgba(239,68,68,0.12)' }}>
              <ShieldAlert size={16} style={{ color: '#ef4444' }} />
            </span>
            <h2 className="font-semibold" style={{ color: 'var(--color-text)' }}>Security Overview</h2>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={load} disabled={loading} className="btn-ghost p-2" title="Refresh">
              <RefreshCw size={15} className={loading ? 'animate-spin' : ''} />
            </button>
            <button onClick={onClose} className="btn-ghost p-2" aria-label="Close">
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">

          {error && (
            <div className="card p-4 text-sm" style={{ color: 'var(--color-error)' }}>
              Failed to load: {error}
            </div>
          )}

          {loading && !data && (
            <div className="space-y-3">
              {[...Array(4)].map((_, i) => <div key={i} className="skeleton h-12 rounded-lg" />)}
            </div>
          )}

          {data && (
            <>
              {/* Summary pills */}
              <div className="grid grid-cols-2 gap-3">
                <div className="card p-4">
                  <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>Devices at risk</p>
                  <p className="text-2xl font-bold mt-1" style={{ color: atRisk > 0 ? '#ef4444' : '#22c55e' }}>
                    {atRisk}
                  </p>
                  <p className="text-[11px] mt-0.5" style={{ color: 'var(--color-text-faint)' }}>
                    critical / high / medium
                  </p>
                </div>
                <div className="card p-4">
                  <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>Scan coverage</p>
                  <p className="text-2xl font-bold mt-1" style={{ color: 'var(--color-text)' }}>
                    {coveragePct}%
                  </p>
                  <p className="text-[11px] mt-0.5" style={{ color: 'var(--color-text-faint)' }}>
                    {totalScan} of {totalDev} devices
                  </p>
                </div>
              </div>

              {/* Coverage bar */}
              <div>
                <div className="flex justify-between items-center mb-1">
                  <span className="text-xs font-semibold uppercase tracking-wider"
                    style={{ color: 'var(--color-text-muted)' }}>Scan Coverage</span>
                  <span className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                    {totalScan}/{totalDev} scanned
                  </span>
                </div>
                <div className="h-2 rounded-full overflow-hidden" style={{ background: 'var(--color-surface-offset)' }}>
                  <div className="h-full rounded-full transition-all duration-500"
                    style={{ width: `${coveragePct}%`, background: coveragePct >= 80 ? '#22c55e' : coveragePct >= 50 ? '#f59e0b' : '#ef4444' }} />
                </div>
              </div>

              {/* Severity distribution */}
              {Object.keys(sevCounts).length > 0 && (
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider mb-3"
                    style={{ color: 'var(--color-text-muted)' }}>Severity Distribution</p>
                  <div className="flex flex-wrap gap-2">
                    {SEV_ORDER.filter(s => sevCounts[s] > 0).map(s => {
                      const cfg = SEV_CFG[s]
                      return (
                        <div key={s} className="flex items-center gap-2 px-3 py-2 rounded-lg"
                          style={{ background: cfg.bg, border: `1px solid ${cfg.border}` }}>
                          <span className="text-lg font-bold tabular-nums" style={{ color: cfg.color }}>
                            {sevCounts[s]}
                          </span>
                          <span className="text-xs font-medium" style={{ color: cfg.color }}>
                            {cfg.label}
                          </span>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}

              {/* Most vulnerable devices */}
              {topVuln.length > 0 && (
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider mb-3"
                    style={{ color: 'var(--color-text-muted)' }}>Most Vulnerable</p>
                  <div className="space-y-2">
                    {topVuln.map((d, i) => (
                      <button
                        key={d.mac_address}
                        onClick={() => onDeviceClick && onDeviceClick(d.mac_address)}
                        className="card p-3 w-full text-left flex items-center gap-3 hover:border-brand/40 transition-colors"
                      >
                        <SevBadge severity={d.severity} />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium truncate" style={{ color: 'var(--color-text)' }}>
                            {d.display_name}
                          </p>
                          <p className="text-xs font-mono" style={{ color: 'var(--color-text-faint)' }}>
                            {d.ip_address || d.mac_address}
                          </p>
                        </div>
                        <span className="text-xs shrink-0" style={{ color: 'var(--color-text-faint)' }}>
                          {d.vuln_count} finding{d.vuln_count !== 1 ? 's' : ''}
                        </span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Recent scans */}
              {recentScan.length > 0 && (
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider mb-3"
                    style={{ color: 'var(--color-text-muted)' }}>Recent Scans</p>
                  <div className="card divide-y" style={{ '--tw-divide-opacity': 1 }}>
                    {recentScan.slice(0, 10).map((r, i) => {
                      const cfg = SEV_CFG[r.severity] || SEV_CFG.info
                      return (
                        <button
                          key={i}
                          onClick={() => onDeviceClick && onDeviceClick(r.mac_address)}
                          className="w-full px-3 py-2.5 flex items-center gap-3 text-left hover:bg-surface-offset transition-colors first:rounded-t-lg last:rounded-b-lg"
                        >
                          <span className="w-2 h-2 rounded-full shrink-0 mt-0.5" style={{ background: cfg.color }} />
                          <div className="flex-1 min-w-0">
                            <p className="text-xs font-medium truncate" style={{ color: 'var(--color-text)' }}>
                              {r.display_name}
                            </p>
                          </div>
                          <SevBadge severity={r.severity} />
                          <span className="text-[10px] shrink-0 flex items-center gap-1"
                            style={{ color: 'var(--color-text-faint)' }}>
                            <Clock size={9} />
                            {fmtRelative(r.scanned_at)}
                          </span>
                        </button>
                      )
                    })}
                  </div>
                </div>
              )}

              {topVuln.length === 0 && recentScan.length === 0 && (
                <div className="card p-8 flex flex-col items-center gap-3 text-center">
                  <ShieldCheck size={32} style={{ color: '#22c55e' }} />
                  <p className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>
                    No vulnerabilities found
                  </p>
                  <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                    Run vulnerability scans on your devices to see results here.
                  </p>
                </div>
              )}
            </>
          )}
        </div>
      </aside>
    </>
  )
}
