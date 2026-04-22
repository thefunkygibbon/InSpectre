import { useState, useEffect } from 'react'
import {
  ShieldAlert, ShieldCheck, X, RefreshCw,
  AlertTriangle, Info, Clock, ChevronDown, ChevronRight,
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
  const [data,        setData]        = useState(null)
  const [loading,     setLoading]     = useState(true)
  const [error,       setError]       = useState(null)
  const [expandedVuln, setExpandedVuln] = useState({}) // mac → { loading } | { findings: [] }

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

  async function toggleVulnExpand(mac) {
    if (expandedVuln[mac]) {
      setExpandedVuln(prev => { const n = { ...prev }; delete n[mac]; return n })
      return
    }
    setExpandedVuln(prev => ({ ...prev, [mac]: { loading: true } }))
    try {
      const reports = await api.getVulnReports(mac, 1)
      const findings = reports?.[0]?.findings || []
      setExpandedVuln(prev => ({ ...prev, [mac]: { findings } }))
    } catch {
      setExpandedVuln(prev => ({ ...prev, [mac]: { findings: [] } }))
    }
  }

  const sevCounts  = data?.severity_counts  || {}
  const totalScan  = data?.total_scanned    || 0
  const totalDev   = data?.total_devices    || 0
  const topVuln    = data?.top_vulnerable   || []
  const recentScan = data?.recent_scans     || []
  const coveragePct = totalDev > 0 ? Math.round((totalScan / totalDev) * 100) : 0

  const atRisk  = ['critical', 'high', 'medium'].reduce((s, k) => s + (sevCounts[k] || 0), 0)
  const nClean  = sevCounts.clean || 0

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
              {/* Summary cards */}
              <div className="grid grid-cols-3 gap-2">
                <div className="card p-3">
                  <p className="text-[11px]" style={{ color: 'var(--color-text-faint)' }}>At risk</p>
                  <p className="text-xl font-bold mt-0.5" style={{ color: atRisk > 0 ? '#ef4444' : '#22c55e' }}>
                    {atRisk}
                  </p>
                  <p className="text-[10px] mt-0.5 leading-tight" style={{ color: 'var(--color-text-faint)' }}>
                    crit / high / med
                  </p>
                </div>
                <div className="card p-3">
                  <p className="text-[11px]" style={{ color: 'var(--color-text-faint)' }}>Coverage</p>
                  <p className="text-xl font-bold mt-0.5" style={{ color: 'var(--color-text)' }}>
                    {coveragePct}%
                  </p>
                  <p className="text-[10px] mt-0.5" style={{ color: 'var(--color-text-faint)' }}>
                    {totalScan}/{totalDev} scanned
                  </p>
                </div>
                <div className="card p-3">
                  <p className="text-[11px]" style={{ color: 'var(--color-text-faint)' }}>Clean</p>
                  <p className="text-xl font-bold mt-0.5" style={{ color: '#22c55e' }}>
                    {nClean}
                  </p>
                  <p className="text-[10px] mt-0.5" style={{ color: 'var(--color-text-faint)' }}>
                    no findings
                  </p>
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
                    {topVuln.map(d => {
                      const exp = expandedVuln[d.mac_address]
                      const isOpen = !!exp
                      return (
                        <div key={d.mac_address} className="card overflow-hidden">
                          <button
                            onClick={() => toggleVulnExpand(d.mac_address)}
                            className="w-full p-3 text-left flex items-center gap-3 hover:bg-surface-offset/40 transition-colors"
                          >
                            {isOpen
                              ? <ChevronDown size={12} style={{ color: 'var(--color-text-faint)', flexShrink: 0 }} />
                              : <ChevronRight size={12} style={{ color: 'var(--color-text-faint)', flexShrink: 0 }} />}
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
                          {isOpen && (
                            <div className="px-3 pb-3 pt-1 border-t" style={{ borderColor: 'var(--color-border)' }}>
                              {exp.loading ? (
                                <p className="text-[11px] animate-pulse" style={{ color: 'var(--color-text-faint)' }}>Loading findings…</p>
                              ) : exp.findings?.length === 0 ? (
                                <p className="text-[11px]" style={{ color: '#22c55e' }}>No findings in latest report</p>
                              ) : (
                                <div className="space-y-1 mt-1">
                                  {(exp.findings || []).map((f, i) => {
                                    const cfg = SEV_CFG[f.severity] || SEV_CFG.info
                                    return (
                                      <div key={i} className="flex items-center gap-2">
                                        <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase shrink-0"
                                          style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.border}` }}>
                                          {f.severity.slice(0, 4)}
                                        </span>
                                        <span className="text-[11px] truncate" style={{ color: 'var(--color-text-muted)' }}>
                                          {f.name}
                                        </span>
                                        {f.matched_at && (
                                          <span className="text-[10px] font-mono shrink-0 truncate max-w-[100px]"
                                            style={{ color: 'var(--color-text-faint)' }}>
                                            {f.matched_at}
                                          </span>
                                        )}
                                      </div>
                                    )
                                  })}
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      )
                    })}
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
                          onClick={() => onDeviceClick && onDeviceClick(r.mac_address, 'vuln')}
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
