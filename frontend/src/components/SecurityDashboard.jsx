import { useState, useEffect } from 'react'
import {
  ShieldAlert, ShieldCheck, RefreshCw, ScanLine,
  AlertTriangle, Info, Clock, ChevronDown, ChevronRight,
  Settings2, Save, Loader, X,
} from 'lucide-react'
import { api } from '../api'

// ---------------------------------------------------------------------------
// Vuln scan settings panel
// ---------------------------------------------------------------------------
const VULN_SETTING_META = {
  vuln_scan_schedule: {
    label: 'Scheduled Scans', type: 'select',
    options: [
      { value: 'disabled', label: 'Disabled' },
      { value: '6h',       label: 'Every 6 hours' },
      { value: '12h',      label: 'Every 12 hours' },
      { value: '24h',      label: 'Daily' },
      { value: 'weekly',   label: 'Weekly' },
    ],
  },
  vuln_scan_targets: {
    label: 'Scan Targets', type: 'select',
    options: [
      { value: 'all',       label: 'All devices' },
      { value: 'important', label: 'Watched devices only' },
    ],
  },
  vuln_scan_on_new_device: {
    label: 'Auto-scan New Devices', type: 'toggle',
    description: 'Automatically run a scan when a new device is first discovered.',
  },
  vuln_scan_on_port_change: {
    label: 'Scan on Port Change', type: 'toggle',
    description: 'Automatically scan when a new open port is detected.',
  },
  nuclei_template_update_interval: {
    label: 'Template Updates', type: 'select',
    options: [
      { value: 'disabled', label: 'Disabled' },
      { value: '12h',      label: 'Every 12 hours' },
      { value: '24h',      label: 'Daily' },
      { value: '48h',      label: 'Every 48 hours' },
      { value: 'weekly',   label: 'Weekly' },
    ],
  },
  vuln_scan_templates: {
    label: 'Template Tags', type: 'text',
    description: 'Comma-separated tags (e.g. cve,exposure,misconfig,default-login,network).',
  },
}

const VULN_KEYS = Object.keys(VULN_SETTING_META)

function VulnSettingsPanel({ onClose }) {
  const [vals,   setVals]   = useState({})
  const [dirty,  setDirty]  = useState({})
  const [saving, setSaving] = useState(false)
  const [saved,  setSaved]  = useState(false)

  useEffect(() => {
    api.getSettings().then(all => {
      const map = {}
      for (const s of all) if (VULN_KEYS.includes(s.key)) map[s.key] = s.value
      setVals(map)
    }).catch(() => {})
  }, [])

  function handleChange(key, value) {
    setDirty(d => ({ ...d, [key]: value }))
  }

  async function handleSave() {
    setSaving(true)
    await Promise.all(Object.entries(dirty).map(([k, v]) => api.updateSetting(k, v)))
    setVals(v => ({ ...v, ...dirty }))
    setDirty({})
    setSaving(false)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  const hasDirty = Object.keys(dirty).length > 0
  const val = (key) => dirty[key] ?? vals[key] ?? ''

  return (
    <div className="card mb-6 overflow-hidden">
      <div className="px-4 py-3 border-b flex items-center justify-between"
        style={{ borderColor: 'var(--color-border)', background: 'var(--color-surface-offset)' }}>
        <span className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider"
          style={{ color: 'var(--color-text-muted)' }}>
          <Settings2 size={13} /> Scan Settings
        </span>
        <button onClick={onClose} className="p-1 rounded hover:opacity-70 transition-opacity"
          style={{ color: 'var(--color-text-faint)' }}>
          <X size={14} />
        </button>
      </div>
      <div className="px-4 py-4 grid grid-cols-1 sm:grid-cols-2 gap-4">
        {VULN_KEYS.map(key => {
          const meta = VULN_SETTING_META[key]
          const v = val(key)
          const isDirty = dirty[key] !== undefined
          const dirtyStyle = isDirty ? { borderColor: 'color-mix(in srgb, var(--color-brand) 50%, transparent)' } : {}

          if (meta.type === 'toggle') {
            const isOn = v === 'true'
            return (
              <div key={key} className="space-y-1 sm:col-span-2">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-xs font-medium" style={{ color: 'var(--color-text)' }}>{meta.label}</span>
                    {meta.description && (
                      <p className="text-[10px] mt-0.5" style={{ color: 'var(--color-text-faint)' }}>{meta.description}</p>
                    )}
                  </div>
                  <button type="button" role="switch" aria-checked={isOn}
                    onClick={() => handleChange(key, isOn ? 'false' : 'true')}
                    className="relative inline-flex h-5 w-9 items-center rounded-full transition-colors ml-4 shrink-0"
                    style={{ background: isOn ? 'var(--color-brand)' : 'var(--color-border)' }}>
                    <span className="inline-block h-3.5 w-3.5 rounded-full bg-white shadow transition-transform"
                      style={{ transform: isOn ? 'translateX(19px)' : 'translateX(3px)' }} />
                  </button>
                </div>
              </div>
            )
          }

          if (meta.type === 'select') {
            return (
              <div key={key} className="space-y-1">
                <label className="text-xs font-medium" style={{ color: 'var(--color-text)' }}>{meta.label}</label>
                <select className="input text-xs w-full" style={dirtyStyle} value={v}
                  onChange={e => handleChange(key, e.target.value)}>
                  {meta.options?.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              </div>
            )
          }

          return (
            <div key={key} className="space-y-1 sm:col-span-2">
              <label className="text-xs font-medium" style={{ color: 'var(--color-text)' }}>{meta.label}</label>
              <input type="text" className="input text-xs font-mono w-full" style={dirtyStyle} value={v}
                onChange={e => handleChange(key, e.target.value)} />
              {meta.description && (
                <p className="text-[10px]" style={{ color: 'var(--color-text-faint)' }}>{meta.description}</p>
              )}
            </div>
          )
        })}
      </div>
      {hasDirty && (
        <div className="px-4 pb-4">
          <button onClick={handleSave} disabled={saving}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-white disabled:opacity-50"
            style={{ background: 'var(--color-brand)' }}>
            {saving
              ? <><Loader size={11} className="animate-spin" /> Saving…</>
              : saved ? '✓ Saved' : <><Save size={11} /> Save settings</>}
          </button>
        </div>
      )}
    </div>
  )
}

const SEV_CFG = {
  critical: { label: 'Critical', color: '#ef4444', bg: 'rgba(239,68,68,0.15)',  border: 'rgba(239,68,68,0.35)'  },
  high:     { label: 'High',     color: '#f97316', bg: 'rgba(249,115,22,0.15)', border: 'rgba(249,115,22,0.35)' },
  medium:   { label: 'Medium',   color: '#f59e0b', bg: 'rgba(245,158,11,0.15)', border: 'rgba(245,158,11,0.35)' },
  low:      { label: 'Low',      color: '#3b82f6', bg: 'rgba(59,130,246,0.15)', border: 'rgba(59,130,246,0.35)' },
  info:     { label: 'Info',     color: '#8b5cf6', bg: 'rgba(139,92,246,0.15)', border: 'rgba(139,92,246,0.35)' },
  clean:    { label: 'Clean',    color: '#22c55e', bg: 'rgba(34,197,94,0.15)',  border: 'rgba(34,197,94,0.35)'  },
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'clean']

function TrendBars({ trend }) {
  const SEV_PRIORITY = ['critical', 'high', 'medium', 'low', 'info', 'clean']
  const SEV_COLORS = {
    critical: '#ef4444', high: '#f97316', medium: '#f59e0b',
    low: '#3b82f6', info: '#8b5cf6', clean: '#22c55e',
  }
  const maxTotal = Math.max(...trend.map(d => {
    return SEV_PRIORITY.reduce((s, k) => s + (d[k] || 0), 0)
  }), 1)

  return (
    <div className="flex items-end gap-0.5 h-16">
      {trend.slice(-30).map((day, i) => {
        const total = SEV_PRIORITY.reduce((s, k) => s + (day[k] || 0), 0)
        const heightPct = total > 0 ? Math.max(8, Math.round((total / maxTotal) * 100)) : 2
        const topSev = SEV_PRIORITY.find(k => (day[k] || 0) > 0)
        const color = topSev ? SEV_COLORS[topSev] : 'var(--color-border)'
        return (
          <div key={i} title={`${day.date}: ${total} scan${total !== 1 ? 's' : ''}`}
            className="flex-1 rounded-sm cursor-default transition-opacity hover:opacity-80"
            style={{ height: `${heightPct}%`, background: color, opacity: total > 0 ? 0.8 : 0.2 }} />
        )
      })}
    </div>
  )
}

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

export function SecurityDashboard({ onDeviceClick }) {
  const [data,         setData]         = useState(null)
  const [trend,        setTrend]        = useState(null)
  const [loading,      setLoading]      = useState(true)
  const [error,        setError]        = useState(null)
  const [expandedVuln, setExpandedVuln] = useState({})
  const [scanning,     setScanning]     = useState(false)
  const [scanMsg,      setScanMsg]      = useState(null)
  const [showSettings, setShowSettings] = useState(false)

  async function load() {
    setLoading(true)
    setError(null)
    try {
      const [d, t] = await Promise.all([
        api.getVulnSummary(),
        api.getVulnTrend(30).catch(() => []),
      ])
      setData(d)
      setTrend(t)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  async function handleScanAll() {
    setScanning(true)
    setScanMsg(null)
    try {
      await api.scanAllVulns()
      setScanMsg('Scan started — results will appear as devices complete.')
    } catch (e) {
      setScanMsg(`Error: ${e.message}`)
    } finally {
      setScanning(false)
    }
  }

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
    <div className="max-w-3xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <span className="w-8 h-8 rounded-lg flex items-center justify-center"
              style={{ background: 'rgba(239,68,68,0.12)' }}>
              <ShieldAlert size={16} style={{ color: '#ef4444' }} />
            </span>
            <h2 className="font-semibold" style={{ color: 'var(--color-text)' }}>Security Overview</h2>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={handleScanAll} disabled={scanning || loading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-white disabled:opacity-50 transition-opacity"
              style={{ background: 'var(--color-brand)' }}
              title="Run vulnerability scan on all eligible devices">
              <ScanLine size={13} className={scanning ? 'animate-pulse' : ''} />
              {scanning ? 'Starting…' : 'Scan all devices'}
            </button>
            <button onClick={load} disabled={loading} className="btn-ghost p-2" title="Refresh data">
              <RefreshCw size={15} className={loading ? 'animate-spin' : ''} />
            </button>
            <button
              onClick={() => setShowSettings(v => !v)}
              className="btn-ghost p-2 transition-colors"
              title="Scan settings"
              style={showSettings ? { color: 'var(--color-brand)' } : {}}>
              <Settings2 size={16} />
            </button>
          </div>
        </div>

        {scanMsg && (
          <div className="mb-4 px-4 py-2.5 rounded-xl text-xs"
            style={{ background: scanMsg.startsWith('Error') ? 'rgba(239,68,68,0.1)' : 'rgba(16,185,129,0.1)',
                     color: scanMsg.startsWith('Error') ? '#f87171' : '#10b981',
                     border: `1px solid ${scanMsg.startsWith('Error') ? 'rgba(239,68,68,0.2)' : 'rgba(16,185,129,0.2)'}` }}>
            {scanMsg}
          </div>
        )}

        {showSettings && <VulnSettingsPanel onClose={() => setShowSettings(false)} />}

        <div className="space-y-6">

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

              {/* 30-day scan trend */}
              {trend && trend.length >= 2 && (
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider mb-3"
                    style={{ color: 'var(--color-text-muted)' }}>30-Day Scan Activity</p>
                  <TrendBars trend={trend} />
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
                          onClick={() => onDeviceClick && onDeviceClick(r.mac_address, 'vulns')}
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
    </div>
  )
}
