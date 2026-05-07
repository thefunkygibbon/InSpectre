import { useState, useEffect, useRef } from 'react'
import {
  X, Box, Play, Square, RotateCcw, ChevronDown, ChevronRight,
  Network, HardDrive, Tag, Terminal, ShieldAlert, ShieldCheck,
  Settings2, Clock, ExternalLink, Eye, EyeOff, Loader2, FileText,
} from 'lucide-react'
import { api } from '../api'

const STATUS_CONFIG = {
  running:    { color: '#22c55e', bg: 'rgba(34,197,94,0.12)',   border: 'rgba(34,197,94,0.3)',   label: 'Running'    },
  exited:     { color: '#6b7280', bg: 'rgba(107,114,128,0.12)', border: 'rgba(107,114,128,0.3)', label: 'Stopped'    },
  paused:     { color: '#f59e0b', bg: 'rgba(245,158,11,0.12)',  border: 'rgba(245,158,11,0.3)',  label: 'Paused'     },
  restarting: { color: '#3b82f6', bg: 'rgba(59,130,246,0.12)',  border: 'rgba(59,130,246,0.3)',  label: 'Restarting' },
  dead:       { color: '#ef4444', bg: 'rgba(239,68,68,0.12)',   border: 'rgba(239,68,68,0.3)',   label: 'Dead'       },
  created:    { color: '#8b5cf6', bg: 'rgba(139,92,246,0.12)',  border: 'rgba(139,92,246,0.3)',  label: 'Created'    },
}

function fmt(iso) {
  if (!iso || iso === '0001-01-01T00:00:00Z') return '--'
  return new Date(iso).toLocaleString()
}

function fmtSize(bytes) {
  if (!bytes) return '0 B'
  const k = 1024
  const sizes = ['B','KB','MB','GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`
}

const STOPPED_STATES = ['exited', 'created', 'dead']

const SECRET_PATTERNS = /password|secret|token|key|api_key|auth|credential/i

function maskEnvValue(env) {
  const eq = env.indexOf('=')
  if (eq < 0) return env
  const k = env.slice(0, eq)
  const v = env.slice(eq + 1)
  if (SECRET_PATTERNS.test(k) && v.length > 0) return `${k}=••••••••`
  return env
}

const TABS = [
  { id: 'overview', label: 'Overview'  },
  { id: 'logs',     label: 'Logs'      },
  { id: 'vuln',     label: 'Vuln Scan' },
  { id: 'admin',    label: 'Admin'     },
]

function Collapsible({ title, icon: Icon, defaultOpen = false, children }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div>
      <button onClick={() => setOpen(o => !o)} className="w-full flex items-center gap-2 mb-2 group">
        {Icon && <Icon size={14} className="text-brand" />}
        <span className="text-xs font-semibold text-text-muted uppercase tracking-wider flex-1 text-left">{title}</span>
        {open
          ? <ChevronDown  size={13} className="text-text-faint shrink-0" />
          : <ChevronRight size={13} className="text-text-faint shrink-0" />}
      </button>
      {open && <div className="card p-4 space-y-0.5">{children}</div>}
    </div>
  )
}

function Row({ label, value, mono, children }) {
  return (
    <div className="flex items-start justify-between py-1.5 gap-4 border-b border-border last:border-0">
      <span className="text-xs text-text-muted shrink-0 mt-0.5">{label}</span>
      <span className={`text-sm text-text text-right truncate max-w-[60%] ${mono ? 'font-mono text-xs' : ''}`}>
        {children || (value ?? '--')}
      </span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Log streaming tab
// ---------------------------------------------------------------------------
function LogsTab({ containerId, isRunning }) {
  const [lines,   setLines]   = useState([])
  const [running, setRunning] = useState(false)
  const [tail,    setTail]    = useState(100)
  const abortRef = useRef(null)
  const endRef   = useRef(null)

  function startStream() {
    if (abortRef.current) abortRef.current.abort()
    const ctrl = new AbortController()
    abortRef.current = ctrl
    setLines([])
    setRunning(true)
    api.dockerLogs(containerId, tail, (line) => {
      setLines(prev => [...prev.slice(-999), line])
    }, ctrl.signal).catch(() => {}).finally(() => setRunning(false))
  }

  function stopStream() {
    if (abortRef.current) { abortRef.current.abort(); abortRef.current = null }
    setRunning(false)
  }

  useEffect(() => () => stopStream(), [])

  useEffect(() => {
    if (endRef.current) endRef.current.scrollIntoView({ behavior: 'smooth' })
  }, [lines])

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 flex-wrap">
        <div className="flex items-center gap-2">
          <label className="text-xs text-text-muted">Last</label>
          <select value={tail} onChange={e => setTail(Number(e.target.value))}
            className="input text-xs py-1 px-2 h-auto" disabled={running}>
            <option value={50}>50 lines</option>
            <option value={100}>100 lines</option>
            <option value={200}>200 lines</option>
            <option value={500}>500 lines</option>
          </select>
        </div>
        {running ? (
          <button onClick={stopStream}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border
                       border-red-500/40 bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors">
            <Square size={11} className="fill-current" /> Stop
          </button>
        ) : (
          <button onClick={startStream}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border
                       border-brand/40 bg-brand/10 text-brand hover:bg-brand/20 transition-colors">
            <Play size={11} /> {lines.length > 0 ? 'Restart' : 'Stream Logs'}
          </button>
        )}
        {running && (
          <span className="flex items-center gap-1 text-xs" style={{ color: 'var(--color-text-faint)' }}>
            <Loader2 size={11} className="animate-spin" />Live
          </span>
        )}
      </div>

      {lines.length === 0 && !running ? (
        <div className="flex flex-col items-center py-10 gap-2 text-center">
          <Terminal size={24} style={{ color: 'var(--color-text-faint)' }} />
          <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
            Press "Stream Logs" to fetch {isRunning ? 'live' : ''} container logs.
          </p>
        </div>
      ) : (
        <div
          className="rounded-xl p-3 font-mono text-[11px] overflow-y-auto max-h-[60vh] space-y-0.5"
          style={{ background: 'var(--color-surface-offset)', border: '1px solid var(--color-border)' }}
        >
          {lines.map((line, i) => (
            <div key={i} className="whitespace-pre-wrap break-all leading-snug"
              style={{ color: line.includes('[ERROR]') ? '#ef4444' : 'var(--color-text-muted)' }}>
              {line}
            </div>
          ))}
          {running && <div className="w-2 h-3 inline-block animate-pulse" style={{ background: 'var(--color-brand)' }} />}
          <div ref={endRef} />
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Severity config for Trivy CVE cards
// ---------------------------------------------------------------------------
const SEV_CFG = {
  critical: { label: 'Critical', color: '#ef4444', bg: 'rgba(239,68,68,0.12)',  border: 'rgba(239,68,68,0.3)'  },
  high:     { label: 'High',     color: '#f97316', bg: 'rgba(249,115,22,0.12)', border: 'rgba(249,115,22,0.3)' },
  medium:   { label: 'Medium',   color: '#f59e0b', bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.3)' },
  low:      { label: 'Low',      color: '#3b82f6', bg: 'rgba(59,130,246,0.12)', border: 'rgba(59,130,246,0.3)' },
  unknown:  { label: 'Unknown',  color: '#8b5cf6', bg: 'rgba(139,92,246,0.12)', border: 'rgba(139,92,246,0.3)' },
}
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'unknown']

function TrivyCVECard({ vuln }) {
  const [open, setOpen] = useState(false)
  const cfg = SEV_CFG[vuln.severity] || SEV_CFG.unknown
  const isNVD = vuln.id.startsWith('CVE-')
  return (
    <div className="rounded-lg border overflow-hidden mb-1.5" style={{ borderColor: cfg.border }}>
      <button onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-3 py-2 text-left"
        style={{ background: cfg.bg }}>
        <span className="text-[10px] font-bold shrink-0 px-1.5 py-0.5 rounded"
          style={{ background: 'rgba(0,0,0,0.2)', color: cfg.color }}>
          {cfg.label.slice(0, 4).toUpperCase()}
        </span>
        {vuln.cvss != null && (
          <span className="text-[10px] font-bold shrink-0" style={{ color: cfg.color }}>
            {vuln.cvss.toFixed(1)}
          </span>
        )}
        <span className="text-[11px] font-mono font-medium shrink-0" style={{ color: 'var(--color-text)' }}>
          {vuln.id}
        </span>
        <span className="text-[11px] flex-1 truncate" style={{ color: 'var(--color-text-muted)' }}>
          {vuln.pkg}
        </span>
        {open
          ? <ChevronDown  size={11} style={{ color: 'var(--color-text-faint)', flexShrink: 0 }} />
          : <ChevronRight size={11} style={{ color: 'var(--color-text-faint)', flexShrink: 0 }} />}
      </button>
      {open && (
        <div className="px-3 py-2.5 space-y-2" style={{ background: 'rgba(0,0,0,0.25)' }}>
          {vuln.title && (
            <p className="text-xs leading-snug" style={{ color: 'var(--color-text)' }}>{vuln.title}</p>
          )}
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px]" style={{ color: 'var(--color-text-faint)' }}>
            <span>Pkg: <span className="font-mono" style={{ color: 'var(--color-text-muted)' }}>{vuln.pkg}</span></span>
            <span>Installed: <span className="font-mono text-red-400">{vuln.installed || '?'}</span></span>
            {vuln.fixed && (
              <span>Fixed in: <span className="font-mono text-green-400">{vuln.fixed}</span></span>
            )}
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {isNVD && (
              <a href={`https://nvd.nist.gov/vuln/detail/${vuln.id}`}
                target="_blank" rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded border transition-opacity hover:opacity-70"
                style={{ color: 'var(--color-brand)', borderColor: 'var(--color-brand)', background: 'rgba(0,0,0,0.2)' }}>
                NVD <ExternalLink size={9} />
              </a>
            )}
            {vuln.target && (
              <span className="text-[10px] font-mono" style={{ color: 'var(--color-text-faint)' }}>
                {vuln.target}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function VulnGroup({ severity, vulns, defaultOpen }) {
  const [open, setOpen] = useState(defaultOpen)
  const cfg = SEV_CFG[severity] || SEV_CFG.unknown
  return (
    <div className="mb-3">
      <button onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 mb-2 py-1">
        {open
          ? <ChevronDown  size={12} style={{ color: cfg.color }} />
          : <ChevronRight size={12} style={{ color: cfg.color }} />}
        <span className="text-xs font-semibold" style={{ color: cfg.color }}>{cfg.label}</span>
        <span className="text-[10px] px-2 py-0.5 rounded-full font-bold"
          style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.border}` }}>
          {vulns.length}
        </span>
      </button>
      {open && vulns.map((v, i) => <TrivyCVECard key={i} vuln={v} />)}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Vuln scan tab (Trivy) — state is lifted to ContainersPage
// ---------------------------------------------------------------------------
function VulnTab({ container, trivyScan, updateTrivyScan }) {
  const abortRef        = useRef(null)
  const [loadingHistory, setLoadingHistory] = useState(false)

  const logs      = trivyScan.logs || []
  const vulns     = trivyScan.vulns     // null = never scanned, [] = clean, [...] = found
  const scanning  = trivyScan.scanning
  const scannedAt = trivyScan.scannedAt

  // On first open, load stored result from backend
  useEffect(() => {
    if (vulns !== null || scanning) return
    setLoadingHistory(true)
    api.dockerAutoScanResult(container.name).then(data => {
      if (data && Array.isArray(data.vulns)) {
        updateTrivyScan({ vulns: data.vulns, scannedAt: data.scanned_at || null })
      }
    }).catch(() => {}).finally(() => setLoadingHistory(false))
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  function startScan() {
    if (abortRef.current) abortRef.current.abort()
    const ctrl = new AbortController()
    abortRef.current = ctrl
    updateTrivyScan({ logs: [], vulns: null, scanning: true, scannedAt: null })
    api.dockerTrivyScan(container.id, (line) => {
      if (line.startsWith('TRIVY_RESULT:')) {
        try {
          const payload = JSON.parse(line.slice('TRIVY_RESULT:'.length))
          updateTrivyScan(cur => ({ ...cur, vulns: payload.vulns || [], scannedAt: payload.scanned_at || null }))
        } catch (_) { /* ignore parse errors */ }
      } else if (line !== 'TRIVY_DONE') {
        const msg = line.startsWith('LOG: ') ? line.slice(5) : line
        updateTrivyScan(cur => ({ ...cur, logs: [...(cur.logs || []).slice(-199), msg] }))
      }
    }, ctrl.signal).catch(() => {}).finally(() => updateTrivyScan(cur => ({ ...cur, scanning: false })))
  }

  function stopScan() {
    if (abortRef.current) { abortRef.current.abort(); abortRef.current = null }
    updateTrivyScan(cur => ({ ...cur, scanning: false }))
  }

  useEffect(() => () => { if (abortRef.current) abortRef.current.abort() }, [])

  const grouped = Object.fromEntries(SEV_ORDER.map(s => [s, []]))
  for (const v of (vulns || [])) {
    const s = SEV_ORDER.includes(v.severity) ? v.severity : 'unknown'
    grouped[s].push(v)
  }
  const hasVulns = vulns !== null && vulns.length > 0

  return (
    <div className="space-y-4">
      {/* Image info + scan timestamp */}
      <div className="rounded-lg px-4 py-3 text-xs space-y-1"
        style={{ background: 'var(--color-surface-offset)', border: '1px solid var(--color-border)' }}>
        <p className="font-medium" style={{ color: 'var(--color-text)' }}>
          Image: <span className="font-mono">{container.image}</span>
        </p>
        {scannedAt && !scanning && (
          <p style={{ color: 'var(--color-text-faint)' }}>Last scanned: {new Date(scannedAt).toLocaleString()}</p>
        )}
        {!scannedAt && !scanning && vulns === null && (
          <p style={{ color: 'var(--color-text-faint)' }}>Scans the container image for known CVEs using Trivy.</p>
        )}
      </div>

      {/* Controls */}
      <div className="flex items-center gap-2">
        {scanning ? (
          <button onClick={stopScan}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border
                       border-red-500/40 bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors">
            <Square size={11} className="fill-current" /> Stop Scan
          </button>
        ) : (
          <button onClick={startScan}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border
                       border-brand/40 bg-brand/10 text-brand hover:bg-brand/20 transition-colors">
            <ShieldAlert size={11} /> {vulns !== null ? 'Re-scan' : 'Scan Image'}
          </button>
        )}
        {scanning && (
          <span className="flex items-center gap-1 text-xs" style={{ color: 'var(--color-text-faint)' }}>
            <Loader2 size={11} className="animate-spin" />Scanning…
          </span>
        )}
      </div>

      {/* Scan errors/warnings only — INFO lines suppressed */}
      {logs.some(l => l.includes('[ERROR]') || l.includes('[WARN]')) && (
        <div className="rounded-lg p-3 font-mono text-[11px] space-y-0.5"
          style={{ background: 'var(--color-surface-offset)', border: '1px solid var(--color-border)' }}>
          {logs.filter(l => l.includes('[ERROR]') || l.includes('[WARN]')).map((l, i) => (
            <div key={i} className="leading-snug whitespace-pre-wrap break-all"
              style={{ color: l.includes('[ERROR]') ? '#ef4444' : '#f59e0b' }}>
              {l}
            </div>
          ))}
        </div>
      )}

      {/* Loading history */}
      {loadingHistory && (
        <div className="flex items-center gap-2 text-xs py-4" style={{ color: 'var(--color-text-faint)' }}>
          <Loader2 size={13} className="animate-spin" /> Loading last scan result…
        </div>
      )}

      {/* Not-yet-scanned empty state */}
      {vulns === null && !scanning && !loadingHistory && (
        <div className="flex flex-col items-center py-10 gap-2 text-center">
          <ShieldAlert size={24} style={{ color: 'var(--color-text-faint)' }} />
          <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
            Click "Scan Image" to check for known CVEs with Trivy.
          </p>
        </div>
      )}

      {/* Results */}
      {vulns !== null && !scanning && (
        <>
          {hasVulns ? (
            <div className="flex flex-wrap gap-2">
              {SEV_ORDER.filter(s => grouped[s].length > 0).map(s => {
                const cfg = SEV_CFG[s]
                return (
                  <span key={s} className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold"
                    style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.border}` }}>
                    <span className="text-base font-bold tabular-nums">{grouped[s].length}</span> {cfg.label}
                  </span>
                )
              })}
            </div>
          ) : (
            <div className="flex items-center gap-2 px-4 py-3 rounded-lg text-xs font-medium"
              style={{ background: 'rgba(34,197,94,0.1)', color: '#22c55e', border: '1px solid rgba(34,197,94,0.25)' }}>
              <ShieldCheck size={14} /> No vulnerabilities found in this image
            </div>
          )}

          {hasVulns && (
            <div>
              {SEV_ORDER.filter(s => grouped[s].length > 0).map(s => (
                <VulnGroup key={s} severity={s} vulns={grouped[s]}
                  defaultOpen={s === 'critical' || s === 'high'} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main drawer
// ---------------------------------------------------------------------------
export function ContainerDrawer({ container: initialContainer, trivyScan, updateTrivyScan, initialTab, onClose, onContainerUpdate }) {
  const [container,   setContainer]   = useState(initialContainer)
  const isProxmox   = container.host_type === 'proxmox'
  const visibleTabs = isProxmox ? TABS.filter(t => t.id !== 'logs' && t.id !== 'vuln') : TABS
  const startTab    = initialTab || 'overview'
  const [activeTab,   setActiveTab]   = useState(
    isProxmox && (startTab === 'logs' || startTab === 'vuln') ? 'overview' : startTab
  )
  const [actioning,   setActioning]   = useState(null)
  const [actionMsg,   setActionMsg]   = useState('')
  const [showAllEnv,  setShowAllEnv]  = useState(false)
  const [masked,      setMasked]      = useState(true)

  useEffect(() => { setContainer(initialContainer) }, [initialContainer])

  const cfg       = STATUS_CONFIG[container.status] || STATUS_CONFIG.exited
  const isRunning = container.status === 'running'
  const isStopped = STOPPED_STATES.includes(container.status)

  async function doAction(action) {
    setActioning(action)
    setActionMsg('')
    try {
      let updated
      if (action === 'start')   updated = await api.dockerStart(container.id)
      if (action === 'stop')    updated = await api.dockerStop(container.id)
      if (action === 'restart') updated = await api.dockerRestart(container.id)
      if (updated) {
        setContainer(updated)
        if (onContainerUpdate) onContainerUpdate(updated)
        setActionMsg(`[OK] Container ${action}ed successfully.`)
      }
    } catch (e) {
      setActionMsg(`[ERROR] ${e.message}`)
    } finally {
      setActioning(null)
    }
  }

  const envToShow = showAllEnv ? container.env : (container.env || []).slice(0, 8)

  return (
    <>
      <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40" onClick={onClose} />
      <aside className="fixed right-0 top-0 h-full w-full max-w-md bg-surface border-l border-border
                        z-50 flex flex-col shadow-2xl animate-slide-in overflow-hidden">

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-5 border-b border-border">
          <div className="flex items-center gap-3 min-w-0">
            <span className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
              style={{ background: cfg.bg }}>
              <Box size={16} style={{ color: cfg.color }} />
            </span>
            <div className="min-w-0">
              <h2 className="font-semibold text-text truncate">{container.name}</h2>
              <p className="text-xs text-text-muted font-mono">{container.short_id}</p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <span className="text-[10px] font-medium px-2 py-0.5 rounded-full"
              style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.border}` }}>
              {cfg.label}
            </span>
            <button onClick={onClose} className="btn-ghost p-2" aria-label="Close"><X size={18} /></button>
          </div>
        </div>

        {/* Tab bar */}
        <div className="flex border-b border-border px-4 gap-0 overflow-x-auto scrollbar-none"
          style={{ background: 'var(--color-surface)' }}>
          {visibleTabs.map(tab => (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)}
              className="px-3 py-3 text-xs font-medium border-b-2 transition-colors whitespace-nowrap shrink-0"
              style={activeTab === tab.id
                ? { borderColor: 'var(--color-brand)', color: 'var(--color-brand)' }
                : { borderColor: 'transparent', color: 'var(--color-text-muted)' }}>
              {tab.label}
              {tab.id === 'vuln' && trivyScan.scanning && (
                <span className="ml-1.5 inline-block w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse align-middle" />
              )}
            </button>
          ))}
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">

          {/* ── Overview tab ── */}
          {activeTab === 'overview' && (
            <>
              <div className="flex flex-wrap gap-2">
                <span className="badge-online" style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.border}` }}>
                  <Box size={11} />{cfg.label}
                </span>
                {container.restart_policy && container.restart_policy !== 'no' && (
                  <span className="badge-online" style={{ background: 'rgba(99,102,241,0.12)', color: '#818cf8', border: '1px solid rgba(99,102,241,0.3)' }}>
                    <RotateCcw size={11} />{container.restart_policy}
                  </span>
                )}
              </div>

              <Collapsible title="Container" icon={Box} defaultOpen>
                <Row label="Name"     value={container.name} />
                <Row label="ID"       value={container.id} mono />
                {!isProxmox && <Row label="Image"    value={container.image} />}
                {container.host_name && <Row label="Host"     value={container.host_name} />}
                {isProxmox && container.node  && <Row label="Node" value={container.node} />}
                {isProxmox && container.vmid  && <Row label="VMID" value={container.vmid} />}
                {!isProxmox && <Row label="Platform" value={container.platform || '--'} />}
                <Row label="Hostname" value={container.hostname || '--'} />
                {container.working_dir && <Row label="Working Dir" value={container.working_dir} mono />}
                <Row label="Created"  value={fmt(container.created)} />
                {isRunning  && <Row label="Started"  value={fmt(container.state?.started_at)} />}
                {!isRunning && container.state?.finished_at && (
                  <Row label="Stopped" value={fmt(container.state.finished_at)} />
                )}
                {!isRunning && container.state?.exit_code !== undefined && container.state.exit_code !== 0 && (
                  <Row label="Exit Code" value={container.state.exit_code} />
                )}
              </Collapsible>

              {(container.ports || []).length > 0 && (
                <Collapsible title={`Port Bindings (${container.ports.length})`} icon={Network} defaultOpen>
                  {container.ports.map((p, i) => (
                    <div key={i} className="py-1.5 border-b border-border last:border-0 flex items-center justify-between">
                      <span className="font-mono text-xs text-text-muted">{p.container_port}</span>
                      {p.host_port ? (
                        <div className="flex items-center gap-1.5">
                          <span className="font-mono text-xs text-brand">
                            {p.host_ip && p.host_ip !== '0.0.0.0' ? `${p.host_ip}:` : ''}{p.host_port}
                          </span>
                          {(p.container_port.startsWith('80/') || p.container_port.startsWith('443/') || p.host_port) && (
                            <a
                              href={`${p.container_port.startsWith('443/') ? 'https' : 'http'}://localhost:${p.host_port}`}
                              target="_blank" rel="noopener noreferrer"
                              onClick={e => e.stopPropagation()}
                              className="opacity-50 hover:opacity-100 transition-opacity"
                              style={{ color: 'var(--color-brand)' }}>
                              <ExternalLink size={10} />
                            </a>
                          )}
                        </div>
                      ) : (
                        <span className="text-xs text-text-faint italic">not exposed</span>
                      )}
                    </div>
                  ))}
                </Collapsible>
              )}

              {(container.networks || []).length > 0 && (
                <Collapsible title={`Networks (${container.networks.length})`} icon={Network} defaultOpen={false}>
                  {container.networks.map((n, i) => (
                    <div key={i} className="py-1.5 border-b border-border last:border-0">
                      <span className="text-xs font-mono" style={{ color: 'var(--color-text)' }}>{n}</span>
                    </div>
                  ))}
                </Collapsible>
              )}

              {(container.mounts || []).length > 0 && (
                <Collapsible title={`Mounts (${container.mounts.length})`} icon={HardDrive} defaultOpen={false}>
                  {container.mounts.map((m, i) => (
                    <div key={i} className="py-2 border-b border-border last:border-0 space-y-0.5">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[10px] px-1.5 py-0.5 rounded font-medium"
                          style={{ background: 'var(--color-surface-offset)', color: 'var(--color-text-muted)', border: '1px solid var(--color-border)' }}>
                          {m.type}
                        </span>
                        <span className="text-[10px] text-text-faint">{m.mode}</span>
                      </div>
                      <p className="font-mono text-[10px] truncate" style={{ color: 'var(--color-text-muted)' }} title={m.source}>
                        {m.source || '—'}
                      </p>
                      <p className="font-mono text-[10px] truncate" style={{ color: 'var(--color-brand)' }} title={m.destination}>
                        → {m.destination}
                      </p>
                    </div>
                  ))}
                </Collapsible>
              )}

              {Object.keys(container.labels || {}).length > 0 && (
                <Collapsible title={`Labels (${Object.keys(container.labels).length})`} icon={Tag} defaultOpen={false}>
                  {Object.entries(container.labels).map(([k, v]) => (
                    <div key={k} className="py-1.5 border-b border-border last:border-0">
                      <p className="text-[10px] font-mono text-text-muted truncate">{k}</p>
                      <p className="text-xs font-mono text-text truncate">{v || <span className="italic text-text-faint">empty</span>}</p>
                    </div>
                  ))}
                </Collapsible>
              )}

              {(container.env || []).length > 0 && (
                <Collapsible title={`Environment (${container.env.length})`} icon={FileText} defaultOpen={false}>
                  <div className="flex items-center justify-between mb-2 pb-1 border-b border-border">
                    <button onClick={() => setMasked(v => !v)}
                      className="flex items-center gap-1 text-[10px] opacity-60 hover:opacity-100 transition-opacity"
                      style={{ color: 'var(--color-text-muted)' }}>
                      {masked ? <Eye size={9} /> : <EyeOff size={9} />}
                      {masked ? 'Show secrets' : 'Mask secrets'}
                    </button>
                  </div>
                  {envToShow.map((e, i) => {
                    const display = masked ? maskEnvValue(e) : e
                    return (
                      <div key={i} className="py-1 border-b border-border last:border-0">
                        <p className="font-mono text-[10px] text-text-muted break-all">{display}</p>
                      </div>
                    )
                  })}
                  {(container.env || []).length > 8 && (
                    <button onClick={() => setShowAllEnv(v => !v)}
                      className="mt-1 text-[10px] text-brand opacity-70 hover:opacity-100">
                      {showAllEnv ? 'Show fewer' : `Show all ${container.env.length} vars`}
                    </button>
                  )}
                </Collapsible>
              )}
            </>
          )}

          {/* ── Logs tab ── */}
          {activeTab === 'logs' && (
            <LogsTab containerId={container.id} isRunning={isRunning} />
          )}

          {/* ── Vuln tab ── */}
          {activeTab === 'vuln' && (
            <VulnTab
              container={container}
              trivyScan={trivyScan}
              updateTrivyScan={updateTrivyScan}
            />
          )}

          {/* ── Admin tab ── */}
          {activeTab === 'admin' && (
            <div className="space-y-6">
              <Collapsible title="Container Actions" icon={Settings2} defaultOpen>
                <div className="grid grid-cols-2 gap-2 pt-1">
                  <button
                    onClick={() => doAction('start')}
                    disabled={!!actioning || isRunning}
                    className="flex items-center justify-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium
                               transition-colors border-green-500/40 bg-green-500/10 text-green-400
                               hover:bg-green-500/20 disabled:opacity-40 disabled:cursor-not-allowed">
                    {actioning === 'start' ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />}
                    {actioning === 'start' ? 'Starting…' : 'Start'}
                  </button>

                  <button
                    onClick={() => doAction('stop')}
                    disabled={!!actioning || isStopped}
                    className="flex items-center justify-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium
                               transition-colors border-red-500/40 bg-red-500/10 text-red-400
                               hover:bg-red-500/20 disabled:opacity-40 disabled:cursor-not-allowed">
                    {actioning === 'stop' ? <Loader2 size={12} className="animate-spin" /> : <Square size={12} />}
                    {actioning === 'stop' ? 'Stopping…' : 'Stop'}
                  </button>

                  <button
                    onClick={() => doAction('restart')}
                    disabled={!!actioning}
                    className="col-span-2 flex items-center justify-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium
                               transition-colors border-amber-500/40 bg-amber-500/10 text-amber-400
                               hover:bg-amber-500/20 disabled:opacity-40 disabled:cursor-not-allowed">
                    {actioning === 'restart' ? <Loader2 size={12} className="animate-spin" /> : <RotateCcw size={12} />}
                    {actioning === 'restart' ? 'Restarting…' : 'Restart'}
                  </button>
                </div>

                {actionMsg && (
                  <div className="mt-3 rounded-lg px-3 py-2 font-mono text-xs"
                    style={{
                      background: actionMsg.includes('[ERROR]') ? 'rgba(239,68,68,0.1)' : 'rgba(34,197,94,0.1)',
                      color: actionMsg.includes('[ERROR]') ? '#ef4444' : '#22c55e',
                      border: `1px solid ${actionMsg.includes('[ERROR]') ? 'rgba(239,68,68,0.3)' : 'rgba(34,197,94,0.3)'}`,
                    }}>
                    {actionMsg}
                  </div>
                )}
              </Collapsible>

              {(container.command || []).length > 0 && (
                <Collapsible title="Command" icon={Terminal} defaultOpen={false}>
                  <p className="font-mono text-xs text-text break-all py-1">
                    {container.command.join(' ')}
                  </p>
                </Collapsible>
              )}

              <Collapsible title="Image Details" icon={Box} defaultOpen={false}>
                <Row label="Image"    value={container.image} />
                <Row label="Image ID" mono>
                  <span className="font-mono text-[10px] text-text break-all">{container.image_id?.replace('sha256:','').slice(0,32) || '--'}</span>
                </Row>
              </Collapsible>
            </div>
          )}
        </div>
      </aside>
    </>
  )
}
