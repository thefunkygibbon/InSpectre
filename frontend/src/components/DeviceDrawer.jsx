import { useState, useEffect, useRef } from 'react'
import {
  X, Wifi, WifiOff, Globe, Clock, Terminal,
  ShieldCheck, ScanLine, RefreshCw, ExternalLink,
  Activity, GitBranch, RotateCcw, Ban, History,
  ChevronDown, ChevronRight, Square, Tag, CheckCircle2,
  FileText, Star as StarIcon, ShieldAlert, EyeOff, Eye, Layers,
  AlertTriangle, Network, Loader2, GitMerge, Radio, BellOff, Plus, Trash2,
  TrendingUp, TrendingDown,
} from 'lucide-react'
import { OnlineDot }      from './OnlineDot'
import { StarButton }     from './StarButton'
import { DeviceNotes }    from './DeviceNotes'
import { DeviceTimeline } from './DeviceTimeline'
import { VulnPanel }      from './VulnPanel'
import { TrafficPanel }   from './TrafficPanel'
import { StreamOutput }   from './StreamOutput'
import { api }            from '../api'
import { useStreamAction }  from '../hooks/useStreamAction'
import { CATEGORIES, OVERRIDE_OPTIONS } from '../deviceCategories'

function fmt(iso) {
  if (!iso) return '--'
  return new Date(iso).toLocaleString()
}
function fmtDate(iso) {
  if (!iso) return '--'
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
}

const HTTP_PORTS  = new Set([80, 8080, 8000, 3000, 5000, 8888, 8008, 8081, 8082, 8090, 9000, 9090, 1880])
const HTTPS_PORTS = new Set([443, 8443, 4443, 9443])
function isWebPort(port)   { return HTTP_PORTS.has(port) || HTTPS_PORTS.has(port) }
function portUrl(ip, port) { return `${HTTPS_PORTS.has(port) ? 'https' : 'http'}://${ip}:${port}` }

const PORT_DESCRIPTIONS = {
  21:    'FTP',              22:    'SSH',
  23:    'Telnet',           25:    'SMTP',
  53:    'DNS',              80:    'HTTP',
  110:   'POP3',             143:   'IMAP',
  443:   'HTTPS',            445:   'SMB',
  554:   'RTSP (stream)',    631:   'IPP (printer)',
  993:   'IMAPS',            995:   'POP3S',
  1883:  'MQTT',             3306:  'MySQL',
  3389:  'RDP',              5353:  'mDNS',
  5432:  'PostgreSQL',       5900:  'VNC',
  6379:  'Redis',            8080:  'HTTP-alt',
  8443:  'HTTPS-alt',        8883:  'MQTT/TLS',
  9100:  'JetDirect (print)', 27017: 'MongoDB',
}
const DANGEROUS_PORTS = new Set([21, 23, 3389, 5900])

const ZONE_COLORS = {
  Trusted:        { bg: 'rgba(34,197,94,0.12)',   color: '#22c55e',   border: 'rgba(34,197,94,0.3)'   },
  IoT:            { bg: 'rgba(20,184,166,0.12)',   color: '#14b8a6',   border: 'rgba(20,184,166,0.3)'  },
  Guest:          { bg: 'rgba(251,191,36,0.12)',   color: '#f59e0b',   border: 'rgba(251,191,36,0.3)'  },
  Lab:            { bg: 'rgba(139,92,246,0.12)',   color: '#8b5cf6',   border: 'rgba(139,92,246,0.3)'  },
  Infrastructure: { bg: 'rgba(99,102,241,0.12)',   color: '#6366f1',   border: 'rgba(99,102,241,0.3)'  },
}
function zoneStyle(zone) {
  return ZONE_COLORS[zone] || { bg: 'rgba(107,114,128,0.12)', color: '#6b7280', border: 'rgba(107,114,128,0.3)' }
}

const TABS = [
  { id: 'overview',  label: 'Overview'  },
  { id: 'vulns',     label: 'Vulns'     },
  { id: 'traffic',   label: 'Traffic'   },
  { id: 'timeline',  label: 'Timeline'  },
  { id: 'admin',     label: 'Admin'     },
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

function IpHistorySection({ mac }) {
  const [history, setHistory] = useState(null)
  const [error,   setError]   = useState(null)
  const [loaded,  setLoaded]  = useState(false)

  useEffect(() => {
    if (loaded) return
    setLoaded(true)
    api.getIpHistory(mac).then(setHistory).catch(e => { setError(e.message); setHistory([]) })
  }, [mac, loaded])

  if (history === null) return (
    <div className="space-y-2">
      {[...Array(2)].map((_, i) => <div key={i} className="skeleton h-8 rounded-lg" />)}
    </div>
  )
  if (error)            return <p className="text-xs text-red-400">{error}</p>
  if (history.length === 0) return <p className="text-xs text-text-muted italic">No IP history recorded yet.</p>

  return (
    <div className="space-y-0">
      <div className="grid grid-cols-[1fr_1fr_1fr] gap-2 pb-1.5 border-b border-border">
        <span className="text-[10px] font-semibold uppercase tracking-wider text-text-faint">IP Address</span>
        <span className="text-[10px] font-semibold uppercase tracking-wider text-text-faint">First seen</span>
        <span className="text-[10px] font-semibold uppercase tracking-wider text-text-faint">Last seen</span>
      </div>
      {history.map((row, i) => (
        <div key={i} className="grid grid-cols-[1fr_1fr_1fr] gap-2 py-1.5 border-b border-border last:border-0 items-center">
          <span className="font-mono text-xs text-brand">{row.ip}</span>
          <span className="text-xs text-text-muted">{fmtDate(row.first_seen)}</span>
          <span className="text-xs text-text-muted">{fmtDate(row.last_seen)}</span>
        </div>
      ))}
    </div>
  )
}

const DATALIST_ID = 'vendor-suggestions'

function VendorInput({ value, onChange, placeholder }) {
  const [vendors, setVendors] = useState([])
  useEffect(() => {
    if (VendorInput._cache) { setVendors(VendorInput._cache); return }
    api.getVendors().then(list => {
      const sorted = [...new Set(list.filter(Boolean))].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()))
      VendorInput._cache = sorted
      setVendors(sorted)
    }).catch(() => {})
  }, [])
  return (
    <>
      <datalist id={DATALIST_ID}>
        {vendors.map(v => <option key={v} value={v} />)}
      </datalist>
      <input list={DATALIST_ID} className="input w-full" value={value} onChange={e => onChange(e.target.value)}
        placeholder={placeholder} autoComplete="off" spellCheck={false} />
      {vendors.length > 0 && (
        <p className="text-[10px] text-text-faint mt-1">{vendors.length} known vendor{vendors.length !== 1 ? 's' : ''} — start typing to filter</p>
      )}
    </>
  )
}
VendorInput._cache = null

function IdentityForm({ device, onSaved }) {
  const [vendor,  setVendor]  = useState(device.vendor_override || device.vendor || '')
  const [typeKey, setTypeKey] = useState(device.device_type_override || '')
  const [saving,  setSaving]  = useState(false)
  const [saved,   setSaved]   = useState(false)
  const [error,   setError]   = useState(null)

  async function handleSave(e) {
    e.preventDefault()
    setSaving(true); setError(null); setSaved(false)
    try {
      const updated = await api.updateIdentity(device.mac_address, {
        vendor_override:      vendor.trim() || null,
        device_type_override: typeKey        || null,
      })
      setSaved(true)
      VendorInput._cache = null
      setTimeout(() => setSaved(false), 2500)
      if (onSaved) onSaved(updated)
    } catch (err) { setError(err.message) }
    finally { setSaving(false) }
  }

  return (
    <form onSubmit={handleSave} className="space-y-3">
      <div>
        <label className="block text-xs text-text-muted mb-1">Vendor</label>
        <VendorInput value={vendor} onChange={setVendor} placeholder={device.vendor || 'e.g. Amazon Technologies Inc.'} />
      </div>
      <div>
        <label className="block text-xs text-text-muted mb-1">Device Type</label>
        <div className="relative">
          <select className="input w-full appearance-none pr-8" value={typeKey} onChange={e => setTypeKey(e.target.value)}>
            {OVERRIDE_OPTIONS.map(opt => (
              <option key={opt.value} value={opt.value}>
                {opt.value && CATEGORIES[opt.value] ? `${CATEGORIES[opt.value].label} — ${opt.label}` : opt.label}
              </option>
            ))}
          </select>
          <ChevronDown size={13} className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 text-text-faint" />
        </div>
      </div>
      <p className="text-[11px] text-text-faint leading-relaxed">
        Saving a device type records a fingerprint entry in your local database.
      </p>
      {error && <p className="text-xs text-red-400">{error}</p>}
      <div className="flex gap-2">
        <button type="submit" disabled={saving} className="btn-primary flex items-center gap-1.5 shrink-0">
          {saved ? <><CheckCircle2 size={13} /> Saved!</> : saving ? 'Saving…' : 'Save Identity'}
        </button>
        <button type="button" onClick={() => { setVendor(''); setTypeKey('') }}
          className="btn-ghost text-xs text-text-faint hover:text-text">Reset to auto</button>
      </div>
    </form>
  )
}

// Service label display helper (maps Nerva scheme names to readable labels)
const SERVICE_LABELS = {
  http: 'HTTP',         https: 'HTTPS',         ssh: 'SSH',
  ftp: 'FTP',           telnet: 'Telnet',        smtp: 'SMTP',
  pop3: 'POP3',         imap: 'IMAP',            imaps: 'IMAPS',
  mysql: 'MySQL',       postgresql: 'PostgreSQL', mssql: 'MSSQL',
  redis: 'Redis',       mongodb: 'MongoDB',       elasticsearch: 'Elasticsearch',
  mqtt: 'MQTT',         mqtts: 'MQTT/TLS',       smb: 'SMB',
  rdp: 'RDP',           vnc: 'VNC',              ldap: 'LDAP',
  ldaps: 'LDAPS',       ftps: 'FTPS',
  dns: 'DNS',           ntp: 'NTP',              amqp: 'AMQP',
  amqps: 'AMQPS',       cassandra: 'Cassandra',   memcached: 'Memcached',
  ws: 'WebSocket',      wss: 'WebSocket/TLS',
}
function svcLabel(scheme) {
  return SERVICE_LABELS[scheme] || scheme
}

// Pipeline stage indicator
const PIPELINE_STEPS = [
  { key: 'discovered',  label: 'Discovered'  },
  { key: 'ports',       label: 'Ports'       },
  { key: 'services',    label: 'Services'    },
  { key: 'vulns',       label: 'Vuln scan'   },
]

function ScanPipeline({ device, vulnScanning }) {
  const { deep_scanned, pipeline_stage, vuln_last_scanned, is_online } = device

  function stepStatus(key) {
    if (key === 'discovered') return 'done'
    if (key === 'ports') {
      if (deep_scanned) return 'done'
      return is_online ? 'running' : 'pending'
    }
    if (key === 'services') {
      if (pipeline_stage === 'services_done') return 'done'
      if (deep_scanned) return 'running'
      return 'pending'
    }
    if (key === 'vulns') {
      if (vulnScanning) return 'running'
      if (vuln_last_scanned) return 'done'
      return 'pending'
    }
    return 'pending'
  }

  return (
    <div className="card p-3">
      <div className="flex items-center gap-2 mb-2.5">
        <Network size={13} className="text-brand" />
        <span className="text-[11px] font-semibold text-text-muted uppercase tracking-wider">Scan Pipeline</span>
      </div>
      <div className="flex items-center gap-0">
        {PIPELINE_STEPS.map((step, i) => {
          const status = stepStatus(step.key)
          const isLast = i === PIPELINE_STEPS.length - 1
          return (
            <div key={step.key} className="flex items-center flex-1 min-w-0">
              <div className="flex flex-col items-center flex-1 min-w-0">
                <div className={`w-5 h-5 rounded-full flex items-center justify-center shrink-0 mb-1
                  ${status === 'done'    ? 'bg-green-500/20 border border-green-500/50'
                  : status === 'running' ? 'bg-brand/20 border border-brand/50'
                  : 'bg-surface-offset border border-border'}`}>
                  {status === 'done' && <CheckCircle2 size={10} className="text-green-400" />}
                  {status === 'running' && <Loader2 size={10} className="text-brand animate-spin" />}
                  {status === 'pending' && <span className="w-1.5 h-1.5 rounded-full bg-text-faint" />}
                </div>
                <span className={`text-[9px] font-medium leading-none text-center truncate w-full px-0.5
                  ${status === 'done' ? 'text-green-400'
                  : status === 'running' ? 'text-brand'
                  : 'text-text-faint'}`}>
                  {step.label}
                </span>
              </div>
              {!isLast && (
                <div className={`h-px flex-1 mx-0.5 -mt-3
                  ${status === 'done' ? 'bg-green-500/40' : 'bg-border'}`} />
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------
export function DeviceDrawer({ device, onClose, onRename, onResolveName, onRefresh, onStarToggle, onMetadataUpdate, onZoneChange, vulnScanState, onVulnScanChange, initialTab }) {
  if (!device) return null

  const [localDevice,  setLocalDevice]  = useState(device)
  const [resolving,    setResolving]    = useState(false)
  const [rescanning,   setRescanning]   = useState(false)
  const [activeAction, setActiveAction] = useState(null)  // 'ping' | 'traceroute' | 'rescan'
  const [staticLines,  setStaticLines]  = useState([])
  const [activeTab,    setActiveTab]    = useState(initialTab || 'overview')
  const [blocking,     setBlocking]     = useState(false)
  const [ignoring,     setIgnoring]     = useState(false)
  const [deleting,     setDeleting]     = useState(false)

  // Vuln scan state is owned by the parent (App.jsx) so it survives drawer close/reopen.
  // Proxy setters propagate functional updaters so rapid SSE lines don't get lost to stale closures.
  const vulnLines    = vulnScanState?.lines    ?? []
  const vulnScanning = vulnScanState?.scanning ?? false
  function setVulnLines(updater) {
    if (!onVulnScanChange) return
    if (typeof updater === 'function') {
      onVulnScanChange(s => ({ lines: updater(s.lines) }))
    } else {
      onVulnScanChange({ lines: updater })
    }
  }
  function setVulnScanning(updater) {
    if (!onVulnScanChange) return
    if (typeof updater === 'function') {
      onVulnScanChange(s => ({ scanning: updater(s.scanning) }))
    } else {
      onVulnScanChange({ scanning: updater })
    }
  }

  useEffect(() => { setLocalDevice(device) }, [device])

  const stream = useStreamAction()

  const name = localDevice.custom_name || localDevice.hostname || localDevice.ip_address
  const scan = localDevice.scan_results
  const mac  = localDevice.mac_address

  const vulnSev    = localDevice.vuln_severity
  const vulnSevCfg = vulnSev && vulnSev !== 'clean' ? {
    critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#3b82f6', info: '#8b5cf6'
  }[vulnSev] : null

  async function handleResolve() {
    setResolving(true)
    await onResolveName(mac)
    setResolving(false)
  }

  async function handleRescan() {
    setRescanning(true); setActiveAction('rescan'); stream.stop(); stream.clear(); setStaticLines([])
    try {
      await api.rescanDevice(mac)
      setStaticLines(['[INFO] Deep scan queued — results will update shortly.'])
    } catch (e) { setStaticLines([`[ERROR] ${e.message}`]) }
    finally { setRescanning(false); if (onRefresh) onRefresh() }
  }

  function handlePing() {
    if (activeAction === 'ping' && stream.running) { stream.stop(); return }
    setActiveAction('ping'); setStaticLines([])
    stream.start(`/devices/${mac}/ping`)
  }

  function handleTraceroute() {
    if (activeAction === 'traceroute' && stream.running) { stream.stop(); return }
    setActiveAction('traceroute'); setStaticLines([])
    stream.start(`/devices/${mac}/traceroute`)
  }

  async function handleBlockToggle() {
    setBlocking(true)
    setActiveAction('block')
    setStaticLines([])
    try {
      const action = localDevice.is_blocked ? 'unblock' : 'block'
      const updated = localDevice.is_blocked
        ? await api.unblockDevice(mac)
        : await api.blockDevice(mac)
      setLocalDevice(updated)
      if (onRefresh) onRefresh()
      setStaticLines([
        action === 'block'
          ? `[OK] Device ${updated.ip_address} is now blocked from the internet via ARP spoofing.`
          : `[OK] Device ${updated.ip_address} has been unblocked — internet access restored.`,
      ])
    } catch (e) {
      setStaticLines([`[ERROR] ${e.message}`])
    } finally {
      setBlocking(false)
    }
  }

  async function handleStarClick(mac, value) {
    setLocalDevice(prev => ({ ...prev, is_important: value }))
    if (onStarToggle) onStarToggle(mac, value)
  }

  async function handleIgnoreToggle() {
    setIgnoring(true)
    const newVal = !localDevice.is_ignored
    setLocalDevice(prev => ({ ...prev, is_ignored: newVal }))
    try {
      const updated = await api.updateMetadata(mac, { is_ignored: newVal })
      setLocalDevice(updated)
      if (onRefresh) onRefresh()
    } catch {
      setLocalDevice(prev => ({ ...prev, is_ignored: !newVal }))
    } finally {
      setIgnoring(false)
    }
  }

  const termLines   = stream.lines.length ? stream.lines : staticLines
  const termRunning = stream.running
  const pingRunning  = activeAction === 'ping'       && stream.running
  const traceRunning = activeAction === 'traceroute' && stream.running

  // Derive stream mode so StreamOutput knows how to render
  const streamMode = activeAction === 'ping'       ? 'ping'
                   : activeAction === 'traceroute' ? 'traceroute'
                   : 'generic'

  return (
    <>
      <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40" onClick={onClose} />
      <aside className="fixed right-0 top-0 h-full w-full max-w-md bg-surface border-l border-border
                        z-50 flex flex-col shadow-2xl animate-slide-in overflow-hidden">

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-5 border-b border-border">
          <div className="flex items-center gap-3 min-w-0">
            <OnlineDot online={localDevice.is_online} />
            <div className="min-w-0">
              <h2 className="font-semibold text-text truncate">{name}</h2>
              <p className="text-xs text-text-muted font-mono">{mac}</p>
            </div>
          </div>
          <div className="flex items-center gap-1 shrink-0">
            <StarButton device={localDevice} onToggle={handleStarClick} size={16} />
            <button onClick={onClose} className="btn-ghost p-2" aria-label="Close"><X size={18} /></button>
          </div>
        </div>

        {/* Tab bar */}
        <div className="flex border-b border-border px-4 gap-0 overflow-x-auto scrollbar-none" style={{ background: 'var(--color-surface)' }}>
          {TABS.map(tab => {
            const isVuln   = tab.id === 'vulns'
            const isActive = activeTab === tab.id
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className="px-3 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
                style={isActive
                  ? { borderColor: 'var(--color-brand)', color: 'var(--color-brand)' }
                  : { borderColor: 'transparent', color: 'var(--color-text-muted)' }}
              >
                {tab.label}
                {isVuln && vulnSevCfg && (
                  <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: vulnSevCfg }} />
                )}
              </button>
            )
          })}
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">

          {activeTab === 'overview' && (
            <>
              {/* Scan pipeline progress */}
              <ScanPipeline device={localDevice} vulnScanning={vulnScanning} />

              {/* Virtual interface notice */}
              {localDevice.is_virtual_interface && (
                <div className="flex items-start gap-2 px-3 py-2.5 rounded-lg"
                  style={{ background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.25)' }}>
                  <GitMerge size={13} className="mt-0.5 shrink-0" style={{ color: '#818cf8' }} />
                  <p className="text-[11px] leading-snug" style={{ color: '#a5b4fc' }}>
                    Virtual interface (macvlan / container) — shares IPs with the physical NIC on
                    this host. Scan data may differ from the primary device entry.
                  </p>
                </div>
              )}

              {/* Status badges */}
              <div className="flex gap-2 flex-wrap">
                {localDevice.is_online
                  ? <span className="badge-online"><Wifi size={11} />Online</span>
                  : <span className="badge-offline"><WifiOff size={11} />Offline</span>}
                {localDevice.deep_scanned
                  ? <span className="badge-online"><ShieldCheck size={11} />Scanned</span>
                  : <span className="badge-scanning"><ScanLine size={11} className="animate-pulse" />Scan pending</span>}
                {localDevice.device_type_override && (
                  <span className="badge-online" style={{ background: 'rgba(20,184,166,0.12)', color: '#14b8a6', border: '1px solid rgba(20,184,166,0.3)' }}>
                    <Tag size={11} />Identity confirmed
                  </span>
                )}
                {localDevice.is_important && (
                  <span className="badge-online" style={{ background: 'rgba(245,158,11,0.12)', color: '#f59e0b', border: '1px solid rgba(245,158,11,0.3)' }}>
                    <StarIcon size={11} />Watched
                  </span>
                )}
                {vulnSev && vulnSev !== 'clean' && (
                  <span className="badge-online" style={{ background: `rgba(239,68,68,0.12)`, color: vulnSevCfg, border: `1px solid rgba(239,68,68,0.3)` }}>
                    <ShieldAlert size={11} />{vulnSev.charAt(0).toUpperCase() + vulnSev.slice(1)} vuln
                  </span>
                )}
                {localDevice.is_blocked && (
                  <span className="badge-online" style={{ background: 'rgba(239,68,68,0.15)', color: '#f87171', border: '1px solid rgba(239,68,68,0.4)' }}>
                    <Ban size={11} />Blocked
                  </span>
                )}
                {localDevice.zone && (() => {
                  const zs = zoneStyle(localDevice.zone)
                  return (
                    <span className="badge-online" style={{ background: zs.bg, color: zs.color, border: `1px solid ${zs.border}` }}>
                      <Layers size={11} />{localDevice.zone}
                    </span>
                  )
                })()}
                {localDevice.is_ignored && (
                  <span className="badge-online" style={{ background: 'rgba(107,114,128,0.12)', color: '#6b7280', border: '1px solid rgba(107,114,128,0.3)' }}>
                    <EyeOff size={11} />Ignored
                  </span>
                )}
              </div>

              {/* Actions */}
              <Collapsible title="Actions" icon={Activity} defaultOpen={true}>
                <div className="grid grid-cols-2 gap-2 pt-1">
                  {pingRunning
                    ? <StopBtn label="Stop Ping"  onClick={handlePing} />
                    : <ActionBtn icon={Activity}    label="Ping"         active={activeAction === 'ping'}       onClick={handlePing} />}
                  {traceRunning
                    ? <StopBtn label="Stop Trace" onClick={handleTraceroute} />
                    : <ActionBtn icon={GitBranch}   label="Traceroute"   active={activeAction === 'traceroute'} onClick={handleTraceroute} />}
                  <ActionBtn icon={RotateCcw}   label="Re-scan ports" active={activeAction === 'rescan'}     loading={rescanning} onClick={handleRescan} />
                  <ActionBtn icon={ShieldAlert} label="Vuln scan"     active={activeTab   === 'vulns'}
                    onClick={() => setActiveTab('vulns')} />
                </div>
                <button
                  onClick={handleBlockToggle}
                  disabled={blocking}
                  className={`mt-2 w-full flex items-center justify-center gap-2 py-2 rounded-lg
                             border text-xs font-medium transition-colors duration-150
                             ${localDevice.is_blocked
                               ? 'border-red-500/60 bg-red-500/15 text-red-400 hover:bg-red-500/25'
                               : 'border-orange-500/40 bg-orange-500/10 text-orange-400 hover:bg-orange-500/20'
                             }
                             ${blocking ? 'opacity-60 cursor-wait' : ''}`}>
                  <Ban size={12} className={blocking ? 'animate-pulse' : ''} />
                  {blocking
                    ? (localDevice.is_blocked ? 'Unblocking…' : 'Blocking…')
                    : (localDevice.is_blocked ? 'Unblock device' : 'Block internet access')}
                </button>
                <button
                  onClick={handleIgnoreToggle}
                  disabled={ignoring}
                  className={`mt-2 w-full flex items-center justify-center gap-2 py-2 rounded-lg
                             border text-xs font-medium transition-colors duration-150
                             ${localDevice.is_ignored
                               ? 'border-brand/40 bg-brand/10 text-brand hover:bg-brand/20'
                               : 'border-border bg-surface-offset text-text-muted hover:text-text hover:border-border'
                             }
                             ${ignoring ? 'opacity-60 cursor-wait' : ''}`}>
                  {localDevice.is_ignored
                    ? <><Eye size={12} /> Un-ignore device</>
                    : <><EyeOff size={12} /> Ignore device</>}
                </button>
                <StreamOutput
                  lines={termLines}
                  running={termRunning}
                  onStop={stream.stop}
                  mode={streamMode}
                />
              </Collapsible>

              {/* Network */}
              <Collapsible title="Network" icon={Globe} defaultOpen={true}>
                <Row label="IP Address"  value={localDevice.ip_address} mono />
                <Row label="MAC Address" value={mac} mono />
                <Row label="Vendor"      value={localDevice.vendor_override || localDevice.vendor || 'Unknown'} />
                <Row
                  label="Hostname"
                  value={
                    <span className="flex items-center gap-2">
                      <span className="truncate">{localDevice.hostname || '--'}</span>
                      <button onClick={handleResolve} disabled={resolving}
                        className="shrink-0 text-brand hover:text-brand-light transition-colors"
                        title="Re-resolve hostname" aria-label="Re-resolve hostname">
                        <RefreshCw size={12} className={resolving ? 'animate-spin' : ''} />
                      </button>
                    </span>
                  }
                />
                {localDevice.custom_name && <Row label="Custom name" value={localDevice.custom_name} />}
                {localDevice.location    && <Row label="Location"    value={localDevice.location} />}
                <ZoneEditor mac={mac} currentZone={localDevice.zone} onChanged={zone => {
                  setLocalDevice(prev => ({ ...prev, zone }))
                  if (onZoneChange) onZoneChange(zone)
                }} />
                {localDevice.miss_count  !== undefined && <Row label="Miss count" value={localDevice.miss_count} />}
                <MdnsRow mac={mac} scan={scan} onRefreshed={updated => setLocalDevice(prev => ({ ...prev, scan_results: { ...(prev.scan_results || {}), mdns_services: updated } }))} />
              </Collapsible>

              {/* IP History */}
              <Collapsible title="IP History" icon={History} defaultOpen={false}>
                <IpHistorySection mac={mac} />
              </Collapsible>

              {/* Timeline summary */}
              <Collapsible title="Timeline" icon={Clock} defaultOpen={true}>
                <Row label="First seen" value={fmt(localDevice.first_seen)} />
                <Row label="Last seen"  value={fmt(localDevice.last_seen)} />
                {scan?.scanned_at && <Row label="Scanned at" value={fmt(scan.scanned_at)} />}
              </Collapsible>

              {/* Open Ports */}
              {scan?.open_ports?.length > 0 && (() => {
                // Summarise vuln severity counts from the latest report if available
                const sevCounts = {}
                const latestFindings = localDevice.latest_vuln_findings || []
                for (const f of latestFindings) {
                  if (['critical','high','medium'].includes(f.severity)) {
                    sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1
                  }
                }
                const sevBadges = Object.entries(sevCounts).map(([sev, n]) => {
                  const colors = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b' }
                  return (
                    <span key={sev} className="text-[9px] font-semibold px-1 rounded"
                      style={{ background: `${colors[sev]}20`, color: colors[sev] }}>
                      {n} {sev[0].toUpperCase()}
                    </span>
                  )
                })
                const portTitle = (
                  <span className="flex items-center gap-1.5">
                    Open Ports ({scan.open_ports.length})
                    {sevBadges.length > 0 && (
                      <span className="flex items-center gap-1 ml-1">{sevBadges}</span>
                    )}
                  </span>
                )
                return (
                <Collapsible title={portTitle} icon={Terminal} defaultOpen={true}>
                  {scan.open_ports.map((p, i) => {
                    const web        = isWebPort(p.port)
                    const url        = web ? portUrl(localDevice.ip_address, p.port) : null
                    const dangerous  = DANGEROUS_PORTS.has(p.port)
                    const nervaSvc   = (localDevice.services || []).find(s => s.port === p.port)
                    const label      = nervaSvc
                      ? svcLabel(nervaSvc.service)
                      : (p.service || PORT_DESCRIPTIONS[p.port] || '')
                    const hasTls     = nervaSvc?.tls
                    return (
                      <div key={i} className="py-2 border-b border-border last:border-0 space-y-0.5">
                        <div className="flex items-center gap-3">
                          {web ? (
                            <a href={url} target="_blank" rel="noopener noreferrer"
                              className="font-mono text-xs text-brand hover:text-brand-light underline
                                         underline-offset-2 w-20 shrink-0 flex items-center gap-1 group">
                              {p.port}/{p.proto}
                              <ExternalLink size={9} className="opacity-60 group-hover:opacity-100" />
                            </a>
                          ) : (
                            <span className={`font-mono text-xs w-20 shrink-0 ${dangerous ? 'text-amber-400' : 'text-text-muted'}`}>
                              {dangerous && <AlertTriangle size={10} className="inline mr-1 opacity-70" />}
                              {p.port}/{p.proto}
                            </span>
                          )}
                          <span className="text-sm text-text flex-1 truncate">{label}</span>
                          <div className="flex items-center gap-1.5 shrink-0">
                            {hasTls && (
                              <span className="text-[9px] px-1 py-0.5 rounded font-medium"
                                style={{ background: 'rgba(34,197,94,0.1)', color: '#22c55e', border: '1px solid rgba(34,197,94,0.25)' }}>
                                TLS
                              </span>
                            )}
                            {(p.product || p.version) && (
                              <span className="text-xs text-text-muted truncate max-w-[110px]">
                                {[p.product, p.version].filter(Boolean).join(' ')}
                              </span>
                            )}
                          </div>
                        </div>
                        {p.cpe && (
                          <p className="font-mono text-[10px] text-text-faint pl-20 truncate" title={p.cpe}>{p.cpe}</p>
                        )}
                      </div>
                    )
                  })}
                </Collapsible>
                )
              })()}

              {/* Port Baseline */}
              {localDevice.baseline_ports != null && (
                <Collapsible title="Port Baseline" icon={GitBranch} defaultOpen={false}>
                  <PortBaselineSection device={localDevice} onReset={() => {
                    api.resetBaseline(mac).then(() => {
                      setLocalDevice(prev => ({ ...prev, baseline_ports: null, baseline_scan_count: 0 }))
                    }).catch(() => {})
                  }} />
                </Collapsible>
              )}
            </>
          )}

          {activeTab === 'vulns' && (
            <VulnPanel
              device={localDevice}
              lines={vulnLines}
              setLines={setVulnLines}
              scanning={vulnScanning}
              setScanning={setVulnScanning}
              onScanComplete={() => {
                api.getDevice(mac).then(updated => {
                  setLocalDevice(updated)
                  if (onRefresh) onRefresh()
                }).catch(() => {})
              }}
            />
          )}

          {activeTab === 'traffic' && (
            <TrafficPanel device={localDevice} />
          )}

          {activeTab === 'timeline' && (
            <>
              <div className="flex items-center gap-2 mb-4">
                <Clock size={14} className="text-brand" />
                <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider">Event Timeline</h3>
              </div>
              <DeviceTimeline mac={mac} />
            </>
          )}

          {activeTab === 'admin' && (
            <div className="space-y-6">
              <Collapsible title="Notes, Tags & Location" icon={FileText} defaultOpen={true}>
                <DeviceNotes
                  device={localDevice}
                  onSaved={updated => {
                    setLocalDevice(prev => ({ ...prev, ...updated }))
                    if (onMetadataUpdate) onMetadataUpdate(mac, updated)
                  }}
                />
              </Collapsible>

              <Collapsible title="Device Identity" icon={Tag} defaultOpen={true}>
                <IdentityForm
                  device={localDevice}
                  onSaved={updated => {
                    setLocalDevice(updated)
                    if (onRefresh) onRefresh()
                  }}
                />
              </Collapsible>

              <Collapsible title="Rename Device" icon={RotateCcw} defaultOpen={true}>
                <RenameForm device={localDevice} onRename={onRename} />
              </Collapsible>

              <Collapsible title="Alert Suppressions" icon={BellOff} defaultOpen={false}>
                <SuppressionManager mac={mac} />
              </Collapsible>

              {/* Danger zone */}
              <div className="rounded-xl border border-red-500/30 overflow-hidden">
                <div className="px-4 py-2.5 border-b border-red-500/20"
                  style={{ background: 'rgba(239,68,68,0.06)' }}>
                  <span className="text-xs font-semibold uppercase tracking-wider text-red-400">Danger Zone</span>
                </div>
                <div className="p-4 space-y-3">
                  <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
                    Permanently delete this device and all associated data (events, scan reports,
                    traffic stats, alerts). The device will be re-discovered automatically if it
                    becomes active again on the network.
                  </p>
                  <button
                    disabled={deleting}
                    onClick={async () => {
                      if (!window.confirm(`Delete ${localDevice.custom_name || localDevice.hostname || mac} and all its data? This cannot be undone.`)) return
                      setDeleting(true)
                      try {
                        await api.deleteDevice(mac)
                        onClose()
                        if (onRefresh) onRefresh()
                      } catch (e) {
                        alert('Delete failed: ' + e.message)
                        setDeleting(false)
                      }
                    }}
                    className="flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium
                               transition-colors duration-150 border-red-500/40 bg-red-500/10 text-red-400
                               hover:bg-red-500/20 disabled:opacity-50 disabled:cursor-not-allowed">
                    <Trash2 size={13} />
                    {deleting ? 'Deleting…' : 'Delete Device'}
                  </button>
                </div>
              </div>
            </div>
          )}

        </div>
      </aside>
    </>
  )
}

function ActionBtn({ icon: Icon, label, onClick, active, loading }) {
  return (
    <button onClick={onClick} disabled={loading}
      className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium
                  transition-colors duration-150
                  ${ active
                    ? 'border-brand bg-brand/10 text-brand'
                    : 'border-border bg-surface-offset hover:bg-surface-dynamic text-text-muted hover:text-text'
                  }
                  ${ loading ? 'opacity-60 cursor-wait' : '' }`}>
      <Icon size={13} className={loading ? 'animate-spin' : ''} />
      {label}
    </button>
  )
}

function StopBtn({ label, onClick }) {
  return (
    <button onClick={onClick}
      className="flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium
                 transition-colors duration-150
                 border-red-500/40 bg-red-500/10 text-red-400
                 hover:bg-red-500/20 hover:border-red-500/60">
      <Square size={12} className="fill-current" />
      {label}
    </button>
  )
}

function Section({ title, icon: Icon, children }) {
  return (
    <div>
      <div className="flex items-center gap-2 mb-3">
        {Icon && <Icon size={14} className="text-brand" />}
        <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider">{title}</h3>
      </div>
      <div className="card p-4 space-y-0.5">{children}</div>
    </div>
  )
}

function Row({ label, value, mono }) {
  return (
    <div className="flex items-center justify-between py-1.5 gap-4 border-b border-border last:border-0">
      <span className="text-xs text-text-muted shrink-0">{label}</span>
      <span className={`text-sm text-text text-right truncate ${mono ? 'font-mono text-xs' : ''}`}>
        {value ?? '--'}
      </span>
    </div>
  )
}

function RenameForm({ device, onRename }) {
  const [val, setVal]       = useState(device.custom_name || '')
  const [saving, setSaving] = useState(false)

  async function handleSave(e) {
    e.preventDefault()
    setSaving(true)
    await onRename(device.mac_address, val.trim())
    setSaving(false)
  }

  return (
    <form onSubmit={handleSave} className="flex gap-2">
      <input className="input" value={val} onChange={e => setVal(e.target.value)}
        placeholder={device.hostname || device.ip_address || 'Custom name…'} />
      <button type="submit" disabled={saving} className="btn-primary shrink-0">
        {saving ? '…' : 'Save'}
      </button>
    </form>
  )
}

function ZoneEditor({ mac, currentZone, onChanged }) {
  const [editing,   setEditing]   = useState(false)
  const [value,     setValue]     = useState(currentZone || '')
  const [zones,     setZones]     = useState([])
  const [saving,    setSaving]    = useState(false)

  useEffect(() => {
    api.getDeviceZones().then(setZones).catch(() => {})
  }, [])

  const [saveError, setSaveError] = useState(null)

  async function handleSave(e) {
    e.preventDefault()
    setSaving(true)
    setSaveError(null)
    const zoneVal = (value.trim() === '' || value.trim() === '-NONE-') ? null : value.trim()
    try {
      await api.assignZone({ mac_addresses: [mac], zone: zoneVal })
      onChanged(zoneVal)
      setEditing(false)
    } catch (err) {
      setSaveError(err.message || 'Save failed')
    } finally { setSaving(false) }
  }

  const displayZone = currentZone || 'Unassigned'
  if (!editing) {
    return (
      <div className="flex items-center justify-between py-1.5 gap-4 border-b border-border last:border-0">
        <span className="text-xs text-text-muted shrink-0">Zone</span>
        <span className="flex items-center gap-2 text-sm text-text">
          <span className={currentZone ? 'text-text' : 'text-text-faint italic'}>{displayZone}</span>
          <button onClick={() => { setValue(currentZone || ''); setEditing(true) }}
            className="text-brand hover:text-brand opacity-60 hover:opacity-100 transition-opacity" title="Edit zone">
            <Tag size={11} />
          </button>
        </span>
      </div>
    )
  }

  return (
    <div className="flex flex-col py-1.5 gap-1 border-b border-border last:border-0">
      <div className="flex items-center justify-between gap-4">
        <span className="text-xs text-text-muted shrink-0">Zone</span>
        <form onSubmit={handleSave} className="flex gap-1 items-center">
          <input
            list="zone-list"
            className="input py-0.5 px-2 text-xs h-6 w-32"
            value={value}
            onChange={e => { setValue(e.target.value); setSaveError(null) }}
            placeholder="Zone name or leave blank…"
            autoFocus
          />
          <datalist id="zone-list">
            <option value="-NONE-" />
            {zones.map(z => <option key={z} value={z} />)}
          </datalist>
          <button type="submit" disabled={saving}
            className="text-xs px-2 py-0.5 rounded" style={{ background: 'var(--color-brand)', color: '#fff' }}>
            {saving ? '…' : 'Set'}
          </button>
          <button type="button" onClick={() => { setEditing(false); setSaveError(null) }}
            className="text-xs px-1 py-0.5 rounded opacity-60 hover:opacity-100" style={{ color: 'var(--color-text-faint)' }}>
            <X size={10} />
          </button>
        </form>
      </div>
      {saveError && <p className="text-[10px] text-red-400 text-right">{saveError}</p>}
    </div>
  )
}

function MdnsRow({ mac, scan, onRefreshed }) {
  const [refreshing, setRefreshing] = useState(false)
  const services = scan?.mdns_services || []

  async function handleRefresh() {
    setRefreshing(true)
    try {
      const result = await api.refreshMdns(mac)
      onRefreshed(result.mdns_services || [])
    } catch {}
    finally { setRefreshing(false) }
  }

  return (
    <div className="flex items-start justify-between py-1.5 gap-4 border-b border-border last:border-0">
      <span className="text-xs text-text-muted shrink-0 mt-0.5">mDNS services</span>
      <div className="flex flex-col items-end gap-1">
        {services.length > 0 ? (
          <div className="flex flex-wrap gap-1 justify-end">
            {services.map(s => (
              <span key={s} className="text-[10px] px-1.5 py-0.5 rounded font-mono"
                style={{ background: 'var(--color-surface-offset)', color: 'var(--color-text-muted)', border: '1px solid var(--color-border)' }}>
                {s}
              </span>
            ))}
          </div>
        ) : (
          <span className="text-xs text-text-faint italic">None discovered</span>
        )}
        <button onClick={handleRefresh} disabled={refreshing}
          className="flex items-center gap-1 text-[10px] opacity-60 hover:opacity-100 transition-opacity"
          style={{ color: 'var(--color-brand)' }}>
          <Radio size={9} className={refreshing ? 'animate-pulse' : ''} />
          {refreshing ? 'Scanning…' : 'Refresh mDNS'}
        </button>
      </div>
    </div>
  )
}

function PortBaselineSection({ device, onReset }) {
  const baseline = device.baseline_ports || []
  const current  = (device.scan_results?.open_ports || []).map(p => p.port)
  const newPorts    = current.filter(p => !baseline.includes(p))
  const closedPorts = baseline.filter(p => !current.includes(p))
  const hasDrift    = newPorts.length > 0 || closedPorts.length > 0

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs text-text-muted">
          Confirmed baseline · {baseline.length} port{baseline.length !== 1 ? 's' : ''}
        </span>
        <button onClick={onReset}
          className="flex items-center gap-1 text-[10px] opacity-60 hover:opacity-100 transition-opacity"
          style={{ color: 'var(--color-text-muted)' }}>
          <RotateCcw size={9} />
          Reset
        </button>
      </div>
      {baseline.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {baseline.map(p => {
            const isNew    = newPorts.includes(p)
            const isClosed = closedPorts.includes(p)
            return (
              <span key={p} className="font-mono text-[10px] px-1.5 py-0.5 rounded"
                style={isClosed
                  ? { background: 'rgba(245,158,11,0.15)', color: '#f59e0b', border: '1px solid rgba(245,158,11,0.3)' }
                  : { background: 'var(--color-surface-offset)', color: 'var(--color-text-muted)', border: '1px solid var(--color-border)' }}>
                {p}
              </span>
            )
          })}
          {newPorts.map(p => (
            <span key={`new-${p}`} className="font-mono text-[10px] px-1.5 py-0.5 rounded"
              style={{ background: 'rgba(239,68,68,0.15)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.3)' }}>
              +{p}
            </span>
          ))}
        </div>
      )}
      {hasDrift && (
        <div className="flex flex-wrap gap-2 text-[11px]">
          {newPorts.length > 0 && (
            <span className="flex items-center gap-1" style={{ color: '#ef4444' }}>
              <TrendingUp size={10} />
              {newPorts.length} new port{newPorts.length !== 1 ? 's' : ''}: {newPorts.join(', ')}
            </span>
          )}
          {closedPorts.length > 0 && (
            <span className="flex items-center gap-1" style={{ color: '#f59e0b' }}>
              <TrendingDown size={10} />
              {closedPorts.length} closed: {closedPorts.join(', ')}
            </span>
          )}
        </div>
      )}
      {!hasDrift && baseline.length > 0 && (
        <p className="text-[11px]" style={{ color: 'var(--color-text-faint)' }}>No drift from baseline</p>
      )}
    </div>
  )
}

const SUPPRESSION_EVENT_TYPES = [
  { value: '', label: 'All events (global suppress)' },
  { value: 'joined',      label: 'New device joined' },
  { value: 'offline',     label: 'Device offline' },
  { value: 'online',      label: 'Device online' },
  { value: 'port_change', label: 'Port change' },
  { value: 'vuln_scan_complete', label: 'Vuln scan complete' },
]

function SuppressionManager({ mac }) {
  const [suppressions, setSuppressions] = useState(null)
  const [adding,       setAdding]       = useState(false)
  const [newType,      setNewType]      = useState('')
  const [newReason,    setNewReason]    = useState('')
  const [newExpiry,    setNewExpiry]    = useState('')
  const [saving,       setSaving]       = useState(false)

  async function load() {
    try {
      const list = await api.getSuppressions(mac)
      setSuppressions(list)
    } catch { setSuppressions([]) }
  }

  useEffect(() => { load() }, [mac])

  async function handleAdd(e) {
    e.preventDefault()
    setSaving(true)
    try {
      await api.createSuppression({
        mac_address: mac,
        event_type:  newType || null,
        reason:      newReason || null,
        expires_at:  newExpiry || null,
      })
      setAdding(false); setNewType(''); setNewReason(''); setNewExpiry('')
      await load()
    } catch {}
    finally { setSaving(false) }
  }

  async function handleDelete(id) {
    await api.deleteSuppression(id)
    await load()
  }

  if (suppressions === null) return <p className="text-xs text-text-faint">Loading…</p>

  return (
    <div className="space-y-2 pt-1">
      {suppressions.length === 0 ? (
        <p className="text-xs italic" style={{ color: 'var(--color-text-faint)' }}>No active suppressions.</p>
      ) : (
        <div className="space-y-1">
          {suppressions.map(s => (
            <div key={s.id} className="flex items-center justify-between gap-2 px-2 py-1.5 rounded-lg"
              style={{ background: 'var(--color-surface-offset)', border: '1px solid var(--color-border)' }}>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium" style={{ color: 'var(--color-text)' }}>
                  {s.event_type ? SUPPRESSION_EVENT_TYPES.find(t => t.value === s.event_type)?.label || s.event_type : 'All events'}
                </p>
                {s.reason && <p className="text-[10px] truncate" style={{ color: 'var(--color-text-faint)' }}>{s.reason}</p>}
                {s.expires_at && <p className="text-[10px]" style={{ color: 'var(--color-text-faint)' }}>Expires: {new Date(s.expires_at).toLocaleDateString()}</p>}
              </div>
              <button onClick={() => handleDelete(s.id)}
                className="opacity-40 hover:opacity-100 transition-opacity shrink-0"
                style={{ color: '#ef4444' }} aria-label="Delete suppression">
                <Trash2 size={12} />
              </button>
            </div>
          ))}
        </div>
      )}

      {!adding ? (
        <button onClick={() => setAdding(true)}
          className="flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-lg border w-full justify-center transition-colors"
          style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}>
          <Plus size={11} />Add suppression
        </button>
      ) : (
        <form onSubmit={handleAdd} className="space-y-2 p-2 rounded-lg"
          style={{ background: 'var(--color-surface-offset)', border: '1px solid var(--color-border)' }}>
          <div>
            <label className="block text-[10px] text-text-faint mb-1">Event type</label>
            <select value={newType} onChange={e => setNewType(e.target.value)}
              className="input w-full text-xs py-1">
              {SUPPRESSION_EVENT_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-[10px] text-text-faint mb-1">Reason (optional)</label>
            <input value={newReason} onChange={e => setNewReason(e.target.value)}
              className="input w-full text-xs py-1" placeholder="Reason…" />
          </div>
          <div>
            <label className="block text-[10px] text-text-faint mb-1">Expires (optional)</label>
            <input type="datetime-local" value={newExpiry} onChange={e => setNewExpiry(e.target.value)}
              className="input w-full text-xs py-1" />
          </div>
          <div className="flex gap-2">
            <button type="submit" disabled={saving}
              className="btn-primary text-xs py-1 flex-1">{saving ? 'Adding…' : 'Add'}</button>
            <button type="button" onClick={() => setAdding(false)}
              className="btn-ghost text-xs py-1">Cancel</button>
          </div>
        </form>
      )}
    </div>
  )
}
