import { useState, useEffect, useRef } from 'react'
import {
  X, Wifi, WifiOff, Cpu, Globe, Clock, Terminal,
  ShieldCheck, ScanLine, RefreshCw, ExternalLink,
  Activity, GitBranch, Bug, RotateCcw, Ban, History,
  ChevronDown, ChevronRight, Square, Tag, CheckCircle2,
  FileText, Star as StarIcon, ShieldAlert,
} from 'lucide-react'
import { OnlineDot }      from './OnlineDot'
import { StarButton }     from './StarButton'
import { DeviceNotes }    from './DeviceNotes'
import { DeviceTimeline } from './DeviceTimeline'
import { VulnPanel }      from './VulnPanel'
import { StreamOutput }   from './StreamOutput'
import { api }            from '../api'
import { useStreamAction } from '../hooks/useStreamAction'
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

const TABS = [
  { id: 'overview',  label: 'Overview' },
  { id: 'vulns',     label: 'Vulnerabilities' },
  { id: 'timeline',  label: 'Timeline' },
  { id: 'notes',     label: 'Notes & Tags' },
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

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------
export function DeviceDrawer({ device, onClose, onRename, onResolveName, onRefresh, onStarToggle, onMetadataUpdate }) {
  if (!device) return null

  const [localDevice,  setLocalDevice]  = useState(device)
  const [resolving,    setResolving]    = useState(false)
  const [rescanning,   setRescanning]   = useState(false)
  const [activeAction, setActiveAction] = useState(null)  // 'ping' | 'traceroute' | 'rescan'
  const [staticLines,  setStaticLines]  = useState([])
  const [activeTab,    setActiveTab]    = useState('overview')
  const [blocking,     setBlocking]     = useState(false)

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
    setRescanning(true); setActiveAction('rescan'); stream.stop(); setStaticLines([])
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
        <div className="flex border-b border-border px-6 gap-1" style={{ background: 'var(--color-surface)' }}>
          {TABS.map(tab => {
            const isVuln   = tab.id === 'vulns'
            const isActive = activeTab === tab.id
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className="px-3 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5"
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
              </div>

              {/* Actions */}
              <Section title="Actions" icon={Activity}>
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
                {/* Structured stream output */}
                <StreamOutput
                  lines={termLines}
                  running={termRunning}
                  onStop={stream.stop}
                  mode={streamMode}
                />
              </Section>

              {/* Network */}
              <Section title="Network" icon={Globe}>
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
                {localDevice.miss_count  !== undefined && <Row label="Miss count" value={localDevice.miss_count} />}
              </Section>

              {/* IP History */}
              <Collapsible title="IP History" icon={History} defaultOpen={false}>
                <IpHistorySection mac={mac} />
              </Collapsible>

              {/* Timeline summary */}
              <Section title="Timeline" icon={Clock}>
                <Row label="First seen" value={fmt(localDevice.first_seen)} />
                <Row label="Last seen"  value={fmt(localDevice.last_seen)} />
                {scan?.scanned_at && <Row label="Scanned at" value={fmt(scan.scanned_at)} />}
              </Section>

              {/* OS Detection */}
              {scan && (
                <Section title="OS Detection" icon={Cpu}>
                  {scan.os_matches?.length > 0 ? (
                    scan.os_matches.map((m, i) => (
                      <div key={i} className="flex items-center justify-between py-1.5 border-b border-border last:border-0">
                        <span className="text-sm text-text">{m.name}</span>
                        <span className="text-xs font-medium text-brand tabular-nums">{m.accuracy}%</span>
                      </div>
                    ))
                  ) : (
                    <p className="text-sm text-text-muted italic">No confident OS match found</p>
                  )}
                </Section>
              )}

              {/* Open Ports */}
              {scan?.open_ports?.length > 0 && (
                <Section title={`Open Ports (${scan.open_ports.length})`} icon={Terminal}>
                  {scan.open_ports.map((p, i) => {
                    const web = isWebPort(p.port)
                    const url = web ? portUrl(localDevice.ip_address, p.port) : null
                    return (
                      <div key={i} className="flex items-center gap-3 py-1.5 border-b border-border last:border-0">
                        {web ? (
                          <a href={url} target="_blank" rel="noopener noreferrer"
                            className="font-mono text-xs text-brand hover:text-brand-light underline
                                       underline-offset-2 w-16 shrink-0 flex items-center gap-1 group">
                            {p.port}/{p.proto}
                            <ExternalLink size={9} className="opacity-60 group-hover:opacity-100" />
                          </a>
                        ) : (
                          <span className="font-mono text-xs text-text-muted w-16 shrink-0">{p.port}/{p.proto}</span>
                        )}
                        <span className="text-sm text-text">{p.service}</span>
                        {p.product && (
                          <span className="text-xs text-text-muted ml-auto truncate">{p.product} {p.version}</span>
                        )}
                      </div>
                    )
                  })}
                </Section>
              )}

              {/* Identity */}
              <Section title="Device Identity" icon={Tag}>
                <IdentityForm
                  device={localDevice}
                  onSaved={updated => {
                    setLocalDevice(updated)
                    if (onRefresh) onRefresh()
                  }}
                />
              </Section>

              {/* Rename */}
              <Section title="Rename Device" icon={null}>
                <RenameForm device={localDevice} onRename={onRename} />
              </Section>
            </>
          )}

          {activeTab === 'vulns' && (
            <VulnPanel
              device={localDevice}
              onScanComplete={() => {
                api.getDevice(mac).then(updated => {
                  setLocalDevice(updated)
                  if (onRefresh) onRefresh()
                }).catch(() => {})
              }}
            />
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

          {activeTab === 'notes' && (
            <>
              <div className="flex items-center gap-2 mb-4">
                <FileText size={14} className="text-brand" />
                <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider">Notes, Tags & Location</h3>
              </div>
              <DeviceNotes
                device={localDevice}
                onSaved={updated => {
                  setLocalDevice(prev => ({ ...prev, ...updated }))
                  if (onMetadataUpdate) onMetadataUpdate(mac, updated)
                }}
              />
            </>
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
