import { useState, useEffect, useRef } from 'react'
import {
  X, Wifi, WifiOff, Cpu, Globe, Clock, Terminal,
  ShieldCheck, ScanLine, RefreshCw, ExternalLink,
  Activity, GitBranch, Bug, RotateCcw, Ban, History,
  ChevronDown, ChevronRight, Square, Tag, CheckCircle2,
} from 'lucide-react'
import { OnlineDot } from './OnlineDot'
import { api } from '../api'
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

// -- Terminal output box -------------------------------------------------------
function TerminalBox({ lines, running, onStop }) {
  const containerRef = useRef(null)

  useEffect(() => {
    const el = containerRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [lines])

  if (!lines.length && !running) return null
  return (
    <div
      ref={containerRef}
      className="mt-3 rounded-lg bg-[#0d1117] border border-[#30363d] p-3 font-mono
                 text-green-400 max-h-56 overflow-y-auto relative"
      style={{ fontSize: '11px', lineHeight: '1.5' }}
    >
      {running && (
        <button
          onClick={onStop}
          className="absolute top-2 right-2 text-[#30363d] hover:text-red-400 transition-colors"
          title="Stop"
        >
          <X size={12} />
        </button>
      )}
      {lines.map((l, i) => (
        <div key={i} className="whitespace-pre overflow-x-auto">{l}</div>
      ))}
      {running  && <div className="inline-block animate-pulse">&#9608;</div>}
      {!running && lines.length > 0 && <div className="text-green-600 mt-1">--- done ---</div>}
    </div>
  )
}

// -- Collapsible wrapper -------------------------------------------------------
function Collapsible({ title, icon: Icon, defaultOpen = false, children }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div>
      <button onClick={() => setOpen(o => !o)} className="w-full flex items-center gap-2 mb-2 group">
        {Icon && <Icon size={14} className="text-brand" />}
        <span className="text-xs font-semibold text-text-muted uppercase tracking-wider flex-1 text-left">{title}</span>
        {open ? <ChevronDown size={13} className="text-text-faint shrink-0" />
              : <ChevronRight size={13} className="text-text-faint shrink-0" />}
      </button>
      {open && <div className="card p-4 space-y-0.5">{children}</div>}
    </div>
  )
}

// -- IP History section -------------------------------------------------------
function IpHistorySection({ mac }) {
  const [history, setHistory] = useState(null)
  const [error,   setError]   = useState(null)
  const [loaded,  setLoaded]  = useState(false)

  useEffect(() => {
    if (loaded) return
    setLoaded(true)
    api.getIpHistory(mac)
      .then(setHistory)
      .catch(e => { setError(e.message); setHistory([]) })
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

// -- Identity Edit Form --------------------------------------------------------
// Allows the user to manually confirm or correct the vendor name and device
// type. Saved values are persisted to the DB AND recorded as a FingerprintEntry
// so they contribute to the local fingerprint training database.
function IdentityForm({ device, onSaved }) {
  const [vendor,     setVendor]     = useState(device.vendor_override || device.vendor || '')
  const [typeKey,    setTypeKey]    = useState(device.device_type_override || '')
  const [saving,     setSaving]     = useState(false)
  const [saved,      setSaved]      = useState(false)
  const [error,      setError]      = useState(null)

  // Detect category for the currently auto-detected type to show as placeholder
  const autoType = device.device_type_override ? null : null // will be 'Unknown' if not overridden

  async function handleSave(e) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    setSaved(false)
    try {
      const updated = await api.updateIdentity(device.mac_address, {
        vendor_override:      vendor.trim()  || null,
        device_type_override: typeKey         || null,
      })
      setSaved(true)
      setTimeout(() => setSaved(false), 2500)
      if (onSaved) onSaved(updated)
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  function handleClear(e) {
    e.preventDefault()
    setVendor('')
    setTypeKey('')
  }

  return (
    <form onSubmit={handleSave} className="space-y-3">

      {/* Vendor */}
      <div>
        <label className="block text-xs text-text-muted mb-1">Vendor</label>
        <input
          className="input w-full"
          value={vendor}
          onChange={e => setVendor(e.target.value)}
          placeholder={device.vendor || 'e.g. Samsung, Ubiquiti, Hikvision…'}
        />
      </div>

      {/* Device type */}
      <div>
        <label className="block text-xs text-text-muted mb-1">Device Type</label>
        <div className="relative">
          <select
            className="input w-full appearance-none pr-8"
            value={typeKey}
            onChange={e => setTypeKey(e.target.value)}
          >
            {OVERRIDE_OPTIONS.map(opt => (
              <option key={opt.value} value={opt.value}>
                {opt.value && CATEGORIES[opt.value]
                  ? `${CATEGORIES[opt.value].label} — ${opt.label}`
                  : opt.label}
              </option>
            ))}
          </select>
          <ChevronDown size={13} className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 text-text-faint" />
        </div>
      </div>

      {/* Fingerprint notice */}
      <p className="text-[11px] text-text-faint leading-relaxed">
        Saving a device type also records a fingerprint entry in your local
        database. In a future release you will be able to anonymously share
        these corrections to help improve classification for all InSpectre users.
      </p>

      {error && <p className="text-xs text-red-400">{error}</p>}

      <div className="flex gap-2">
        <button type="submit" disabled={saving} className="btn-primary flex items-center gap-1.5 shrink-0">
          {saved
            ? <><CheckCircle2 size={13} /> Saved!</>
            : saving ? 'Saving…' : 'Save Identity'
          }
        </button>
        <button
          type="button"
          onClick={handleClear}
          className="btn-ghost text-xs text-text-faint hover:text-text"
          title="Clear overrides — revert to auto-detection"
        >
          Reset to auto
        </button>
      </div>
    </form>
  )
}

// -- Main component -----------------------------------------------------------
export function DeviceDrawer({ device, onClose, onRename, onResolveName, onRefresh }) {
  if (!device) return null

  const [localDevice,  setLocalDevice]  = useState(device)
  const [resolving,    setResolving]    = useState(false)
  const [rescanning,   setRescanning]   = useState(false)
  const [activeAction, setActiveAction] = useState(null)
  const [staticLines,  setStaticLines]  = useState([])

  // Keep localDevice in sync if the parent re-renders with new data
  useEffect(() => { setLocalDevice(device) }, [device])

  const stream = useStreamAction()

  const name = localDevice.custom_name || localDevice.hostname || localDevice.ip_address
  const scan = localDevice.scan_results
  const mac  = localDevice.mac_address

  async function handleResolve() {
    setResolving(true)
    await onResolveName(mac)
    setResolving(false)
  }

  async function handleRescan() {
    setRescanning(true)
    setActiveAction('rescan')
    stream.stop()
    setStaticLines([])
    try {
      await api.rescanDevice(mac)
      setStaticLines(['[RESCAN] Deep scan queued -- results will update shortly.'])
    } catch (e) {
      setStaticLines([`[RESCAN] Error: ${e.message}`])
    } finally {
      setRescanning(false)
      if (onRefresh) onRefresh()
    }
  }

  function handlePing() {
    if (activeAction === 'ping' && stream.running) {
      stream.stop()
      return
    }
    setActiveAction('ping')
    setStaticLines([])
    stream.start(`/devices/${mac}/ping`)
  }

  function handleTraceroute() {
    if (activeAction === 'traceroute' && stream.running) {
      stream.stop()
      return
    }
    setActiveAction('traceroute')
    setStaticLines([])
    stream.start(`/devices/${mac}/traceroute`)
  }

  function handlePlaceholder(label, note) {
    setActiveAction(label)
    stream.stop()
    setStaticLines([`[${label.toUpperCase()}] ${note}`])
  }

  const termLines   = stream.lines.length ? stream.lines : staticLines
  const termRunning = stream.running

  const pingRunning  = activeAction === 'ping'       && stream.running
  const traceRunning = activeAction === 'traceroute' && stream.running

  return (
    <>
      <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40" onClick={onClose} />
      <aside className="fixed right-0 top-0 h-full w-full max-w-md bg-surface border-l border-border
                        z-50 flex flex-col shadow-2xl animate-slide-in overflow-hidden">

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-5 border-b border-border">
          <div className="flex items-center gap-3">
            <OnlineDot online={localDevice.is_online} />
            <div>
              <h2 className="font-semibold text-text">{name}</h2>
              <p className="text-xs text-text-muted font-mono">{mac}</p>
            </div>
          </div>
          <button onClick={onClose} className="btn-ghost p-2" aria-label="Close"><X size={18} /></button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">

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
          </div>

          {/* ACTIONS */}
          <Section title="Actions" icon={Activity}>
            <div className="grid grid-cols-2 gap-2 pt-1">

              {/* Ping — toggles to Stop while running */}
              {pingRunning ? (
                <StopBtn label="Stop Ping" onClick={handlePing} />
              ) : (
                <ActionBtn icon={Activity} label="Ping"
                  active={activeAction === 'ping'}
                  onClick={handlePing} />
              )}

              {/* Traceroute — toggles to Stop while running */}
              {traceRunning ? (
                <StopBtn label="Stop Trace" onClick={handleTraceroute} />
              ) : (
                <ActionBtn icon={GitBranch} label="Traceroute"
                  active={activeAction === 'traceroute'}
                  onClick={handleTraceroute} />
              )}

              <ActionBtn icon={RotateCcw} label="Re-scan ports"
                active={activeAction === 'rescan'}
                loading={rescanning}
                onClick={handleRescan} />
              <ActionBtn icon={Bug}       label="Vuln scan"
                active={activeAction === 'vuln'}
                onClick={() => handlePlaceholder('vuln', 'Vulnerability scan -- coming in Phase 3.')} />
            </div>

            <button disabled
              className="mt-2 w-full flex items-center justify-center gap-2 py-2 rounded-lg
                         border border-dashed border-border text-xs text-text-faint
                         cursor-not-allowed opacity-60">
              <Ban size={12} />
              Block internet access
              <span className="ml-auto text-[10px] bg-surface-offset px-1.5 py-0.5 rounded">Phase 4</span>
            </button>

            <TerminalBox
              lines={termLines}
              running={termRunning}
              onStop={stream.stop}
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
            {localDevice.miss_count  !== undefined && <Row label="Miss count" value={localDevice.miss_count} />}
          </Section>

          {/* IP History */}
          <Collapsible title="IP History" icon={History} defaultOpen={false}>
            <IpHistorySection mac={mac} />
          </Collapsible>

          {/* Timeline */}
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
                                   underline-offset-2 w-16 shrink-0 flex items-center gap-1 group"
                        title={`Open ${url}`}>
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

          {/* Identity — vendor + device type editing */}
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

        </div>
      </aside>
    </>
  )
}

// Regular action button
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

// Stop button — shown in place of Ping/Traceroute while streaming
function StopBtn({ label, onClick }) {
  return (
    <button
      onClick={onClick}
      className="flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium
                 transition-colors duration-150
                 border-red-500/40 bg-red-500/10 text-red-400
                 hover:bg-red-500/20 hover:border-red-500/60"
    >
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
        placeholder={device.hostname || device.ip_address || 'Custom name...'} />
      <button type="submit" disabled={saving} className="btn-primary shrink-0">
        {saving ? '...' : 'Save'}
      </button>
    </form>
  )
}
