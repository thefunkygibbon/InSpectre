import { useState, useEffect, useRef } from 'react'
import {
  X, Wifi, WifiOff, Cpu, Globe, Clock, Terminal,
  ShieldCheck, ScanLine, RefreshCw, ExternalLink,
  Activity, GitBranch, Bug, RotateCcw, Ban, History,
  ChevronDown, ChevronRight,
} from 'lucide-react'
import { OnlineDot } from './OnlineDot'
import { api } from '../api'

const BASE = import.meta.env.VITE_API_URL || '/api'

function fmt(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}
function fmtDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
}

const HTTP_PORTS  = new Set([80, 8080, 8000, 3000, 5000, 8888, 8008, 8081, 8082, 8090, 9000, 9090, 1880])
const HTTPS_PORTS = new Set([443, 8443, 4443, 9443])
function isWebPort(port)   { return HTTP_PORTS.has(port) || HTTPS_PORTS.has(port) }
function portUrl(ip, port) { return `${HTTPS_PORTS.has(port) ? 'https' : 'http'}://${ip}:${port}` }

// ── SSE hook ────────────────────────────────────────────────────────────────
/**
 * useSSEStream — opens an EventSource to `url` when `active` is true.
 * Appends each `data:` line to `lines`. Closes cleanly on `done` event or unmount.
 * Returns { lines, running, start, stop }.
 */
function useSSEStream() {
  const [lines,   setLines]   = useState([])
  const [running, setRunning] = useState(false)
  const esRef = useRef(null)

  function stop() {
    if (esRef.current) {
      esRef.current.close()
      esRef.current = null
    }
    setRunning(false)
  }

  function start(url) {
    stop()                         // close any previous stream
    setLines([])
    setRunning(true)

    const es = new EventSource(url)
    esRef.current = es

    es.onmessage = (e) => {
      if (e.data) setLines(prev => [...prev, e.data])
    }

    // `done` event signals the process has exited
    es.addEventListener('done', () => {
      es.close()
      esRef.current = null
      setRunning(false)
    })

    es.onerror = () => {
      setLines(prev => [...prev, '--- connection closed ---'])
      es.close()
      esRef.current = null
      setRunning(false)
    }
  }

  // Clean up on unmount
  useEffect(() => () => stop(), [])

  return { lines, running, start, stop }
}

// ── Terminal output box ──────────────────────────────────────────────────────
function TerminalBox({ lines, running, onStop }) {
  const bottomRef = useRef(null)
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [lines])

  if (!lines.length && !running) return null
  return (
    <div className="mt-3 rounded-lg bg-[#0d1117] border border-[#30363d] p-3 font-mono text-xs
                    text-green-400 max-h-64 overflow-y-auto leading-relaxed relative">
      {running && (
        <button
          onClick={onStop}
          className="absolute top-2 right-2 text-[#30363d] hover:text-red-400 transition-colors"
          title="Stop"
        >
          <X size={12} />
        </button>
      )}
      {lines.map((l, i) => <div key={i} className="whitespace-pre-wrap break-all">{l}</div>)}
      {running  && <div className="inline-block animate-pulse">▌</div>}
      {!running && lines.length > 0 && <div className="text-green-600 mt-1">─── done ───</div>}
      <div ref={bottomRef} />
    </div>
  )
}

// ── Collapsible wrapper ──────────────────────────────────────────────────────
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

// ── IP History section ───────────────────────────────────────────────────────
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

// ── Main component ───────────────────────────────────────────────────────────
export function DeviceDrawer({ device, onClose, onRename, onResolveName, onRefresh }) {
  if (!device) return null

  const [resolving,  setResolving]  = useState(false)
  const [rescanning, setRescanning] = useState(false)
  const [activeAction, setActiveAction] = useState(null)

  // One SSE stream shared across all streaming actions
  const stream = useSSEStream()

  const name = device.custom_name || device.hostname || device.ip_address
  const scan = device.scan_results
  const mac  = device.mac_address

  async function handleResolve() {
    setResolving(true)
    await onResolveName(mac)
    setResolving(false)
  }

  async function handleRescan() {
    setRescanning(true)
    setActiveAction('rescan')
    stream.stop()
    try {
      await api.rescanDevice(mac)
      // Show feedback in terminal box by using fake lines
      // (no SSE for this action — it's just a DB flag flip)
    } catch (e) {
      console.error(e)
    } finally {
      setRescanning(false)
      if (onRefresh) onRefresh()
    }
  }

  function handlePing() {
    setActiveAction('ping')
    stream.start(`${BASE}/devices/${mac}/ping`)
  }

  function handleTraceroute() {
    setActiveAction('traceroute')
    stream.start(`${BASE}/devices/${mac}/traceroute`)
  }

  function handlePlaceholder(label, note) {
    setActiveAction(label)
    // use the stream lines state to show the note
    stream.stop()
    // manually push a line by calling start on a fake URL that errors immediately
    // instead, just show in a one-shot way:
    // We'll repurpose the terminal box with a static note
    _setStaticLines([`[${label.toUpperCase()}] ${note}`])
  }

  // For non-SSE actions that still want the terminal box
  const [staticLines, _setStaticLines] = useState([])
  const termLines  = stream.lines.length ? stream.lines : staticLines
  const termRunning = stream.running

  return (
    <>
      <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40" onClick={onClose} />
      <aside className="fixed right-0 top-0 h-full w-full max-w-md bg-surface border-l border-border
                        z-50 flex flex-col shadow-2xl animate-slide-in overflow-hidden">

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-5 border-b border-border">
          <div className="flex items-center gap-3">
            <OnlineDot online={device.is_online} />
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
            {device.is_online
              ? <span className="badge-online"><Wifi size={11} />Online</span>
              : <span className="badge-offline"><WifiOff size={11} />Offline</span>}
            {device.deep_scanned
              ? <span className="badge-online"><ShieldCheck size={11} />Scanned</span>
              : <span className="badge-scanning"><ScanLine size={11} className="animate-pulse" />Scan pending</span>}
          </div>

          {/* Network */}
          <Section title="Network" icon={Globe}>
            <Row label="IP Address"  value={device.ip_address} mono />
            <Row label="MAC Address" value={mac} mono />
            <Row label="Vendor"      value={device.vendor || 'Unknown'} />
            <Row
              label="Hostname"
              value={
                <span className="flex items-center gap-2">
                  <span className="truncate">{device.hostname || '—'}</span>
                  <button onClick={handleResolve} disabled={resolving}
                    className="shrink-0 text-brand hover:text-brand-light transition-colors"
                    title="Re-resolve hostname" aria-label="Re-resolve hostname">
                    <RefreshCw size={12} className={resolving ? 'animate-spin' : ''} />
                  </button>
                </span>
              }
            />
            {device.custom_name && <Row label="Custom name" value={device.custom_name} />}
            {device.miss_count  !== undefined && <Row label="Miss count" value={device.miss_count} />}
          </Section>

          {/* IP History */}
          <Collapsible title="IP History" icon={History} defaultOpen={false}>
            <IpHistorySection mac={mac} />
          </Collapsible>

          {/* Timeline */}
          <Section title="Timeline" icon={Clock}>
            <Row label="First seen" value={fmt(device.first_seen)} />
            <Row label="Last seen"  value={fmt(device.last_seen)} />
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
                const url = web ? portUrl(device.ip_address, p.port) : null
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

          {/* Actions */}
          <Section title="Actions" icon={Activity}>
            <div className="grid grid-cols-2 gap-2 pt-1">
              <ActionBtn icon={Activity}  label="Ping"
                active={activeAction === 'ping' && stream.running}
                loading={activeAction === 'ping' && stream.running}
                onClick={handlePing} />
              <ActionBtn icon={GitBranch} label="Traceroute"
                active={activeAction === 'traceroute' && stream.running}
                loading={activeAction === 'traceroute' && stream.running}
                onClick={handleTraceroute} />
              <ActionBtn icon={RotateCcw} label="Re-scan ports"
                active={activeAction === 'rescan'}
                loading={rescanning}
                onClick={handleRescan} />
              <ActionBtn icon={Bug}       label="Vuln scan"
                active={activeAction === 'vuln'}
                onClick={() => handlePlaceholder('vuln', 'Vulnerability scan — coming in Phase 3.')} />
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

          {/* Rename */}
          <Section title="Rename Device" icon={null}>
            <RenameForm device={device} onRename={onRename} />
          </Section>

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
        {value ?? '—'}
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
