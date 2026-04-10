import { useState } from 'react'
import {
  X, Wifi, WifiOff, Cpu, Globe, Clock, Terminal,
  ShieldCheck, ScanLine, RefreshCw, ExternalLink,
  Activity, GitBranch, Bug, RotateCcw, Ban,
  ChevronDown, ChevronRight
} from 'lucide-react'
import { OnlineDot } from './OnlineDot'
import { api } from '../api'

function fmt(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

// Ports that a browser can meaningfully open
const HTTP_PORTS  = new Set([80, 8080, 8000, 3000, 5000, 8888, 8008, 8081, 8082, 8090, 9000, 9090, 1880])
const HTTPS_PORTS = new Set([443, 8443, 4443, 9443])

function isWebPort(port) {
  return HTTP_PORTS.has(port) || HTTPS_PORTS.has(port)
}

function portUrl(ip, port) {
  const scheme = HTTPS_PORTS.has(port) ? 'https' : 'http'
  return `${scheme}://${ip}:${port}`
}

// ── Terminal output box ────────────────────────────────────────────────────
function TerminalBox({ lines, running }) {
  if (!lines.length && !running) return null
  return (
    <div className="mt-3 rounded-lg bg-[#0d1117] border border-[#30363d] p-3 font-mono text-xs
                    text-green-400 max-h-52 overflow-y-auto leading-relaxed">
      {lines.map((l, i) => (
        <div key={i} className="whitespace-pre-wrap break-all">{l}</div>
      ))}
      {running && (
        <div className="inline-block animate-pulse">▌</div>
      )}
      {!running && lines.length > 0 && (
        <div className="text-green-600 mt-1">─── done ───</div>
      )}
    </div>
  )
}

// ── Main component ─────────────────────────────────────────────────────────
export function DeviceDrawer({ device, onClose, onRename, onResolveName, onRefresh }) {
  if (!device) return null

  const [resolving,    setResolving]    = useState(false)
  const [rescanning,   setRescanning]   = useState(false)
  const [actionLines,  setActionLines]  = useState([])
  const [actionRunning,setActionRunning]= useState(false)
  const [activeAction, setActiveAction] = useState(null)   // 'ping'|'traceroute'|'vuln'|null

  const name = device.custom_name || device.hostname || device.ip_address
  const scan = device.scan_results

  async function handleResolve() {
    setResolving(true)
    await onResolveName(device.mac_address)
    setResolving(false)
  }

  // Reset deep_scanned so probe picks it up on next sweep
  async function handleRescan() {
    setRescanning(true)
    setActiveAction('rescan')
    setActionLines(['Queuing re-scan — probe will run nmap on next sweep…'])
    setActionRunning(false)
    try {
      await api.rescanDevice(device.mac_address)
      setActionLines(prev => [...prev, 'deep_scanned flag cleared.', 'Nmap will start within the next scan interval.'])
      if (onRefresh) onRefresh()
    } catch (e) {
      setActionLines(prev => [...prev, `Error: ${e.message}`])
    } finally {
      setRescanning(false)
    }
  }

  function handlePlaceholderAction(label, note) {
    setActiveAction(label)
    setActionLines([`[${label.toUpperCase()}] ${note}`])
    setActionRunning(false)
  }

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
              <p className="text-xs text-text-muted font-mono">{device.mac_address}</p>
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

          {/* Network info */}
          <Section title="Network" icon={Globe}>
            <Row label="IP Address"  value={device.ip_address} mono />
            <Row label="MAC Address" value={device.mac_address} mono />
            <Row label="Vendor"      value={device.vendor || 'Unknown'} />
            <Row
              label="Hostname"
              value={
                <span className="flex items-center gap-2">
                  <span className="truncate">{device.hostname || '—'}</span>
                  <button
                    onClick={handleResolve}
                    disabled={resolving}
                    className="shrink-0 text-brand hover:text-brand-light transition-colors"
                    title="Re-resolve hostname"
                    aria-label="Re-resolve hostname"
                  >
                    <RefreshCw size={12} className={resolving ? 'animate-spin' : ''} />
                  </button>
                </span>
              }
            />
            {device.custom_name && <Row label="Custom name" value={device.custom_name} />}
            {device.miss_count !== undefined && <Row label="Miss count" value={device.miss_count} />}
          </Section>

          {/* Timestamps */}
          <Section title="Timeline" icon={Clock}>
            <Row label="First seen" value={fmt(device.first_seen)} />
            <Row label="Last seen"  value={fmt(device.last_seen)} />
            {scan?.scanned_at && <Row label="Scanned at" value={fmt(scan.scanned_at)} />}
          </Section>

          {/* OS detection */}
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

          {/* Open ports — with clickable HTTP/HTTPS links */}
          {scan?.open_ports?.length > 0 && (
            <Section title={`Open Ports (${scan.open_ports.length})`} icon={Terminal}>
              {scan.open_ports.map((p, i) => {
                const web = isWebPort(p.port)
                const url = web ? portUrl(device.ip_address, p.port) : null
                return (
                  <div key={i} className="flex items-center gap-3 py-1.5 border-b border-border last:border-0">
                    {/* Port number — teal link or plain label */}
                    {web ? (
                      <a
                        href={url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-mono text-xs text-brand hover:text-brand-light underline
                                   underline-offset-2 w-16 shrink-0 flex items-center gap-1 group"
                        title={`Open ${url}`}
                      >
                        {p.port}/{p.proto}
                        <ExternalLink size={9} className="opacity-60 group-hover:opacity-100" />
                      </a>
                    ) : (
                      <span className="font-mono text-xs text-text-muted w-16 shrink-0">{p.port}/{p.proto}</span>
                    )}
                    <span className="text-sm text-text">{p.service}</span>
                    {p.product && (
                      <span className="text-xs text-text-muted ml-auto truncate">
                        {p.product} {p.version}
                      </span>
                    )}
                  </div>
                )
              })}
            </Section>
          )}

          {/* ── Actions ─────────────────────────────────────────────────── */}
          <Section title="Actions" icon={Activity}>
            <div className="grid grid-cols-2 gap-2 pt-1">
              {/* Ping */}
              <ActionBtn
                icon={Activity}
                label="Ping"
                active={activeAction === 'ping'}
                onClick={() => handlePlaceholderAction(
                  'ping',
                  'Streaming ping ready — probe-side SSE endpoint coming in Phase 3.'
                )}
              />
              {/* Traceroute */}
              <ActionBtn
                icon={GitBranch}
                label="Traceroute"
                active={activeAction === 'traceroute'}
                onClick={() => handlePlaceholderAction(
                  'traceroute',
                  'Streaming traceroute ready — probe-side SSE endpoint coming in Phase 3.'
                )}
              />
              {/* Re-scan ports — live */}
              <ActionBtn
                icon={RotateCcw}
                label="Re-scan ports"
                active={activeAction === 'rescan'}
                loading={rescanning}
                onClick={handleRescan}
              />
              {/* Vuln scan */}
              <ActionBtn
                icon={Bug}
                label="Vuln scan"
                active={activeAction === 'vuln'}
                onClick={() => handlePlaceholderAction(
                  'vuln',
                  'Vulnerability scan ready — probe-side SSE endpoint coming in Phase 3.'
                )}
              />
            </div>

            {/* Block internet — Phase 4 */}
            <button
              disabled
              className="mt-2 w-full flex items-center justify-center gap-2 py-2 rounded-lg
                         border border-dashed border-border text-xs text-text-faint
                         cursor-not-allowed opacity-60"
            >
              <Ban size={12} />
              Block internet access
              <span className="ml-auto text-[10px] bg-surface-offset px-1.5 py-0.5 rounded">Phase 4</span>
            </button>

            {/* Terminal output */}
            <TerminalBox lines={actionLines} running={actionRunning} />
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

// ── Action button ──────────────────────────────────────────────────────────
function ActionBtn({ icon: Icon, label, onClick, active, loading }) {
  return (
    <button
      onClick={onClick}
      disabled={loading}
      className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium
                  transition-colors duration-150
                  ${ active
                    ? 'border-brand bg-brand/10 text-brand'
                    : 'border-border bg-surface-offset hover:bg-surface-dynamic text-text-muted hover:text-text'
                  }
                  ${ loading ? 'opacity-60 cursor-wait' : '' }`}
    >
      <Icon size={13} className={loading ? 'animate-spin' : ''} />
      {label}
    </button>
  )
}

// ── Section wrapper ────────────────────────────────────────────────────────
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

// ── Key-value row ──────────────────────────────────────────────────────────
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

// ── Rename form ────────────────────────────────────────────────────────────
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
      <input
        className="input"
        value={val}
        onChange={e => setVal(e.target.value)}
        placeholder={device.hostname || device.ip_address || 'Custom name…'}
      />
      <button type="submit" disabled={saving} className="btn-primary shrink-0">
        {saving ? '…' : 'Save'}
      </button>
    </form>
  )
}
