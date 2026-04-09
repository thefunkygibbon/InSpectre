import { useState } from 'react'
import { X, Wifi, WifiOff, Cpu, Globe, Clock, Terminal, ShieldCheck, ScanLine, RefreshCw } from 'lucide-react'
import { OnlineDot } from './OnlineDot'

function fmt(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

export function DeviceDrawer({ device, onClose, onRename, onResolveName }) {
  if (!device) return null
  const [resolving, setResolving] = useState(false)
  const name = device.custom_name || device.hostname || device.ip_address
  const scan = device.scan_results

  async function handleResolve() {
    setResolving(true)
    await onResolveName(device.mac_address)
    setResolving(false)
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

          {/* Open ports */}
          {scan?.open_ports?.length > 0 && (
            <Section title="Open Ports" icon={Terminal}>
              {scan.open_ports.map((p, i) => (
                <div key={i} className="flex items-center gap-3 py-1.5 border-b border-border last:border-0">
                  <span className="font-mono text-xs text-brand w-16 shrink-0">{p.port}/{p.proto}</span>
                  <span className="text-sm text-text">{p.service}</span>
                  {p.product && <span className="text-xs text-text-muted ml-auto truncate">{p.product} {p.version}</span>}
                </div>
              ))}
            </Section>
          )}

          {/* Rename */}
          <Section title="Rename Device" icon={null}>
            <RenameForm device={device} onRename={onRename} />
          </Section>

        </div>
      </aside>
    </>
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
