import { X, Wifi, WifiOff, Cpu, Globe, Clock, Terminal, ShieldCheck, ScanLine } from 'lucide-react'
import { OnlineDot } from './OnlineDot'

function fmt(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

export function DeviceDrawer({ device, onClose, onRename }) {
  if (!device) return null
  const name = device.custom_name || device.hostname || device.ip_address
  const scan = device.scan_results

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 animate-fade-in"
        onClick={onClose}
      />
      {/* Drawer */}
      <aside className="fixed right-0 top-0 h-full w-full max-w-md bg-gray-900 border-l border-white/8
                        z-50 flex flex-col shadow-2xl animate-slide-in overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-5 border-b border-white/8">
          <div className="flex items-center gap-3">
            <OnlineDot online={device.is_online} />
            <div>
              <h2 className="font-semibold text-gray-100">{name}</h2>
              <p className="text-xs text-gray-500 font-mono">{device.mac_address}</p>
            </div>
          </div>
          <button onClick={onClose} className="btn-ghost p-2" aria-label="Close">
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">

          {/* Status badge */}
          <div className="flex gap-2 flex-wrap">
            {device.is_online
              ? <span className="badge-online"><Wifi size={11}/>Online</span>
              : <span className="badge-offline"><WifiOff size={11}/>Offline</span>}
            {device.deep_scanned
              ? <span className="badge-online"><ShieldCheck size={11}/>Scanned</span>
              : <span className="badge-scanning"><ScanLine size={11} className="animate-pulse"/>Scan pending</span>}
          </div>

          {/* Network info */}
          <Section title="Network" icon={Globe}>
            <Row label="IP Address"  value={device.ip_address} mono />
            <Row label="MAC Address" value={device.mac_address} mono />
            <Row label="Vendor"      value={device.vendor || 'Unknown'} />
            <Row label="Hostname"    value={device.hostname || '—'} />
            {device.custom_name && <Row label="Custom name" value={device.custom_name} />}
            <Row label="Miss count"  value={device.miss_count} />
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
                  <div key={i} className="flex items-center justify-between py-1">
                    <span className="text-sm text-gray-300">{m.name}</span>
                    <span className="text-xs font-medium text-brand-400 tabular-nums">{m.accuracy}%</span>
                  </div>
                ))
              ) : (
                <p className="text-sm text-gray-500 italic">No confident OS match found</p>
              )}
            </Section>
          )}

          {/* Open ports */}
          {scan?.open_ports?.length > 0 && (
            <Section title="Open Ports" icon={Terminal}>
              <div className="space-y-1">
                {scan.open_ports.map((p, i) => (
                  <div key={i} className="flex items-center gap-3 py-1.5 border-b border-white/5 last:border-0">
                    <span className="font-mono text-sm text-brand-400 w-16 shrink-0">{p.port}/{p.proto}</span>
                    <span className="text-sm text-gray-300">{p.service}</span>
                    {p.product && <span className="text-xs text-gray-500 ml-auto truncate">{p.product} {p.version}</span>}
                  </div>
                ))}
              </div>
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
        {Icon && <Icon size={14} className="text-brand-500" />}
        <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">{title}</h3>
      </div>
      <div className="card p-4 space-y-1">{children}</div>
    </div>
  )
}

function Row({ label, value, mono }) {
  return (
    <div className="flex items-center justify-between py-1 gap-4">
      <span className="text-xs text-gray-500 shrink-0">{label}</span>
      <span className={`text-sm text-gray-200 text-right truncate ${mono ? 'font-mono text-xs' : ''}`}>
        {value ?? '—'}
      </span>
    </div>
  )
}

function RenameForm({ device, onRename }) {
  const [val, setVal] = require('react').useState(device.custom_name || '')
  const [saving, setSaving] = require('react').useState(false)

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
        placeholder={device.hostname || device.ip_address}
      />
      <button type="submit" disabled={saving} className="btn-primary shrink-0">
        {saving ? '…' : 'Save'}
      </button>
    </form>
  )
}
