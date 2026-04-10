import {
  Wifi, Laptop, Smartphone, Server, Printer, Tv,
  HelpCircle, Camera, Gamepad2, Cpu, Router,
  MonitorSpeaker, Tablet, Radio, Network, Shield, Monitor
} from 'lucide-react'
import { OnlineDot } from './OnlineDot'
import { classifyDevice, getDeviceCategory } from '../deviceCategories'

function relativeTime(iso) {
  if (!iso) return ''
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1)  return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24)  return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

/** Map category type key → Lucide icon component */
const TYPE_ICON_MAP = {
  router:   Router,
  switch:   Network,
  ap:       Wifi,
  server:   Server,
  nas:      Server,
  desktop:  Monitor,
  laptop:   Laptop,
  phone:    Smartphone,
  tablet:   Tablet,
  tv:       Tv,
  streamer: MonitorSpeaker,
  console:  Gamepad2,
  camera:   Camera,
  printer:  Printer,
  iot:      Cpu,
  voip:     Radio,
  unknown:  HelpCircle,
}

function getDeviceIcon(device) {
  const type = classifyDevice(device)
  return TYPE_ICON_MAP[type] || HelpCircle
}

/**
 * Clean up vendor name — strip trailing noise so it reads nicely as a subtitle.
 * e.g. "Reolink Security Technologies Co., Ltd." → "Reolink"
 */
function cleanVendor(vendor) {
  if (!vendor) return null
  return vendor
    .replace(/\s+(Inc\.?|LLC\.?|Ltd\.?|Co\.,?\s*Ltd\.?|Technologies|Technology|International|Electronics|Systems|Networks|Communications|Corp\.?|Group|Holdings)(\s+|$)/gi, '')
    .trim()
}

/**
 * Best display name with fallback chain:
 * 1. custom_name  2. hostname  3. cleaned vendor  4. "Device .{last_octet}"  5. MAC prefix
 */
function deviceDisplayName(device) {
  if (device.custom_name) return device.custom_name
  if (device.hostname)    return device.hostname
  const v = cleanVendor(device.vendor_override || device.vendor)
  if (v) return v
  if (device.ip_address) {
    const parts = device.ip_address.split('.')
    if (parts.length === 4) return `Device .${parts[3]}`
  }
  if (device.mac_address) return device.mac_address.slice(0, 8).toUpperCase()
  return 'Unknown'
}

function openPortCount(device) {
  const ports = device.scan_results?.open_ports
  if (Array.isArray(ports)) return ports.length
  return null
}

export function DeviceCard({ device, onClick }) {
  const name      = deviceDisplayName(device)
  const vendor    = cleanVendor(device.vendor_override || device.vendor)
  const DevIcon   = getDeviceIcon(device)
  const category  = getDeviceCategory(device)
  const ports     = openPortCount(device)
  const scanning  = !device.deep_scanned

  // Show vendor as subtitle only when it differs from the main name
  const showVendorSubtitle = vendor && vendor !== name

  return (
    <button
      onClick={onClick}
      className={`device-card${scanning ? ' device-card-scanning' : ''} p-5 text-left w-full flex flex-col gap-3 group`}
    >
      {/* ── Header: icon + name + vendor subtitle ── */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2.5 min-w-0">
          {/* Device type icon — colour driven by category */}
          <span
            className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 transition-colors duration-200"
            style={{ background: category.bgColor }}
          >
            <DevIcon size={15} style={{ color: category.color }} />
          </span>

          <div className="min-w-0">
            {/* 1 — Device name */}
            <div className="flex items-center gap-1.5">
              <OnlineDot online={device.is_online} size="sm" />
              <span className="font-semibold text-sm truncate" style={{ color: 'var(--color-text)' }}>
                {name}
              </span>
            </div>
            {/* 2 — Vendor subtitle */}
            {showVendorSubtitle && (
              <span className="text-[11px] truncate block" style={{ color: 'var(--color-text-muted)' }}>
                {vendor}
              </span>
            )}
          </div>
        </div>

        {scanning && (
          <span className="shrink-0 text-[10px] font-medium text-amber-400 bg-amber-400/10
                           border border-amber-400/20 rounded-full px-2 py-0.5 mt-0.5">
            Scanning
          </span>
        )}
      </div>

      {/* ── Details grid ── */}
      <div className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-xs">
        {/* 3 — IP */}
        <span style={{ color: 'var(--color-text-muted)' }}>IP</span>
        <span className="font-mono truncate" style={{ color: 'var(--color-text)' }}>
          {device.ip_address}
        </span>

        {/* 4 — MAC */}
        <span style={{ color: 'var(--color-text-muted)' }}>MAC</span>
        <span className="font-mono truncate text-[11px]" style={{ color: 'var(--color-text)' }}>
          {device.mac_address}
        </span>

        {/* 5 — Device type */}
        <span style={{ color: 'var(--color-text-muted)' }}>Type</span>
        <span className="truncate capitalize" style={{ color: 'var(--color-text)' }}>
          {category.label}
        </span>

        {/* 6 — Open ports (only once scanned) */}
        {ports !== null && (
          <>
            <span style={{ color: 'var(--color-text-muted)' }}>Ports</span>
            <span style={{ color: 'var(--color-text)' }}>{ports} open</span>
          </>
        )}
      </div>

      {/* ── Footer: last seen ── */}
      <div
        className="flex items-center justify-end pt-1 border-t"
        style={{ borderColor: 'var(--color-border)' }}
      >
        <span className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
          {relativeTime(device.last_seen)}
        </span>
      </div>
    </button>
  )
}
