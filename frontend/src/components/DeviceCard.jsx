import {
  Wifi, Laptop, Smartphone, Server, Printer, Tv,
  HelpCircle, Camera, Gamepad2, Cpu, Router,
  MonitorSpeaker, Tablet, Radio, Network, Shield, Monitor, GitMerge, X
} from 'lucide-react'
import { OnlineDot } from './OnlineDot'
import { StarButton } from './StarButton'
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

function cleanVendor(vendor) {
  if (!vendor) return null
  return vendor
    .replace(/\s+(Inc\.?|LLC\.?|Ltd\.?|Co\.,?\s*Ltd\.?|Technologies|Technology|International|Electronics|Systems|Networks|Communications|Corp\.?|Group|Holdings)(\s+|$)/gi, '')
    .trim()
}

/**
 * Derive the best display name for a device.
 *
 * Priority order:
 *   1. custom_name  — explicitly set by the user
 *   2. hostname     — resolved from DNS / mDNS / NetBIOS
 *   3. IP address   — always available, unambiguous
 *   4. MAC prefix   — last resort if somehow IP is missing too
 *
 * NOTE: vendor is intentionally NOT used as a display name.
 * Vendor strings like "Samsung Electronics" or "Espressif Inc." make terrible
 * card titles when you have multiple devices from the same manufacturer.
 * The vendor is shown as a subtitle line instead (see showVendorSubtitle below).
 */
function deviceDisplayName(device) {
  if (device.custom_name) return device.custom_name
  if (device.hostname)    return device.hostname
  if (device.ip_address)  return device.ip_address
  if (device.mac_address) return device.mac_address.slice(0, 8).toUpperCase()
  return 'Unknown Device'
}

function openPortCount(device) {
  const ports = device.scan_results?.open_ports
  if (Array.isArray(ports)) return ports.length
  return null
}

function baselineDrift(device) {
  const baseline = device.baseline_ports
  if (!baseline || !Array.isArray(baseline)) return null
  const current = (device.scan_results?.open_ports || []).map(p => p.port)
  const newPorts    = current.filter(p => !baseline.includes(p))
  const closedPorts = baseline.filter(p => !current.includes(p))
  if (!newPorts.length && !closedPorts.length) return null
  return { newPorts, closedPorts }
}

const NEW_DEVICE_DAYS = 7

function isNewDevice(device) {
  if (!device.first_seen) return false
  return Date.now() - new Date(device.first_seen).getTime() < NEW_DEVICE_DAYS * 24 * 60 * 60 * 1000
}

export function DeviceCard({ device, onClick, onStarToggle, isVulnScanning, isAcknowledged, onAcknowledge }) {
  const name     = deviceDisplayName(device)
  const vendor   = cleanVendor(device.vendor_override || device.vendor || device.vendor_inferred)
  const DevIcon  = getDeviceIcon(device)
  const category = getDeviceCategory(device)
  const ports    = openPortCount(device)
  const scanning     = !device.deep_scanned && device.is_online
  const drift        = baselineDrift(device)
  const isNew        = isNewDevice(device)
  const showNew      = isNew && !isAcknowledged

// Show vendor only when it adds info the title doesn't already give
  const showVendorSubtitle = vendor && vendor !== name && !device.ip_address?.startsWith(name)

  return (
    <button
      onClick={onClick}
      className={`device-card${scanning ? ' device-card-scanning' : ''}${isVulnScanning && !scanning ? ' device-card-vuln-scanning' : ''}${device.is_important ? ' ring-1 ring-amber-400/30' : ''} p-5 text-left w-full flex flex-col gap-3 group relative`}
    >
      {/* Star button — top right corner */}
      {onStarToggle && (
        <div className="absolute top-3 right-3 z-10">
          <StarButton device={device} onToggle={onStarToggle} size={14} />
        </div>
      )}

      {/* Header */}
      <div className="flex items-start gap-2.5 pr-6">
        <span className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 transition-colors duration-200"
          style={{ background: category.bgColor }}>
          <DevIcon size={15} style={{ color: category.color }} />
        </span>

        {/* Name column — takes all remaining width */}
        <div className="relative min-w-0 flex-1 overflow-hidden">
          {/* Name line — overflow-hidden here is the critical clip point */}
          <div className="flex items-center gap-1.5 overflow-hidden">
            <OnlineDot online={device.is_online} size="sm" />
            <span
              className={`font-semibold text-sm truncate min-w-0 flex-1${showNew ? ' pr-14' : ''}`}
              style={{ color: 'var(--color-text)' }}
            >{name}</span>
          </div>

          {/* NEW badge — absolutely overlaid on the right of the name line */}
          {showNew && (
            <span
              className="absolute top-0 right-0 flex items-center gap-0.5 text-[10px] font-bold rounded-full px-2 py-0.5"
              style={{ color: '#10b981', background: 'rgba(16,185,129,0.18)', border: '1px solid rgba(16,185,129,0.4)' }}
            >
              NEW
              {onAcknowledge && (
                <button
                  onClick={e => { e.stopPropagation(); onAcknowledge(device.mac_address) }}
                  className="opacity-60 hover:opacity-100 transition-opacity ml-0.5"
                  title="Acknowledge — stop surfacing to top"
                  aria-label="Acknowledge new device"
                >
                  <X size={8} />
                </button>
              )}
            </span>
          )}

          {showVendorSubtitle && (
            <span className="text-[11px] truncate block mt-0.5" style={{ color: 'var(--color-text-muted)' }}>{vendor}</span>
          )}

          {/* Scanning / VulnScan — below the name, never compete for horizontal space */}
          {(scanning || isVulnScanning) && (
            <div className="flex items-center gap-1 mt-1 flex-wrap">
              {scanning && (
                <span className="text-[10px] font-medium text-amber-400 bg-amber-400/10 border border-amber-400/20 rounded-full px-2 py-0.5">
                  Scanning
                </span>
              )}
              {isVulnScanning && (
                <span className="text-[10px] font-medium rounded-full px-2 py-0.5"
                  style={{ color: 'var(--color-brand)', background: 'color-mix(in srgb, var(--color-brand) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--color-brand) 25%, transparent)' }}>
                  Vuln Scan
                </span>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Details grid */}
      <div className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-xs">
        <span style={{ color: 'var(--color-text-muted)' }}>IP</span>
        <span className="font-mono truncate" style={{ color: 'var(--color-text)' }}>{device.ip_address}</span>
        <span style={{ color: 'var(--color-text-muted)' }}>MAC</span>
        <span className="font-mono truncate text-[11px]" style={{ color: 'var(--color-text)' }}>{device.mac_address}</span>
        <span style={{ color: 'var(--color-text-muted)' }}>Type</span>
        <span className="truncate capitalize" style={{ color: 'var(--color-text)' }}>
          {category.label}
          {device.fingerbank_result?.device_name && (device.fingerbank_result.score || 0) >= 50 && (
            <span className="block text-[10px] truncate" style={{ color: 'var(--color-brand)', opacity: 0.85 }}>
              {device.fingerbank_result.device_name}
            </span>
          )}
        </span>
        {ports !== null && (
          <>
            <span style={{ color: 'var(--color-text-muted)' }}>Ports</span>
            <span style={{ color: 'var(--color-text)' }}>{ports} open</span>
          </>
        )}
        {device.location && (
          <>
            <span style={{ color: 'var(--color-text-muted)' }}>Location</span>
            <span className="truncate" style={{ color: 'var(--color-text)' }}>{device.location}</span>
          </>
        )}
        {device.group_members?.length > 1 && (
          <>
            <span className="flex items-center gap-1" style={{ color: 'var(--color-text-muted)' }}>
              <GitMerge size={10} />Interfaces
            </span>
            <span className="flex flex-col gap-0.5">
              {device.group_members.map(m => (
                <span key={m.mac_address} className="flex items-center gap-1 text-[11px]">
                  <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${m.is_online ? 'bg-green-400' : 'bg-gray-500'}`} />
                  <span className="truncate" style={{ color: 'var(--color-text)' }}>{m.display_name}</span>
                </span>
              ))}
            </span>
          </>
        )}
      </div>

      {/* Tags */}
      {device.tags_array?.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {device.tags_array.slice(0, 3).map(tag => (
            <span key={tag}
              className="px-1.5 py-0.5 rounded-full text-[10px] font-medium"
              style={{ background: 'var(--color-brand)', color: '#fff', opacity: 0.85 }}>
              {tag}
            </span>
          ))}
          {device.tags_array.length > 3 && (
            <span className="px-1.5 py-0.5 rounded-full text-[10px]"
              style={{ background: 'var(--color-surface-offset)', color: 'var(--color-text-faint)' }}>
              +{device.tags_array.length - 3}
            </span>
          )}
        </div>
      )}

      {/* Footer — always pinned to bottom */}
      <div className="mt-auto flex items-center justify-between pt-1 border-t" style={{ borderColor: 'var(--color-border)' }}>
        {drift ? (
          <div className="flex items-center gap-1">
            {drift.newPorts.length > 0 && (
              <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded-full"
                style={{ background: 'rgba(239,68,68,0.15)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.3)' }}
                title={`New ports vs baseline: ${drift.newPorts.join(', ')}`}>
                +{drift.newPorts.length}
              </span>
            )}
            {drift.closedPorts.length > 0 && (
              <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded-full"
                style={{ background: 'rgba(245,158,11,0.15)', color: '#f59e0b', border: '1px solid rgba(245,158,11,0.3)' }}
                title={`Closed ports vs baseline: ${drift.closedPorts.join(', ')}`}>
                -{drift.closedPorts.length}
              </span>
            )}
          </div>
        ) : <span />}
        <span className="text-xs" style={{ color: device.is_online ? 'var(--color-text-faint)' : '#ef4444' }}>
          {device.is_online
            ? `online · ${relativeTime(device.status_changed_at || device.last_seen)}`
            : `offline · ${relativeTime(device.status_changed_at || device.last_seen)}`}
        </span>
      </div>
    </button>
  )
}
