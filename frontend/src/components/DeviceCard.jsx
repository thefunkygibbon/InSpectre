import {
  Wifi, Laptop, Smartphone, Server, Printer, Tv,
  HelpCircle, Cpu
} from 'lucide-react'
import { OnlineDot } from './OnlineDot'

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

function getDeviceIcon(device) {
  const vendor   = (device.vendor   || '').toLowerCase()
  const hostname = (device.hostname || '').toLowerCase()
  const os       = (device.scan_results?.os_matches?.[0]?.name || '').toLowerCase()
  const combined = `${vendor} ${hostname} ${os}`

  if (/router|gateway|cisco|netgear|asus rt|tp-link|ubiquiti|unifi|mikrotik|openwrt/.test(combined)) return Wifi
  if (/printer|hp laser|canon|epson|brother|xerox/.test(combined)) return Printer
  if (/android|iphone|ipad|samsung|pixel|oneplus|xiaomi|mobile|phone/.test(combined)) return Smartphone
  if (/apple|macbook|laptop|thinkpad|dell|lenovo|hp pavilion|surface/.test(combined)) return Laptop
  if (/server|ubuntu|debian|centos|fedora|linux|proxmox|esxi|vmware|nas|synology|qnap/.test(combined)) return Server
  if (/tv|firetv|roku|chromecast|shield|appletv|smart-tv|bravia/.test(combined)) return Tv
  return HelpCircle
}

function portCount(device) {
  const ports = device.scan_results?.ports
  if (!ports) return null
  if (Array.isArray(ports)) return ports.length
  if (typeof ports === 'object') return Object.keys(ports).length
  return null
}

export function DeviceCard({ device, onClick }) {
  const name      = device.display_name || device.ip_address
  const os        = device.scan_results?.os_matches?.[0]?.name
  const DevIcon   = getDeviceIcon(device)
  const ports     = portCount(device)
  const scanning  = !device.deep_scanned

  return (
    <button
      onClick={onClick}
      className={`device-card${scanning ? ' device-card-scanning' : ''} p-5 text-left w-full flex flex-col gap-3 group`}
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-2 relative">
        <div className="flex items-center gap-2.5 min-w-0">
          {/* Device type icon */}
          <span
            className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 transition-colors duration-200"
            style={{
              background: 'color-mix(in srgb, var(--color-brand) 10%, var(--color-surface-offset))',
            }}
          >
            <DevIcon size={15} style={{ color: 'var(--color-brand)' }} />
          </span>
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <OnlineDot online={device.is_online} size="sm" />
              <span className="font-semibold text-sm truncate" style={{ color: 'var(--color-text)' }}>{name}</span>
            </div>
            {ports != null && (
              <span
                className="text-[10px] font-medium"
                style={{ color: 'var(--color-text-faint)' }}
              >
                {ports}p
              </span>
            )}
          </div>
        </div>
        {scanning && (
          <span className="shrink-0 text-[10px] font-medium text-amber-400 bg-amber-400/10
                           border border-amber-400/20 rounded-full px-2 py-0.5">
            Scanning
          </span>
        )}
      </div>

      {/* Details grid */}
      <div className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-xs relative">
        <span style={{ color: 'var(--color-text-muted)' }}>IP</span>
        <span className="font-mono truncate" style={{ color: 'var(--color-text)' }}>{device.ip_address}</span>

        <span style={{ color: 'var(--color-text-muted)' }}>MAC</span>
        <span className="font-mono truncate text-[11px]" style={{ color: 'var(--color-text)' }}>{device.mac_address}</span>

        {device.vendor && (
          <>
            <span style={{ color: 'var(--color-text-muted)' }}>Vendor</span>
            <span className="truncate" style={{ color: 'var(--color-text)' }}>{device.vendor}</span>
          </>
        )}
      </div>

      {/* Footer */}
      <div className="flex items-center justify-between pt-1 border-t relative" style={{ borderColor: 'var(--color-border)' }}>
        {os ? (
          <div className="flex items-center gap-1.5 text-xs truncate" style={{ color: 'var(--color-text-muted)' }}>
            <Cpu size={11} style={{ color: 'var(--color-brand)' }} className="shrink-0" />
            <span className="truncate">{os}</span>
          </div>
        ) : (
          <span className="text-xs" style={{ color: 'var(--color-text-faint)' }}>{device.vendor || 'Unknown vendor'}</span>
        )}
        <span className="text-xs shrink-0 ml-2" style={{ color: 'var(--color-text-faint)' }}>
          {relativeTime(device.last_seen)}
        </span>
      </div>
    </button>
  )
}
