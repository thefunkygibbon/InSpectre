import { OnlineDot } from './OnlineDot'
import { StarButton } from './StarButton'

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

function cleanVendor(vendor) {
  if (!vendor) return '--'
  return vendor
    .replace(/\s+(Inc\.?|LLC\.?|Ltd\.?|Co\.,?\s*Ltd\.?|Technologies|Technology|International|Electronics|Systems|Networks|Communications|Corp\.?|Group|Holdings)(\s+|$)/gi, '')
    .trim()
}

export function DeviceRow({ device, onClick, striped, onStarToggle, isVulnScanning }) {
  const name = device.custom_name || device.hostname || device.ip_address || device.mac_address

  return (
    <div
      onClick={onClick}
      className={`grid grid-cols-[1.5rem_1fr_5rem_1.5rem] sm:grid-cols-[1.5rem_2fr_1fr_1fr_1fr_6rem_1.5rem]
                  gap-3 sm:gap-4 px-4 py-3 border-b last:border-0
                  items-center cursor-pointer hover:bg-surface-offset transition-colors
                  ${striped ? 'bg-surface-offset/40' : ''}`}
      style={{ borderColor: 'var(--color-border)' }}
    >
      <OnlineDot online={device.is_online} size="sm" />

      <div className="min-w-0">
        <p className="text-sm font-medium truncate" style={{ color: 'var(--color-text)' }}>{name}</p>
        <p className="text-xs font-mono truncate" style={{ color: 'var(--color-text-faint)' }}>{device.ip_address}</p>
      </div>

      <span className="hidden sm:block font-mono text-xs truncate" style={{ color: 'var(--color-text-muted)' }}>
        {device.mac_address}
      </span>

      <span className="hidden sm:block text-xs truncate" style={{ color: 'var(--color-text-muted)' }}>
        {cleanVendor(device.vendor_override || device.vendor)}
      </span>

      <span className="hidden sm:block text-xs" style={{ color: 'var(--color-text-faint)' }}>
        {relativeTime(device.last_seen)}
      </span>

      <div className="flex flex-col gap-1 items-start">
        <span
          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium
                      ${device.is_online ? 'badge-online' : 'badge-offline'}`}
        >
          {device.is_online ? 'Online' : 'Offline'}
        </span>
        {isVulnScanning && (
          <span className="hidden sm:inline-flex text-[10px] font-medium rounded-full px-2 py-0.5"
            style={{ color: 'var(--color-brand)', background: 'color-mix(in srgb, var(--color-brand) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--color-brand) 25%, transparent)' }}>
            Vuln Scan
          </span>
        )}
      </div>

      <div onClick={e => e.stopPropagation()}>
        {onStarToggle && <StarButton device={device} onToggle={onStarToggle} size={13} />}
      </div>
    </div>
  )
}
