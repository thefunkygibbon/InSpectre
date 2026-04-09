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

export function DeviceRow({ device, onClick, striped }) {
  const name = device.display_name || device.ip_address

  return (
    <button
      onClick={onClick}
      className={`grid grid-cols-[1.5rem_2fr_1fr_1fr_1fr_6rem] gap-4 px-4 py-3 w-full text-left
                  border-b border-border last:border-0 transition-colors duration-100
                  hover:bg-surface-hover active:bg-surface-active
                  ${ striped ? 'bg-surface-offset/30' : '' }`}
    >
      <div className="flex items-center">
        <OnlineDot online={device.is_online} />
      </div>
      <div className="min-w-0">
        <p className="text-sm font-medium text-text truncate">{name}</p>
        {device.hostname && device.custom_name && (
          <p className="text-xs text-text-muted font-mono truncate">{device.hostname}</p>
        )}
        <p className="text-xs text-text-muted font-mono">{device.ip_address}</p>
      </div>
      <div className="flex items-center">
        <span className="text-xs font-mono text-text-muted truncate">{device.mac_address}</span>
      </div>
      <div className="flex items-center">
        <span className="text-sm text-text truncate">{device.vendor || '—'}</span>
      </div>
      <div className="flex items-center">
        <span className="text-xs text-text-muted">{relativeTime(device.last_seen)}</span>
      </div>
      <div className="flex items-center">
        {device.is_online
          ? <span className="badge-online">Online</span>
          : <span className="badge-offline">Offline</span>}
      </div>
    </button>
  )
}
