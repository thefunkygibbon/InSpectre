import { ScanLine, Clock } from 'lucide-react'
import { OnlineDot } from './OnlineDot'

function timeAgo(iso) {
  if (!iso) return 'never'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1)  return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs  < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

export function DeviceRow({ device, onClick, zebra }) {
  const name = device.custom_name || device.hostname || device.ip_address

  return (
    <button
      onClick={onClick}
      className={`grid list-cols w-full text-left px-4 py-3 gap-4 items-center
                  border-b border-white/5 last:border-0 group cursor-pointer
                  hover:bg-white/4 transition-colors duration-100 animate-fade-in
                  ${ zebra ? 'bg-white/[0.015]' : '' }`}
    >
      {/* Device name */}
      <div className="flex items-center gap-2.5 min-w-0">
        <OnlineDot online={device.is_online} />
        <span className="text-sm font-medium text-gray-200 truncate group-hover:text-brand-300 transition-colors">
          {name}
        </span>
        {!device.deep_scanned && (
          <ScanLine size={11} className="text-amber-400 animate-pulse shrink-0" title="Scan pending" />
        )}
      </div>

      {/* IP */}
      <span className="font-mono text-xs text-gray-400 hidden md:block">{device.ip_address || '—'}</span>

      {/* MAC */}
      <span className="font-mono text-xs text-gray-600 hidden lg:block">{device.mac_address}</span>

      {/* Vendor */}
      <span className="text-xs text-gray-400 truncate hidden sm:block">{device.vendor || '—'}</span>

      {/* Status badge */}
      <div>
        {device.is_online
          ? <span className="badge-online">Online</span>
          : <span className="badge-offline">Offline</span>}
      </div>

      {/* Last seen */}
      <div className="hidden md:flex items-center gap-1 text-xs text-gray-600">
        <Clock size={10} />
        {timeAgo(device.last_seen)}
      </div>
    </button>
  )
}
