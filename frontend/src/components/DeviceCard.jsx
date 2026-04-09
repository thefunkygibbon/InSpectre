import { Cpu } from 'lucide-react'
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

export function DeviceCard({ device, onClick }) {
  const name = device.display_name || device.ip_address
  const os   = device.scan_results?.os_matches?.[0]?.name

  return (
    <button
      onClick={onClick}
      className="card p-5 text-left w-full flex flex-col gap-3 hover:border-brand/40 hover:shadow-brand/5
                 hover:shadow-lg transition-all duration-200 active:scale-[0.98] group"
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <OnlineDot online={device.is_online} />
          <span className="font-semibold text-text text-sm truncate">{name}</span>
        </div>
        {!device.deep_scanned && (
          <span className="shrink-0 text-[10px] font-medium text-amber-400 bg-amber-400/10
                           border border-amber-400/20 rounded-full px-2 py-0.5">
            Scanning
          </span>
        )}
      </div>

      {/* Details grid */}
      <div className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-xs">
        <span className="text-text-muted">IP</span>
        <span className="font-mono text-text truncate">{device.ip_address}</span>

        <span className="text-text-muted">MAC</span>
        <span className="font-mono text-text truncate text-[11px]">{device.mac_address}</span>

        {device.vendor && (
          <>
            <span className="text-text-muted">Vendor</span>
            <span className="text-text truncate">{device.vendor}</span>
          </>
        )}
      </div>

      {/* Footer */}
      <div className="flex items-center justify-between pt-1 border-t border-border">
        {os ? (
          <div className="flex items-center gap-1.5 text-xs text-text-muted truncate">
            <Cpu size={11} className="text-brand shrink-0" />
            <span className="truncate">{os}</span>
          </div>
        ) : (
          <span className="text-xs text-text-muted">{device.vendor || 'Unknown vendor'}</span>
        )}
        <span className="text-xs text-text-muted shrink-0 ml-2">{relativeTime(device.last_seen)}</span>
      </div>
    </button>
  )
}
