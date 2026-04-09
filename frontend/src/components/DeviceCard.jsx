import { Cpu, Network, Clock, ScanLine } from 'lucide-react'
import { OnlineDot } from './OnlineDot'

function timeAgo(iso) {
  if (!iso) return 'never'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1)  return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24)  return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

export function DeviceCard({ device, onClick }) {
  const name = device.custom_name || device.hostname || device.ip_address
  const os   = device.scan_results?.os_matches?.[0]?.name

  return (
    <button
      onClick={onClick}
      className="card glass-hover w-full text-left p-5 flex flex-col gap-4 group cursor-pointer
                 hover:border-brand-500/30 hover:shadow-lg hover:shadow-brand-900/20
                 transition-all duration-200 animate-fade-in"
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2.5 min-w-0">
          <OnlineDot online={device.is_online} />
          <span className="font-semibold text-gray-100 truncate text-sm group-hover:text-brand-300 transition-colors">
            {name}
          </span>
        </div>
        {!device.deep_scanned && (
          <span className="badge-scanning shrink-0">
            <ScanLine size={10} className="animate-pulse" />
            Scanning
          </span>
        )}
      </div>

      {/* Details grid */}
      <div className="grid grid-cols-2 gap-2 text-xs">
        <Detail icon={Network} label={device.ip_address || '—'} />
        <Detail icon={Cpu}     label={device.vendor || 'Unknown vendor'} truncate />
      </div>

      {/* OS / MAC footer */}
      <div className="pt-1 border-t border-white/5 flex items-center justify-between gap-2">
        <span className="font-mono text-xs text-gray-600">{device.mac_address}</span>
        {os && <span className="text-xs text-brand-400/80 truncate max-w-[120px]">{os}</span>}
      </div>

      {/* Last seen */}
      <div className="flex items-center gap-1 text-xs text-gray-600">
        <Clock size={10} />
        <span>Last seen {timeAgo(device.last_seen)}</span>
      </div>
    </button>
  )
}

function Detail({ icon: Icon, label, truncate }) {
  return (
    <div className="flex items-center gap-1.5 text-gray-400">
      <Icon size={11} className="shrink-0 text-gray-600" />
      <span className={truncate ? 'truncate' : ''}>{label}</span>
    </div>
  )
}
