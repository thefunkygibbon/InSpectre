import { Box } from 'lucide-react'

const STATUS_CONFIG = {
  running:    { color: '#22c55e', bg: 'rgba(34,197,94,0.12)',   border: 'rgba(34,197,94,0.3)',   dot: '#22c55e', label: 'Running'    },
  exited:     { color: '#6b7280', bg: 'rgba(107,114,128,0.12)', border: 'rgba(107,114,128,0.3)', dot: '#6b7280', label: 'Stopped'    },
  paused:     { color: '#f59e0b', bg: 'rgba(245,158,11,0.12)',  border: 'rgba(245,158,11,0.3)',  dot: '#f59e0b', label: 'Paused'     },
  restarting: { color: '#3b82f6', bg: 'rgba(59,130,246,0.12)',  border: 'rgba(59,130,246,0.3)',  dot: '#3b82f6', label: 'Restarting' },
  dead:       { color: '#ef4444', bg: 'rgba(239,68,68,0.12)',   border: 'rgba(239,68,68,0.3)',   dot: '#ef4444', label: 'Dead'       },
  created:    { color: '#8b5cf6', bg: 'rgba(139,92,246,0.12)',  border: 'rgba(139,92,246,0.3)',  dot: '#8b5cf6', label: 'Created'    },
}

function relativeTime(iso) {
  if (!iso) return ''
  const diff = Date.now() - new Date(iso).getTime()
  if (diff < 0) return ''
  const mins = Math.floor(diff / 60000)
  if (mins < 1)  return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24)  return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

function shortImage(image) {
  if (!image) return ''
  const noReg = image.replace(/^[^/]+\/[^/]+\//, '').replace(/^[^/]+\//, '')
  return noReg || image
}

export function ContainerCard({ container, onClick }) {
  const cfg       = STATUS_CONFIG[container.status] || STATUS_CONFIG.exited
  const isRunning = container.status === 'running'
  const exposedPorts = (container.ports || []).filter(p => p.host_port).slice(0, 3)

  const footerTime = isRunning
    ? (container.state?.started_at ? `started · ${relativeTime(container.state.started_at)}` : 'running')
    : (container.state?.finished_at ? `stopped · ${relativeTime(container.state.finished_at)}` : `created · ${relativeTime(container.created)}`)

  return (
    <button
      onClick={onClick}
      className="device-card p-5 text-left w-full flex flex-col gap-3 group relative"
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2.5 min-w-0">
          <span className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
            style={{ background: cfg.bg }}>
            <Box size={15} style={{ color: cfg.color }} />
          </span>
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full shrink-0 transition-colors"
                style={{ background: cfg.dot }} />
              <span className="font-semibold text-sm truncate" style={{ color: 'var(--color-text)' }}>
                {container.name}
              </span>
            </div>
            <span className="text-[11px] truncate block" style={{ color: 'var(--color-text-muted)' }}>
              {shortImage(container.image)}
            </span>
          </div>
        </div>
        <span className="text-[10px] font-medium px-2 py-0.5 rounded-full shrink-0 whitespace-nowrap"
          style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.border}` }}>
          {cfg.label}
        </span>
      </div>

      {/* Details grid */}
      <div className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-xs">
        <span style={{ color: 'var(--color-text-muted)' }}>ID</span>
        <span className="font-mono truncate text-[11px]" style={{ color: 'var(--color-text)' }}>
          {container.short_id}
        </span>

        {exposedPorts.length > 0 && (
          <>
            <span style={{ color: 'var(--color-text-muted)' }}>Ports</span>
            <span className="truncate" style={{ color: 'var(--color-text)' }}>
              {exposedPorts.map(p => `${p.host_port}→${p.container_port.split('/')[0]}`).join(', ')}
              {(container.ports || []).filter(p => p.host_port).length > 3 && ' …'}
            </span>
          </>
        )}

        {(container.networks || []).length > 0 && (
          <>
            <span style={{ color: 'var(--color-text-muted)' }}>Network</span>
            <span className="truncate" style={{ color: 'var(--color-text)' }}>
              {container.networks.join(', ')}
            </span>
          </>
        )}

        {container.restart_policy && container.restart_policy !== 'no' && (
          <>
            <span style={{ color: 'var(--color-text-muted)' }}>Restart</span>
            <span className="truncate" style={{ color: 'var(--color-text)' }}>
              {container.restart_policy}
            </span>
          </>
        )}
      </div>

      {/* Footer */}
      <div className="mt-auto flex items-center justify-between pt-1 border-t"
        style={{ borderColor: 'var(--color-border)' }}>
        {container.host_name ? (
          <span className="text-[10px] font-medium truncate max-w-[50%]" style={{ color: 'var(--color-text-faint)' }}>
            {container.host_name}
          </span>
        ) : <span />}
        <span className="text-xs" style={{ color: isRunning ? 'var(--color-text-faint)' : '#6b7280' }}>
          {footerTime}
        </span>
      </div>
    </button>
  )
}
