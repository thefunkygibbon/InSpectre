import { useState, useEffect } from 'react'
import {
  Wifi, WifiOff, Plus, ArrowLeftRight, ScanLine,
  Star, Tag, Edit3, AlertCircle, Clock, ShieldAlert, Ban, CheckCircle,
} from 'lucide-react'
import { api } from '../api'

const EVENT_CONFIG = {
  joined:             { icon: Plus,           color: '#10b981', label: 'First seen' },
  online:             { icon: Wifi,           color: '#10b981', label: 'Came online' },
  offline:            { icon: WifiOff,        color: '#ef4444', label: 'Went offline' },
  ip_change:          { icon: ArrowLeftRight, color: '#f59e0b', label: 'IP changed' },
  scan_complete:      { icon: ScanLine,       color: '#6366f1', label: 'Scan complete' },
  renamed:            { icon: Edit3,          color: '#8b5cf6', label: 'Renamed' },
  tagged:             { icon: Tag,            color: '#06b6d4', label: 'Tags updated' },
  marked_important:   { icon: Star,           color: '#f59e0b', label: 'Watch status changed' },
  port_change:        { icon: AlertCircle,    color: '#ef4444', label: 'Ports changed' },
  vuln_scan_complete: { icon: ShieldAlert,    color: '#f97316', label: 'Vulnerability scan' },
  blocked:            { icon: Ban,            color: '#ef4444', label: 'Blocked' },
  unblocked:          { icon: CheckCircle,    color: '#10b981', label: 'Unblocked' },
  primary_ip_changed: { icon: ArrowLeftRight, color: '#f59e0b', label: 'Primary IP changed' },
}

function relativeTime(iso) {
  if (!iso) return ''
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1)  return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24)  return `${hrs}h ago`
  const days = Math.floor(hrs / 24)
  if (days < 7)  return `${days}d ago`
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

function eventDetail(event) {
  const d = event.detail
  if (!d) return null
  switch (event.type) {
    case 'ip_change':        return `${d.old_ip} \u2192 ${d.new_ip}`
    case 'renamed':          return d.new ? `\u201c${d.new}\u201d` : 'Name cleared'
    case 'tagged':           return d.tags ? `Tags: ${d.tags}` : null
    case 'marked_important': return d.important ? '\u2605 Marked as watched' : 'Removed from watched'
    case 'scan_complete':       return d.open_ports != null ? `${d.open_ports} open port${d.open_ports !== 1 ? 's' : ''}` : null
    case 'vuln_scan_complete':  return d.severity ? `${d.severity} (${d.vuln_count ?? 0} finding${d.vuln_count !== 1 ? 's' : ''})` : null
    case 'port_change': {
      const parts = []
      if (d.added?.length)   parts.push(`+${d.added.length} port${d.added.length !== 1 ? 's' : ''} (${d.added.map(p => p.port).join(', ')})`)
      if (d.removed?.length) parts.push(`-${d.removed.length} port${d.removed.length !== 1 ? 's' : ''} (${d.removed.map(p => p.port).join(', ')})`)
      return parts.length ? parts.join(' · ') : null
    }
    default:                 return null
  }
}

export function DeviceTimeline({ mac }) {
  const [events,  setEvents]  = useState(null)
  const [error,   setError]   = useState(null)
  const [loaded,  setLoaded]  = useState(false)

  useEffect(() => {
    if (loaded) return
    setLoaded(true)
    api.getDeviceEvents(mac, 50)
      .then(setEvents)
      .catch(e => { setError(e.message); setEvents([]) })
  }, [mac, loaded])

  if (events === null) return (
    <div className="space-y-2">
      {[...Array(3)].map((_, i) => (
        <div key={i} className="flex gap-3 items-start">
          <div className="skeleton w-6 h-6 rounded-full shrink-0" />
          <div className="flex-1 space-y-1">
            <div className="skeleton h-3 w-24 rounded" />
            <div className="skeleton h-3 w-40 rounded" />
          </div>
        </div>
      ))}
    </div>
  )

  if (error) return <p className="text-xs text-red-400">{error}</p>

  if (events.length === 0) return (
    <div className="flex flex-col items-center gap-2 py-6 text-center">
      <Clock size={24} style={{ color: 'var(--color-text-faint)' }} />
      <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>No events recorded yet</p>
      <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>Events will appear as the device is seen online/offline</p>
    </div>
  )

  return (
    <div className="relative">
      {/* Vertical line */}
      <div
        className="absolute left-[11px] top-3 bottom-3 w-px"
        style={{ background: 'var(--color-border)' }}
      />
      <div className="space-y-4">
        {events.map(event => {
          const cfg    = EVENT_CONFIG[event.type] || { icon: Clock, color: 'var(--color-text-faint)', label: event.type }
          const Icon   = cfg.icon
          const detail = eventDetail(event)
          return (
            <div key={event.id} className="flex gap-3 items-start relative">
              {/* Icon bubble */}
              <div
                className="w-6 h-6 rounded-full flex items-center justify-center shrink-0 relative z-10"
                style={{ background: `${cfg.color}20`, border: `1px solid ${cfg.color}40` }}
              >
                <Icon size={11} style={{ color: cfg.color }} />
              </div>
              {/* Content */}
              <div className="flex-1 min-w-0 pb-1">
                <div className="flex items-baseline gap-2 justify-between">
                  <span className="text-xs font-medium" style={{ color: 'var(--color-text)' }}>
                    {cfg.label}
                  </span>
                  <span className="text-[10px] shrink-0" style={{ color: 'var(--color-text-faint)' }}>
                    {relativeTime(event.created_at)}
                  </span>
                </div>
                {detail && (
                  <p className="text-[11px] mt-0.5 font-mono" style={{ color: 'var(--color-text-muted)' }}>
                    {detail}
                  </p>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
