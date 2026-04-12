import { useEffect, useState } from 'react'
import {
  Wifi, WifiOff, Plus, RefreshCw, Tag, Star,
  ArrowRight, CheckCircle, HelpCircle, MapPin
} from 'lucide-react'
import { api } from '../api'

const EVENT_META = {
  joined:           { icon: Plus,        color: '#22c55e', label: 'First seen on network' },
  online:           { icon: Wifi,        color: '#22c55e', label: 'Came online' },
  offline:          { icon: WifiOff,     color: '#ef4444', label: 'Went offline' },
  ip_change:        { icon: ArrowRight,  color: '#f59e0b', label: 'IP address changed' },
  scan_complete:    { icon: CheckCircle, color: '#3b82f6', label: 'Scan completed' },
  renamed:          { icon: Tag,         color: '#8b5cf6', label: 'Renamed' },
  tagged:           { icon: Tag,         color: '#8b5cf6', label: 'Tags updated' },
  marked_important: { icon: Star,        color: '#f59e0b', label: 'Marked important' },
  port_change:      { icon: RefreshCw,   color: '#06b6d4', label: 'Port list changed' },
  located:          { icon: MapPin,      color: '#10b981', label: 'Location set' },
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
  if (days < 30) return `${days}d ago`
  return new Date(iso).toLocaleDateString()
}

function eventDetail(event) {
  const d = event.detail
  if (!d) return null
  if (event.type === 'ip_change')  return `${d.old_ip} → ${d.new_ip}`
  if (event.type === 'renamed')    return d.new ? `"${d.new}"` : null
  if (event.type === 'tagged')     return d.tags || null
  if (event.type === 'marked_important') return d.important ? 'Watched' : 'Unwatched'
  return null
}

export function DeviceTimeline({ mac }) {
  const [events,  setEvents]  = useState([])
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)

  useEffect(() => {
    if (!mac) return
    setLoading(true)
    api.getDeviceEvents(mac, 100)
      .then(data => { setEvents(data); setError(null) })
      .catch(e  => setError(e.message))
      .finally(() => setLoading(false))
  }, [mac])

  if (loading) return (
    <div className="flex items-center justify-center py-10" style={{ color: 'var(--color-text-faint)' }}>
      <RefreshCw size={16} className="animate-spin mr-2" /> Loading timeline…
    </div>
  )

  if (error) return (
    <p className="text-sm py-4" style={{ color: 'var(--color-error)' }}>Failed to load timeline: {error}</p>
  )

  if (events.length === 0) return (
    <p className="text-sm py-8 text-center" style={{ color: 'var(--color-text-faint)' }}>
      No events recorded yet. Events will appear as the scanner runs.
    </p>
  )

  return (
    <div className="relative">
      {/* Vertical line */}
      <div
        className="absolute left-3.5 top-0 bottom-0 w-px"
        style={{ background: 'var(--color-border)' }}
      />

      <ul className="space-y-4 pl-10">
        {events.map(ev => {
          const meta    = EVENT_META[ev.type] || { icon: HelpCircle, color: 'var(--color-text-faint)', label: ev.type }
          const Icon    = meta.icon
          const detail  = eventDetail(ev)
          return (
            <li key={ev.id} className="relative flex flex-col gap-0.5">
              {/* Icon dot on the line */}
              <span
                className="absolute -left-[26px] w-7 h-7 rounded-full flex items-center justify-center"
                style={{ background: meta.color + '22', border: `1.5px solid ${meta.color}55` }}
              >
                <Icon size={13} style={{ color: meta.color }} />
              </span>

              <span className="text-xs font-medium" style={{ color: 'var(--color-text)' }}>
                {meta.label}
              </span>
              {detail && (
                <span className="text-xs" style={{ color: 'var(--color-text-muted)' }}>{detail}</span>
              )}
              <span className="text-[11px]" style={{ color: 'var(--color-text-faint)' }}>
                {relativeTime(ev.created_at)}
              </span>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
