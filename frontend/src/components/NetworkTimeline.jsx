import { useState, useEffect, useCallback, useMemo } from 'react'
import { Loader, Wifi, WifiOff, Clock, Search, Box, History } from 'lucide-react'
import { api } from '../api'
import { subscribeLive } from '../lib/liveEvents'

const PERIODS = [
  { label: '7 days',  days: 7   },
  { label: '1 month', days: 30  },
  { label: '1 year',  days: 365 },
]

function fmtDate(iso) {
  if (!iso) return ''
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

function fmtDateTime(iso) {
  if (!iso) return ''
  return new Date(iso).toLocaleString()
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

const SOURCE_LABELS = {
  sweep: 'ARP sweep',
  sniffer: 'Passive sniffer',
}

function formatSource(source) {
  if (!source) return null
  if (SOURCE_LABELS[source]) return SOURCE_LABELS[source]
  if (source.startsWith('plugin:')) return `Plugin: ${source.slice(7)}`
  return source
}

function statusDetail(detail) {
  if (!detail) return null
  const parts = []
  const source = formatSource(detail.source)
  if (source) parts.push(`Source: ${source}`)
  if (detail.confirmation === 'icmp') parts.push('Ping confirm')
  return parts.length ? parts.join(' · ') : null
}

function StatusDot({ status }) {
  const colors = { online: '#10b981', offline: '#ef4444', unknown: '#6b7280' }
  return (
    <span className="inline-block w-2 h-2 rounded-full shrink-0"
      style={{ background: colors[status] || colors.unknown }} />
  )
}

function TimelineBar({ segments, deviceName }) {
  if (!segments?.length) {
    return <div className="flex-1 h-6 rounded overflow-hidden" style={{ background: 'var(--color-surface-offset)' }} />
  }

  const STATUS_COLORS = {
    online:  '#10b981',
    offline: '#ef4444',
    unknown: '#374151',
  }

  return (
    <div className="flex-1 h-6 rounded overflow-hidden relative" style={{ background: 'var(--color-surface-offset)' }}>
      {segments.map((seg, i) => {
        const color    = STATUS_COLORS[seg.status] || STATUS_COLORS.unknown
        return (
          <div key={i}
            title={`${deviceName}: ${seg.status} from ${fmtDateTime(seg.from)} to ${fmtDateTime(seg.to)}`}
            className="absolute top-0 bottom-0 transition-opacity hover:opacity-80 cursor-default"
            style={{
              left:    `${seg.leftPct}%`,
              width:   `${seg.widthPct}%`,
              minWidth: '2px',
              background: color,
              opacity: seg.status === 'unknown' ? 0.3 : 0.85,
            }}
          />
        )
      })}
    </div>
  )
}

function XAxisLabels({ windowStart, windowEnd, days }) {
  const ticks = useMemo(() => {
    const start = new Date(windowStart)
    const end   = new Date(windowEnd)
    const totalMs = end - start
    const count = days <= 7 ? 7 : days <= 30 ? 6 : 12
    return Array.from({ length: count + 1 }, (_, i) => {
      const t = new Date(start.getTime() + (totalMs * i) / count)
      return { pct: (i / count) * 100, label: fmtDate(t.toISOString()) }
    })
  }, [windowStart, windowEnd, days])

  return (
    <div className="relative h-5 ml-[160px] mr-[80px] sm:ml-[200px] sm:mr-[90px]">
      {ticks.map((t, i) => (
        <span key={i}
          className="absolute text-[9px] transform -translate-x-1/2"
          style={{ left: `${t.pct}%`, color: 'var(--color-text-faint)' }}>
          {t.label}
        </span>
      ))}
    </div>
  )
}

function DeviceRow({ device, onDeviceClick }) {
  const onlinePct = device.onlinePct ?? 0
  return (
    <div className="flex items-center gap-3 py-1.5">
      <div className="w-[160px] sm:w-[200px] flex items-center gap-2 shrink-0 min-w-0">
        <button
          onClick={() => onDeviceClick && onDeviceClick(device.mac)}
          disabled={!onDeviceClick}
          className="w-1.5 h-1.5 rounded-full shrink-0 transition-opacity hover:opacity-70 disabled:cursor-default"
          style={{ background: device.is_online ? '#10b981' : '#ef4444' }}
          title={device.is_online ? 'Online' : 'Offline'}
        />
        <button
          onClick={() => onDeviceClick && onDeviceClick(device.mac)}
          className="text-xs truncate text-left hover:underline"
          style={{ color: onDeviceClick ? 'var(--color-brand)' : 'var(--color-text)' }}
          title={device.name}>
          {device.name}
        </button>
      </div>

      <TimelineBar segments={device.renderSegments} deviceName={device.name} />

      <div className="w-[70px] sm:w-[80px] text-right shrink-0">
        <span className="text-[10px] font-mono tabular-nums"
          style={{ color: onlinePct >= 90 ? '#10b981' : onlinePct >= 50 ? '#f59e0b' : '#ef4444' }}>
          {onlinePct}% up
        </span>
      </div>
    </div>
  )
}

function ContainerTimelineRow({ container, windowStart, windowEnd }) {
  const STATUS_COLORS = { running: '#22c55e', stopped: '#6b7280', unknown: '#374151', paused: '#f59e0b' }

  const uptimePct = useMemo(() => {
    const totalMs = new Date(windowEnd) - new Date(windowStart)
    if (totalMs <= 0) return 0
    const runMs = container.segments
      .filter(s => s.status === 'running')
      .reduce((sum, s) => sum + (new Date(s.to) - new Date(s.from)), 0)
    return Math.round((runMs / totalMs) * 100)
  }, [container.segments, windowStart, windowEnd])

  return (
    <div className="flex items-center gap-3 py-1.5">
      <div className="w-[160px] sm:w-[200px] flex items-center gap-2 shrink-0 min-w-0">
        <span className="w-1.5 h-1.5 rounded-full shrink-0"
          style={{ background: container.is_running ? '#22c55e' : '#6b7280' }} />
        <span className="text-xs truncate" style={{ color: 'var(--color-text)' }} title={container.name}>
          {container.name}
        </span>
      </div>

      <div className="flex-1 h-6 rounded overflow-hidden relative" style={{ background: 'var(--color-surface-offset)' }}>
        {(() => {
          const winStart = new Date(windowStart)
          const winEnd   = new Date(windowEnd)
          const totalMs  = winEnd - winStart
          if (totalMs <= 0) return null
          return container.segments.map((seg, i) => {
            const segStart = Math.max(new Date(seg.from), winStart)
            const segEnd   = Math.min(new Date(seg.to),   winEnd)
            if (segEnd <= segStart) return null
            const leftPct  = ((segStart - winStart) / totalMs) * 100
            const widthPct = ((segEnd   - segStart) / totalMs) * 100
            const color    = STATUS_COLORS[seg.status] || STATUS_COLORS.unknown
            return (
              <div key={i}
                title={`${container.name}: ${seg.status} from ${new Date(seg.from).toLocaleString()} to ${new Date(seg.to).toLocaleString()}`}
                className="absolute top-0 bottom-0 transition-opacity hover:opacity-80 cursor-default"
                style={{
                  left:    `${leftPct}%`,
                  width:   `${widthPct}%`,
                  minWidth: '2px',
                  background: color,
                  opacity: seg.status === 'unknown' ? 0.3 : 0.85,
                }}
              />
            )
          })
        })()}
      </div>

      <div className="w-[70px] sm:w-[80px] text-right shrink-0">
        <span className="text-[10px] font-mono tabular-nums"
          style={{ color: uptimePct >= 90 ? '#22c55e' : uptimePct >= 50 ? '#f59e0b' : '#6b7280' }}>
          {uptimePct}% up
        </span>
      </div>
    </div>
  )
}

function ContainerTimeline({ days }) {
  const [data,    setData]    = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)
  const [search,  setSearch]  = useState('')

  const load = useCallback(async (d) => {
    setLoading(true)
    setError(null)
    try {
      const result = await api.getContainerTimeline(d)
      setData(result)
    } catch (e) {
      if (e.message?.includes('503') || e.message?.toLowerCase().includes('disabled')) {
        setError('Docker monitoring is disabled. Enable it in Settings → Docker.')
      } else {
        setError(e.message)
      }
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load(days) }, [days, load])

  const filtered = useMemo(() => {
    if (!data?.containers) return []
    const q = search.toLowerCase()
    if (!q) return data.containers
    return data.containers.filter(c => c.name.toLowerCase().includes(q))
  }, [data, search])

  return (
    <div>
      <div className="relative mb-4 max-w-xs">
        <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
          style={{ color: 'var(--color-text-muted)' }} />
        <input className="input pl-8 text-xs w-full" placeholder="Filter containers…"
          value={search} onChange={e => setSearch(e.target.value)} />
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 mb-4 text-xs" style={{ color: 'var(--color-text-muted)' }}>
        <span className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded-sm inline-block" style={{ background: '#22c55e', opacity: 0.85 }} />
          Running
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded-sm inline-block" style={{ background: '#6b7280', opacity: 0.85 }} />
          Stopped
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded-sm inline-block" style={{ background: '#374151', opacity: 0.3 }} />
          Unknown
        </span>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <Loader size={24} className="animate-spin" style={{ color: 'var(--color-text-faint)' }} />
        </div>
      ) : error ? (
        <div className="card p-6 text-center">
          <p className="text-sm" style={{ color: '#ef4444' }}>{error}</p>
        </div>
      ) : !filtered.length ? (
        <div className="card p-10 flex flex-col items-center gap-3 text-center">
          <Box size={28} style={{ color: 'var(--color-text-faint)' }} />
          <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
            {search ? 'No containers match your search' : 'No container timeline data yet'}
          </p>
          <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
            Container start/stop events will be recorded here once the Docker event watcher is active.
          </p>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <div className="px-4 pt-3 pb-1">
            <XAxisLabels windowStart={data.window_start} windowEnd={data.window_end} days={days} />
          </div>
          <div className="px-4 pb-4 divide-y" style={{ divideColor: 'var(--color-border)' }}>
            {filtered.map(c => (
              <ContainerTimelineRow
                key={c.name}
                container={c}
                windowStart={data.window_start}
                windowEnd={data.window_end}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

const STATUS_EVENT_CONFIG = {
  online:  { icon: Wifi,    color: '#10b981', label: 'Came online' },
  offline: { icon: WifiOff, color: '#ef4444', label: 'Went offline' },
}

function RecentStatusHistory({ onDeviceClick, limit = 120 }) {
  const [events, setEvents] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let alive = true
    api.getStatusEvents(limit)
      .then(rows => { if (alive) setEvents(rows) })
      .catch(e => { if (alive) { setError(e.message); setEvents([]) } })
    return () => { alive = false }
  }, [limit])

  return (
    <div className="card p-4">
      <div className="flex items-center gap-2 mb-3">
        <History size={14} style={{ color: 'var(--color-brand)' }} />
        <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>
          Recent status history
        </h3>
      </div>

      {events === null ? (
        <div className="space-y-2">
          {[...Array(3)].map((_, i) => <div key={i} className="skeleton h-8 rounded-lg" />)}
        </div>
      ) : error ? (
        <p className="text-xs text-red-400">{error}</p>
      ) : events.length === 0 ? (
        <p className="text-xs text-text-muted italic">No online/offline events yet.</p>
      ) : (
        <div className="space-y-3">
          {events.map(event => {
            const cfg = STATUS_EVENT_CONFIG[event.type] || STATUS_EVENT_CONFIG.offline
            const Icon = cfg.icon
            const detail = statusDetail(event.detail)
            return (
              <div key={event.id} className="flex gap-3 items-start">
                <div
                  className="w-6 h-6 rounded-full flex items-center justify-center shrink-0"
                  style={{ background: `${cfg.color}20`, border: `1px solid ${cfg.color}40` }}
                >
                  <Icon size={11} style={{ color: cfg.color }} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="text-xs font-medium" style={{ color: 'var(--color-text)' }}>
                      {cfg.label}
                    </span>
                    <span className="text-[10px] shrink-0" style={{ color: 'var(--color-text-muted)' }}>
                      {relativeTime(event.created_at)}
                    </span>
                  </div>
                  <button
                    type="button"
                    disabled={!onDeviceClick}
                    onClick={() => onDeviceClick && onDeviceClick(event.mac_address)}
                    className="text-[11px] font-mono truncate text-left hover:underline"
                    style={{ color: onDeviceClick ? 'var(--color-brand)' : 'var(--color-text)' }}
                    title={event.display_name || event.mac_address}
                  >
                    {event.display_name || event.mac_address}
                    {event.ip_address ? ` · ${event.ip_address}` : ''}
                  </button>
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
      )}
    </div>
  )
}

export function NetworkTimeline({ onDeviceClick }) {
  const [days,    setDays]    = useState(7)
  const [data,    setData]    = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)
  const [search,  setSearch]  = useState('')
  const [view,    setView]    = useState('devices')

  const load = useCallback(async (d, { silent = false } = {}) => {
    if (!silent) setLoading(true)
    setError(null)
    try {
      const result = await api.getTimeline(d)
      setData(result)
    } catch (e) {
      setError(e.message)
    } finally {
      if (!silent) setLoading(false)
    }
  }, [])

  useEffect(() => { load(days) }, [days, load])

  // Live updates: refresh in the background when the backend signals a device
  // change (SSE), plus a slow fallback poll in case the stream drops. Both use
  // silent mode so the timeline data updates in place without a loading flash.
  useEffect(() => {
    const unsub = subscribeLive('devices', () => load(days, { silent: true }))
    const id = setInterval(() => load(days, { silent: true }), 60000)
    return () => { unsub(); clearInterval(id) }
  }, [days, load])

  function changeDays(d) {
    setDays(d)
  }

  const preparedDevices = useMemo(() => {
    if (!data?.devices) return []
    const windowStartMs = new Date(data.window_start).getTime()
    const windowEndMs = new Date(data.window_end).getTime()
    const totalMs = windowEndMs - windowStartMs
    if (totalMs <= 0) {
      return data.devices.map(d => ({ ...d, renderSegments: [], onlinePct: 0 }))
    }
    return data.devices.map(d => {
      let onlineMs = 0
      let knownMs = 0
      const renderSegments = (d.segments || []).map(seg => {
        const rawStart = new Date(seg.from).getTime()
        const rawEnd = new Date(seg.to).getTime()
        const segStart = Math.max(rawStart, windowStartMs)
        const segEnd = Math.min(rawEnd, windowEndMs)
        if (segEnd <= segStart) return null
        const dur = segEnd - segStart
        if (seg.status === 'online') onlineMs += dur
        if (seg.status !== 'unknown') knownMs += dur
        return {
          status: seg.status,
          from: seg.from,
          to: seg.to,
          leftPct: ((segStart - windowStartMs) / totalMs) * 100,
          widthPct: ((segEnd - segStart) / totalMs) * 100,
        }
      }).filter(Boolean)
      // Uptime is measured over the period the device has been known to the
      // system (since first detection), not the full selected window.
      const onlinePct = knownMs > 0 ? Math.round((onlineMs / knownMs) * 100) : 0
      return { ...d, renderSegments, onlinePct }
    })
  }, [data])

  const filtered = useMemo(() => {
    if (!preparedDevices.length) return []
    const q = search.toLowerCase()
    if (!q) return preparedDevices
    return preparedDevices.filter(d =>
      (d.name || '').toLowerCase().includes(q) ||
      (d.ip || '').includes(q) ||
      (d.mac || '').toLowerCase().includes(q)
    )
  }, [preparedDevices, search])

  const stats = useMemo(() => {
    if (!filtered.length) return null
    const total = filtered.length
    const avgUptime = Math.round(filtered.reduce((sum, d) => sum + (d.onlinePct || 0), 0) / total)
    return { total, avgUptime }
  }, [filtered])

  return (
    <div className="max-w-5xl mx-auto">

      {/* Controls row */}
      <div className="flex flex-col sm:flex-row gap-3 mb-6 items-start sm:items-center">
        {/* View toggle: Devices / Containers */}
        <div className="flex items-center gap-1 glass rounded-xl p-1">
          <button onClick={() => setView('devices')}
            className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5"
            style={view === 'devices'
              ? { background: 'var(--color-brand)', color: 'white' }
              : { color: 'var(--color-text-muted)' }}>
            <Wifi size={11} /> Devices
          </button>
          <button onClick={() => setView('containers')}
            className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5"
            style={view === 'containers'
              ? { background: 'var(--color-brand)', color: 'white' }
              : { color: 'var(--color-text-muted)' }}>
            <Box size={11} /> Containers
          </button>
        </div>

        {/* Period picker */}
        <div className="flex items-center gap-1 glass rounded-xl p-1">
          {PERIODS.map(p => (
            <button key={p.days}
              onClick={() => handlePeriodChange(p.days)}
              className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all"
              style={days === p.days
                ? { background: 'var(--color-surface-offset)', color: 'var(--color-text)' }
                : { color: 'var(--color-text-muted)' }}>
              {p.label}
            </button>
          ))}
        </div>

        {view === 'devices' && (
          <div className="relative flex-1 max-w-xs">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
              style={{ color: 'var(--color-text-muted)' }} />
            <input className="input pl-8 text-xs w-full" placeholder="Filter devices…"
              value={search} onChange={e => setSearch(e.target.value)} />
          </div>
        )}

        {view === 'devices' && stats && (
          <div className="flex items-center gap-4 text-xs" style={{ color: 'var(--color-text-muted)' }}>
            <span>{stats.total} device{stats.total !== 1 ? 's' : ''}</span>
            <span>Avg uptime: <span className="font-semibold" style={{ color: 'var(--color-text)' }}>{stats.avgUptime}%</span></span>
          </div>
        )}
      </div>

      {/* Container timeline view */}
      {view === 'containers' && <ContainerTimeline days={days} />}

      {/* Devices view below */}
      {view === 'devices' && <>

      {/* Legend */}
      <div className="flex items-center gap-4 mb-4 text-xs" style={{ color: 'var(--color-text-muted)' }}>
        <span className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded-sm inline-block" style={{ background: '#10b981', opacity: 0.85 }} />
          Online
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded-sm inline-block" style={{ background: '#ef4444', opacity: 0.85 }} />
          Offline
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded-sm inline-block" style={{ background: '#374151', opacity: 0.3 }} />
          Unknown
        </span>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <Loader size={24} className="animate-spin" style={{ color: 'var(--color-text-faint)' }} />
        </div>
      ) : error ? (
        <div className="card p-6 text-center">
          <p className="text-sm" style={{ color: '#ef4444' }}>{error}</p>
        </div>
      ) : !filtered.length ? (
        <div className="card p-10 flex flex-col items-center gap-3 text-center">
          <Clock size={28} style={{ color: 'var(--color-text-faint)' }} />
          <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
            {search ? 'No devices match your search' : 'No timeline data yet'}
          </p>
          <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
            Online/offline events will appear here once devices are active.
          </p>
        </div>
      ) : (
        <>
          <div className="card overflow-hidden">
            {/* X axis */}
            <div className="px-4 pt-3 pb-1">
              <XAxisLabels windowStart={data.window_start} windowEnd={data.window_end} days={days} />
            </div>

            {/* Device rows */}
            <div className="px-4 pb-4 divide-y" style={{ divideColor: 'var(--color-border)' }}>
              {filtered.map(device => (
                <DeviceRow
                  key={device.mac}
                  device={device}
                  onDeviceClick={onDeviceClick}
                />
              ))}
            </div>
          </div>
        </>
      )}

      </>}
    </div>
  )
}
