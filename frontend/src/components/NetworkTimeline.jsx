import { useState, useEffect, useCallback, useMemo } from 'react'
import { Loader, Wifi, WifiOff, Clock, Search } from 'lucide-react'
import { api } from '../api'

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

function StatusDot({ status }) {
  const colors = { online: '#10b981', offline: '#ef4444', unknown: '#6b7280' }
  return (
    <span className="inline-block w-2 h-2 rounded-full shrink-0"
      style={{ background: colors[status] || colors.unknown }} />
  )
}

function TimelineBar({ segments, windowStart, windowEnd, deviceName }) {
  const totalMs = new Date(windowEnd) - new Date(windowStart)
  if (totalMs <= 0) return null

  const STATUS_COLORS = {
    online:  '#10b981',
    offline: '#ef4444',
    unknown: '#374151',
  }

  return (
    <div className="flex-1 h-6 rounded overflow-hidden flex" style={{ background: 'var(--color-surface-offset)' }}>
      {segments.map((seg, i) => {
        const segStart = new Date(seg.from)
        const segEnd   = new Date(seg.to)
        const pct = Math.max(0.1, ((segEnd - segStart) / totalMs) * 100)
        const color = STATUS_COLORS[seg.status] || STATUS_COLORS.unknown
        return (
          <div key={i}
            title={`${deviceName}: ${seg.status} from ${fmtDateTime(seg.from)} to ${fmtDateTime(seg.to)}`}
            className="h-full transition-opacity hover:opacity-80 cursor-default"
            style={{ width: `${pct}%`, background: color, opacity: seg.status === 'unknown' ? 0.3 : 0.85 }}
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

function DeviceRow({ device, windowStart, windowEnd, days, onDeviceClick }) {
  const onlinePct = useMemo(() => {
    const totalMs = new Date(windowEnd) - new Date(windowStart)
    if (totalMs <= 0) return 0
    const onlineMs = device.segments
      .filter(s => s.status === 'online')
      .reduce((sum, s) => sum + (new Date(s.to) - new Date(s.from)), 0)
    return Math.round((onlineMs / totalMs) * 100)
  }, [device.segments, windowStart, windowEnd])

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

      <TimelineBar
        segments={device.segments}
        windowStart={windowStart}
        windowEnd={windowEnd}
        deviceName={device.name}
      />

      <div className="w-[70px] sm:w-[80px] text-right shrink-0">
        <span className="text-[10px] font-mono tabular-nums"
          style={{ color: onlinePct >= 90 ? '#10b981' : onlinePct >= 50 ? '#f59e0b' : '#ef4444' }}>
          {onlinePct}% up
        </span>
      </div>
    </div>
  )
}

export function NetworkTimeline({ onDeviceClick }) {
  const [days,    setDays]    = useState(7)
  const [data,    setData]    = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)
  const [search,  setSearch]  = useState('')

  const load = useCallback(async (d) => {
    setLoading(true)
    setError(null)
    try {
      const result = await api.getTimeline(d)
      setData(result)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load(days) }, [days, load])

  function handlePeriodChange(d) {
    setDays(d)
  }

  const filtered = useMemo(() => {
    if (!data?.devices) return []
    const q = search.toLowerCase()
    if (!q) return data.devices
    return data.devices.filter(d =>
      (d.name || '').toLowerCase().includes(q) ||
      (d.ip || '').includes(q) ||
      (d.mac || '').toLowerCase().includes(q)
    )
  }, [data, search])

  const stats = useMemo(() => {
    if (!filtered.length || !data) return null
    const total = filtered.length
    const avgUptime = Math.round(
      filtered.reduce((sum, d) => {
        const totalMs = new Date(data.window_end) - new Date(data.window_start)
        if (totalMs <= 0) return sum
        const onlineMs = d.segments
          .filter(s => s.status === 'online')
          .reduce((s2, s) => s2 + (new Date(s.to) - new Date(s.from)), 0)
        return sum + (onlineMs / totalMs) * 100
      }, 0) / total
    )
    return { total, avgUptime }
  }, [filtered, data])

  return (
    <div className="max-w-5xl mx-auto">

      {/* Controls row */}
      <div className="flex flex-col sm:flex-row gap-3 mb-6 items-start sm:items-center">
        <div className="flex items-center gap-1 glass rounded-xl p-1">
          {PERIODS.map(p => (
            <button key={p.days}
              onClick={() => handlePeriodChange(p.days)}
              className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all"
              style={days === p.days
                ? { background: 'var(--color-brand)', color: 'white' }
                : { color: 'var(--color-text-muted)' }}>
              {p.label}
            </button>
          ))}
        </div>

        <div className="relative flex-1 max-w-xs">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
            style={{ color: 'var(--color-text-muted)' }} />
          <input className="input pl-8 text-xs w-full" placeholder="Filter devices…"
            value={search} onChange={e => setSearch(e.target.value)} />
        </div>

        {stats && (
          <div className="flex items-center gap-4 text-xs" style={{ color: 'var(--color-text-muted)' }}>
            <span>{stats.total} device{stats.total !== 1 ? 's' : ''}</span>
            <span>Avg uptime: <span className="font-semibold" style={{ color: 'var(--color-text)' }}>{stats.avgUptime}%</span></span>
          </div>
        )}
      </div>

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
                windowStart={data.window_start}
                windowEnd={data.window_end}
                days={days}
                onDeviceClick={onDeviceClick}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
