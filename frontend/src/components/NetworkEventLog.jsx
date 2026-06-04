import { useState, useEffect, useMemo } from 'react'
import { Loader, Wifi, WifiOff, History, Search, X, Clock } from 'lucide-react'
import { api } from '../api'
import { subscribeLive } from '../lib/liveEvents'

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

const EVENT_CONFIG = {
  online:  { icon: Wifi,    color: '#10b981', label: 'Came online' },
  offline: { icon: WifiOff, color: '#ef4444', label: 'Went offline' },
}

const LIMITS = [
  { value: 50,   label: '50 events' },
  { value: 120,  label: '120 events' },
  { value: 300,  label: '300 events' },
  { value: 1000, label: '1000 events' },
]

export function NetworkEventLog({ onDeviceClick }) {
  const [events, setEvents] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const [limit, setLimit] = useState(120)
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')   // 'all' | 'online' | 'offline'
  const [sourceFilter, setSourceFilter] = useState('all') // 'all' | source key

  useEffect(() => {
    let alive = true
    setLoading(true)
    setError(null)
    api.getStatusEvents(limit)
      .then(rows => {
        if (alive) {
          setEvents(rows)
          setLoading(false)
        }
      })
      .catch(e => {
        if (alive) {
          setError(e.message)
          setEvents([])
          setLoading(false)
        }
      })
    return () => { alive = false }
  }, [limit])

  // Live refresh on device events, with a slow fallback poll.
  useEffect(() => {
    const refresh = () => api.getStatusEvents(limit).then(rows => setEvents(rows)).catch(() => {})
    const unsub = subscribeLive('devices', refresh)
    const id = setInterval(refresh, 60000)
    return () => { clearInterval(id); unsub() }
  }, [limit])

  // Collect unique sources from all events for source filter chips
  const availableSources = useMemo(() => {
    if (!events) return []
    const seen = new Set()
    events.forEach(e => {
      let detail = e.detail
      if (typeof detail === 'string') { try { detail = JSON.parse(detail) } catch { detail = null } }
      const src = detail?.source || null
      if (src) seen.add(src)
    })
    return Array.from(seen).sort()
  }, [events])

  const filtered = useMemo(() => {
    if (!events) return []
    return events.filter(e => {
      // Type filter
      if (typeFilter !== 'all' && e.type !== typeFilter) return false
      // Source filter
      if (sourceFilter !== 'all') {
        let detail = e.detail
        if (typeof detail === 'string') { try { detail = JSON.parse(detail) } catch { detail = null } }
        const src = detail?.source || null
        if (src !== sourceFilter) return false
      }
      // Text search
      if (search.trim()) {
        const q = search.toLowerCase()
        if (!(e.display_name || '').toLowerCase().includes(q) &&
            !(e.mac_address || '').toLowerCase().includes(q) &&
            !(e.ip_address || '').includes(q)) return false
      }
      return true
    })
  }, [events, search, typeFilter, sourceFilter])

  const stats = useMemo(() => {
    if (!filtered.length) return null
    const onlineCount = filtered.filter(e => e.type === 'online').length
    const offlineCount = filtered.filter(e => e.type === 'offline').length
    return { total: filtered.length, online: onlineCount, offline: offlineCount }
  }, [filtered])

  const FilterChip = ({ active, onClick, children }) => (
    <button onClick={onClick}
      className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all"
      style={active
        ? { background: 'var(--color-surface-offset)', color: 'var(--color-text)' }
        : { color: 'var(--color-text-muted)' }}>
      {children}
    </button>
  )

  return (
    <div className="max-w-4xl mx-auto">
      {/* Header with controls */}
      <div className="flex flex-col gap-3 mb-5">

        {/* Row 1: limit + search */}
        <div className="flex flex-col sm:flex-row gap-3 items-start sm:items-center">
          <div className="flex items-center gap-1 glass rounded-xl p-1">
            {LIMITS.map(l => (
              <button key={l.value}
                onClick={() => setLimit(l.value)}
                className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all"
                style={limit === l.value
                  ? { background: 'var(--color-surface-offset)', color: 'var(--color-text)' }
                  : { color: 'var(--color-text-muted)' }}>
                {l.label}
              </button>
            ))}
          </div>

          <div className="relative flex-1 max-w-xs">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
              style={{ color: 'var(--color-text-muted)' }} />
            <input className="input pl-8 text-xs w-full" placeholder="Filter by device…"
              value={search} onChange={e => setSearch(e.target.value)} />
            {search && (
              <button onClick={() => setSearch('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-0.5 transition-colors hover:opacity-70"
                style={{ color: 'var(--color-text-muted)' }} aria-label="Clear search">
                <X size={13} />
              </button>
            )}
          </div>
        </div>

        {/* Row 2: smart filters */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Type filter */}
          <div className="flex items-center gap-1 glass rounded-xl p-1">
            <FilterChip active={typeFilter === 'all'} onClick={() => setTypeFilter('all')}>All types</FilterChip>
            <FilterChip active={typeFilter === 'online'} onClick={() => setTypeFilter('online')}>
              <span className="flex items-center gap-1"><Wifi size={10} style={{ color: '#10b981' }} />Online</span>
            </FilterChip>
            <FilterChip active={typeFilter === 'offline'} onClick={() => setTypeFilter('offline')}>
              <span className="flex items-center gap-1"><WifiOff size={10} style={{ color: '#ef4444' }} />Offline</span>
            </FilterChip>
          </div>

          {/* Source filter — only shown when multiple sources exist */}
          {availableSources.length > 1 && (
            <div className="flex items-center gap-1 glass rounded-xl p-1">
              <FilterChip active={sourceFilter === 'all'} onClick={() => setSourceFilter('all')}>All sources</FilterChip>
              {availableSources.map(src => (
                <FilterChip key={src} active={sourceFilter === src} onClick={() => setSourceFilter(src)}>
                  {formatSource(src)}
                </FilterChip>
              ))}
            </div>
          )}

          {/* Stats */}
          {stats && (
            <div className="flex items-center gap-4 ml-auto text-xs" style={{ color: 'var(--color-text-muted)' }}>
              <span>{stats.total} event{stats.total !== 1 ? 's' : ''}</span>
              {typeFilter === 'all' && (
                <>
                  <span className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full" style={{ background: '#10b981' }} />
                    {stats.online}
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full" style={{ background: '#ef4444' }} />
                    {stats.offline}
                  </span>
                </>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Events */}
      <div className="card p-6">
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <Loader size={24} className="animate-spin" style={{ color: 'var(--color-text-faint)' }} />
          </div>
        ) : error ? (
          <div className="text-center py-10">
            <p className="text-sm" style={{ color: '#ef4444' }}>{error}</p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center gap-3 py-16 text-center">
            <Clock size={32} style={{ color: 'var(--color-text-faint)' }} />
            <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
              {search || typeFilter !== 'all' || sourceFilter !== 'all' ? 'No events match your filters' : 'No events recorded yet'}
            </p>
            <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
              Online/offline events will appear here as devices connect and disconnect
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {filtered.map(event => {
              const cfg = EVENT_CONFIG[event.type] || EVENT_CONFIG.offline
              const Icon = cfg.icon
              let parsedDetail = event.detail
              if (typeof parsedDetail === 'string') { try { parsedDetail = JSON.parse(parsedDetail) } catch { parsedDetail = null } }
              const detail = statusDetail(parsedDetail)
              return (
                <div key={event.id} className="flex gap-3 items-start">
                  <div
                    className="w-8 h-8 rounded-full flex items-center justify-center shrink-0"
                    style={{ background: `${cfg.color}20`, border: `1px solid ${cfg.color}40` }}
                  >
                    <Icon size={13} style={{ color: cfg.color }} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-baseline justify-between gap-2">
                      <span className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>
                        {cfg.label}
                      </span>
                      <span className="text-xs shrink-0" style={{ color: 'var(--color-text-muted)' }}>
                        {relativeTime(event.created_at)}
                      </span>
                    </div>
                    <button
                      type="button"
                      disabled={!onDeviceClick}
                      onClick={() => onDeviceClick && onDeviceClick(event.mac_address)}
                      className="text-xs font-mono truncate text-left hover:underline mt-0.5"
                      style={{ color: onDeviceClick ? 'var(--color-brand)' : 'var(--color-text)' }}
                      title={event.display_name || event.mac_address}
                    >
                      {event.display_name || event.mac_address}
                      {event.ip_address ? ` · ${event.ip_address}` : ''}
                    </button>
                    {detail && (
                      <p className="text-xs mt-1 font-mono" style={{ color: 'var(--color-text-muted)' }}>
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
    </div>
  )
}
