import { useState, useEffect, useCallback, useMemo } from 'react'
import { Box, RefreshCw, Search, AlertCircle, Play, Square, Loader2, LayoutGrid, List } from 'lucide-react'
import { api } from '../api'
import { ContainerCard } from './ContainerCard'
import { ContainerDrawer } from './ContainerDrawer'
import { StatCard } from './StatCard'

const STOPPED_STATES = ['exited', 'created', 'dead']

const STATUS_FILTERS = [
  { value: 'all',        label: 'All' },
  { value: 'running',    label: 'Running' },
  { value: 'stopped',    label: 'Stopped' },
  { value: 'paused',     label: 'Paused' },
  { value: 'restarting', label: 'Restarting' },
]

const STATUS_COLOR = {
  running:    '#22c55e',
  exited:     '#6b7280',
  created:    '#8b5cf6',
  dead:       '#ef4444',
  paused:     '#f59e0b',
  restarting: '#3b82f6',
}
const STATUS_LABEL = {
  running: 'Running', exited: 'Stopped', created: 'Created',
  dead: 'Dead', paused: 'Paused', restarting: 'Restarting',
}

function SkeletonCards() {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
      {[...Array(6)].map((_, i) => (
        <div key={i} className="device-card p-5 flex flex-col gap-3">
          <div className="flex items-center gap-2.5">
            <div className="skeleton w-8 h-8 rounded-lg" />
            <div className="skeleton h-4 w-28 rounded" />
          </div>
          <div className="grid grid-cols-2 gap-2">
            {[...Array(4)].map((_, j) => <div key={j} className="skeleton h-3 rounded" />)}
          </div>
          <div className="skeleton h-px w-full" />
          <div className="skeleton h-3 w-20 rounded" />
        </div>
      ))}
    </div>
  )
}

function DisabledState() {
  return (
    <div className="flex flex-col items-center text-center py-24 gap-4">
      <div className="w-16 h-16 rounded-2xl flex items-center justify-center"
        style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)' }}>
        <Box size={28} style={{ color: 'var(--color-text-muted)' }} />
      </div>
      <div>
        <h3 className="font-semibold" style={{ color: 'var(--color-text)' }}>No container hosts configured</h3>
        <p className="text-sm mt-1 max-w-xs" style={{ color: 'var(--color-text-muted)' }}>
          Add a Docker or Proxmox host in <strong>Settings → Docker</strong> to start monitoring containers.
        </p>
      </div>
    </div>
  )
}

function EmptyState({ search, filter }) {
  return (
    <div className="flex flex-col items-center text-center py-24 gap-4">
      <div className="w-16 h-16 rounded-2xl flex items-center justify-center"
        style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)' }}>
        <Box size={28} style={{ color: 'var(--color-text-muted)' }} />
      </div>
      <div>
        <h3 className="font-semibold" style={{ color: 'var(--color-text)' }}>
          {search ? 'No matches' : filter !== 'all' ? `No ${filter} containers` : 'No containers found'}
        </h3>
        <p className="text-sm mt-1" style={{ color: 'var(--color-text-muted)' }}>
          {search ? 'Try a different search term' : 'No Docker containers were found on the configured host.'}
        </p>
      </div>
    </div>
  )
}

function ContainerRow({ container, onClick }) {
  const color = STATUS_COLOR[container.status] || '#6b7280'
  const label = STATUS_LABEL[container.status] || container.status
  const portStr = (container.ports || [])
    .filter(p => p.host_port)
    .map(p => `${p.host_port}→${p.container_port}`)
    .slice(0, 3).join(', ')

  return (
    <div
      onClick={onClick}
      className="flex items-center gap-3 px-4 py-3 rounded-xl border transition-all cursor-pointer hover:opacity-90"
      style={{ background: 'var(--color-surface)', borderColor: 'var(--color-border)' }}>
      {/* Status dot */}
      <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: color }} />

      {/* Name */}
      <span className="font-medium text-sm truncate min-w-0 w-36" style={{ color: 'var(--color-text)' }}>
        {container.name}
      </span>

      {/* Status label */}
      <span className="text-xs font-medium w-20 shrink-0" style={{ color }}>
        {label}
      </span>

      {/* Image */}
      <span className="text-xs font-mono truncate flex-1 min-w-0" style={{ color: 'var(--color-text-muted)' }}>
        {container.image.replace(/^.*\//, '').replace(/:latest$/, '')}
      </span>

      {/* Ports */}
      <span className="text-xs font-mono hidden md:block w-36 shrink-0 truncate" style={{ color: 'var(--color-text-faint)' }}>
        {portStr || '—'}
      </span>

      {/* Networks */}
      <span className="text-xs hidden lg:block w-28 shrink-0 truncate" style={{ color: 'var(--color-text-faint)' }}>
        {(container.networks || []).join(', ') || '—'}
      </span>

      {/* Host */}
      <span className="text-xs hidden xl:block w-28 shrink-0 truncate" style={{ color: 'var(--color-text-faint)' }}>
        {container.host_name || '—'}
      </span>

      {/* Uptime */}
      <span className="text-xs hidden sm:block w-24 shrink-0 text-right" style={{ color: 'var(--color-text-faint)' }}>
        {container.uptime || '—'}
      </span>
    </div>
  )
}

export function ContainersPage({ openContainer }) {
  const [containers,  setContainers]  = useState([])
  const [stats,       setStats]       = useState(null)
  const [loading,     setLoading]     = useState(true)
  const [error,       setError]       = useState(null)
  const [disabled,    setDisabled]    = useState(false)
  const [selected,    setSelected]    = useState(null)
  const [search,      setSearch]      = useState('')
  const [filter,      setFilter]      = useState('all')
  const [hostFilter,  setHostFilter]  = useState('all')
  const [layout,      setLayout]      = useState('grid')
  const [refreshing,  setRefreshing]  = useState(false)

  // Vuln scan state keyed by container ID — persists across drawer open/close
  const [trivyScansByContainer, setTrivyScansByContainer] = useState({})
  function updateTrivyScan(containerId, patchOrFn) {
    setTrivyScansByContainer(prev => {
      const cur = prev[containerId] || { logs: [], vulns: null, scanning: false, scannedAt: null }
      const patch = typeof patchOrFn === 'function' ? patchOrFn(cur) : patchOrFn
      return { ...prev, [containerId]: { ...cur, ...patch } }
    })
  }

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    else setRefreshing(true)
    setError(null)
    setDisabled(false)
    try {
      const [statsData, containerList] = await Promise.all([
        api.dockerStats(),
        api.dockerContainers(),
      ])
      setStats(statsData)
      setContainers(containerList)
    } catch (e) {
      if (e.message?.includes('503') || e.message?.toLowerCase().includes('disabled')) {
        setDisabled(true)
      } else {
        setError(e.message || 'Failed to connect to Docker.')
      }
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  useEffect(() => {
    const id = setInterval(() => load(true), 15000)
    return () => clearInterval(id)
  }, [load])

  // Open a specific container's drawer on the vuln tab (used from SecurityDashboard)
  useEffect(() => {
    if (!openContainer) return
    const found = containers.find(c => c.name === openContainer)
    if (found) {
      setSelected(found)
    }
  }, [openContainer, containers])

  function handleContainerUpdate(updated) {
    setContainers(prev => prev.map(c => c.id === updated.id ? updated : c))
    setSelected(updated)
  }

  const hostOptions = useMemo(() => {
    const seen = new Map()
    for (const c of containers) {
      if (c.host_id && c.host_name && !seen.has(c.host_id)) {
        seen.set(c.host_id, { id: c.host_id, name: c.host_name })
      }
    }
    return [...seen.values()]
  }, [containers])

  const filtered = containers.filter(c => {
    if (hostFilter !== 'all' && c.host_id !== hostFilter) return false
    if (filter === 'stopped' && !STOPPED_STATES.includes(c.status)) return false
    if (filter !== 'all' && filter !== 'stopped' && c.status !== filter) return false
    if (search.trim()) {
      const q = search.toLowerCase()
      return c.name.toLowerCase().includes(q)
          || c.image.toLowerCase().includes(q)
          || c.short_id.toLowerCase().includes(q)
          || (c.networks || []).some(n => n.toLowerCase().includes(q))
    }
    return true
  })

  return (
    <div className="space-y-8">

      {/* Stat cards */}
      {stats && (
        <section>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard label="Total"     value={stats.total}     icon={Box}     color="brand"
              onClick={() => setFilter('all')}      active={filter === 'all'} />
            <StatCard label="Running"   value={stats.running}   icon={Play}    color="emerald"
              onClick={() => setFilter('running')}  active={filter === 'running'} />
            <StatCard label="Stopped"   value={stats.stopped}   icon={Square}  color="red"
              onClick={() => setFilter('stopped')}  active={filter === 'stopped'} />
            <StatCard label="Other"     value={(stats.paused || 0) + (stats.restarting || 0)} icon={Loader2} color="amber"
              onClick={() => setFilter('all')} active={false} />
          </div>
          {stats.docker_version && (
            <p className="text-xs mt-2" style={{ color: 'var(--color-text-faint)' }}>
              Docker {stats.docker_version} &middot; API {stats.api_version}
            </p>
          )}
        </section>
      )}

      {/* Error */}
      {error && (
        <div className="flex items-center gap-3 px-4 py-3 rounded-xl text-sm"
          style={{ background: 'rgb(239 68 68 / 0.1)', border: '1px solid rgb(239 68 68 / 0.2)', color: '#ef4444' }}>
          <AlertCircle size={16} className="shrink-0" />
          {error}
        </div>
      )}

      {/* Toolbar */}
      {!disabled && !loading && (
        <section className="flex flex-wrap gap-2 items-center">
          <div className="relative" style={{ minWidth: '160px', flex: '1 1 160px', maxWidth: '340px' }}>
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
              style={{ color: 'var(--color-text-muted)' }} />
            <input className="input pl-9 w-full" placeholder="Search containers…"
              value={search} onChange={e => setSearch(e.target.value)} />
          </div>

          <div className="flex items-center gap-1 flex-wrap">
            {STATUS_FILTERS.map(f => (
              <button key={f.value}
                onClick={() => setFilter(f.value)}
                className="px-3 py-1.5 rounded-xl text-xs font-medium border transition-colors"
                style={filter === f.value
                  ? { background: 'var(--color-brand)', color: 'white', borderColor: 'transparent' }
                  : { background: 'var(--color-surface-offset)', color: 'var(--color-text-muted)', borderColor: 'var(--color-border)' }}>
                {f.label}
              </button>
            ))}
          </div>

          {hostOptions.length > 1 && (
            <div className="flex items-center gap-1 flex-wrap">
              <span className="text-[10px] font-semibold uppercase tracking-wider mr-1" style={{ color: 'var(--color-text-faint)' }}>Host:</span>
              <button
                onClick={() => setHostFilter('all')}
                className="px-3 py-1.5 rounded-xl text-xs font-medium border transition-colors"
                style={hostFilter === 'all'
                  ? { background: 'var(--color-brand)', color: 'white', borderColor: 'transparent' }
                  : { background: 'var(--color-surface-offset)', color: 'var(--color-text-muted)', borderColor: 'var(--color-border)' }}>
                All
              </button>
              {hostOptions.map(h => (
                <button key={h.id}
                  onClick={() => setHostFilter(h.id)}
                  className="px-3 py-1.5 rounded-xl text-xs font-medium border transition-colors"
                  style={hostFilter === h.id
                    ? { background: 'var(--color-brand)', color: 'white', borderColor: 'transparent' }
                    : { background: 'var(--color-surface-offset)', color: 'var(--color-text-muted)', borderColor: 'var(--color-border)' }}>
                  {h.name}
                </button>
              ))}
            </div>
          )}

          <div className="ml-auto flex items-center gap-1">
            {/* Layout toggle */}
            <button onClick={() => setLayout('grid')} className="btn-ghost p-2"
              title="Grid view" aria-label="Grid view"
              style={{ color: layout === 'grid' ? 'var(--color-brand)' : undefined }}>
              <LayoutGrid size={15} />
            </button>
            <button onClick={() => setLayout('list')} className="btn-ghost p-2"
              title="List view" aria-label="List view"
              style={{ color: layout === 'list' ? 'var(--color-brand)' : undefined }}>
              <List size={15} />
            </button>
            <button onClick={() => load(true)} disabled={refreshing}
              className="btn-ghost p-2" title="Refresh" aria-label="Refresh containers">
              <RefreshCw size={15} className={refreshing ? 'animate-spin' : ''} />
            </button>
          </div>
        </section>
      )}

      {/* Content */}
      {loading ? (
        <SkeletonCards />
      ) : disabled ? (
        <DisabledState />
      ) : filtered.length === 0 ? (
        <EmptyState search={search} filter={filter} />
      ) : (
        <section>
          <p className="text-xs mb-4" style={{ color: 'var(--color-text-faint)' }}>
            Showing {filtered.length} of {containers.length} container{containers.length !== 1 ? 's' : ''}
            {filter !== 'all' && (
              <span className="ml-2 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase"
                style={{ background: 'var(--color-brand)', color: 'white' }}>{filter}</span>
            )}
          </p>

          {layout === 'grid' ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
              {filtered.map(c => (
                <ContainerCard key={c.id} container={c} onClick={() => setSelected(c)} />
              ))}
            </div>
          ) : (
            <div className="space-y-1.5">
              {/* List header */}
              <div className="hidden md:flex items-center gap-3 px-4 pb-1 text-[10px] font-semibold uppercase tracking-wider"
                style={{ color: 'var(--color-text-faint)' }}>
                <span className="w-2.5 shrink-0" />
                <span className="w-36">Name</span>
                <span className="w-20">Status</span>
                <span className="flex-1">Image</span>
                <span className="w-36 hidden md:block">Ports</span>
                <span className="w-28 hidden lg:block">Networks</span>
                <span className="w-28 hidden xl:block">Host</span>
                <span className="w-24 text-right hidden sm:block">Uptime</span>
              </div>
              {filtered.map(c => (
                <ContainerRow key={c.id} container={c} onClick={() => setSelected(c)} />
              ))}
            </div>
          )}
        </section>
      )}

      {selected && (
        <ContainerDrawer
          key={selected.id}
          container={selected}
          trivyScan={trivyScansByContainer[selected.id] || { logs: [], vulns: null, scanning: false, scannedAt: null }}
          updateTrivyScan={patch => updateTrivyScan(selected.id, patch)}
          initialTab={openContainer && openContainer === selected.name ? 'vuln' : undefined}
          onClose={() => setSelected(null)}
          onContainerUpdate={handleContainerUpdate}
        />
      )}
    </div>
  )
}
