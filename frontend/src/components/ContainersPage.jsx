import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { Box, RefreshCw, Search, AlertCircle, Play, Square, Loader2, LayoutGrid, List, ArrowUpDown, ShieldAlert, Network, GitBranch, X, Sparkles } from 'lucide-react'
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

const SORT_OPTIONS = [
  { value: 'name-asc',  label: 'Name (A → Z)' },
  { value: 'name-desc', label: 'Name (Z → A)' },
  { value: 'status',    label: 'Status' },
  { value: 'host',      label: 'Host' },
  { value: 'newest',    label: 'Newest First' },
]

const STATUS_SORT_ORDER = ['running', 'restarting', 'paused', 'created', 'exited', 'dead']

const NEW_CONTAINER_DAYS = 7
function isNewContainer(c) {
  if (!c.created) return false
  return Date.now() - new Date(c.created).getTime() < NEW_CONTAINER_DAYS * 24 * 60 * 60 * 1000
}

function loadAcknowledgedContainers() {
  try { return new Set(JSON.parse(localStorage.getItem('inspectre_ack_containers') || '[]')) }
  catch { return new Set() }
}
function saveAcknowledgedContainers(s) {
  localStorage.setItem('inspectre_ack_containers', JSON.stringify([...s]))
}

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

function ContainerRow({ container, onClick, isAcknowledged, onAcknowledge }) {
  const color    = STATUS_COLOR[container.status] || '#6b7280'
  const label    = STATUS_LABEL[container.status] || container.status
  const showNew  = isNewContainer(container) && !isAcknowledged
  const portStr  = (container.ports || [])
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

      {/* NEW badge */}
      {showNew && (
        <span className="hidden sm:inline-flex items-center gap-0.5 text-[10px] font-bold rounded-full px-2 py-0.5 shrink-0"
          style={{ color: '#10b981', background: 'rgba(16,185,129,0.12)', border: '1px solid rgba(16,185,129,0.35)' }}>
          NEW
          {onAcknowledge && (
            <button
              onClick={e => { e.stopPropagation(); onAcknowledge(container.id) }}
              className="opacity-60 hover:opacity-100 transition-opacity ml-0.5"
              title="Acknowledge — stop surfacing to top"
              aria-label="Acknowledge new container"
            >
              <X size={8} />
            </button>
          )}
        </span>
      )}

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

export function ContainersPage({ openContainer, skin }) {
  const [containers,    setContainers]    = useState([])
  const [stats,         setStats]         = useState(null)
  const [vulnSummary,   setVulnSummary]   = useState([])
  const [loading,       setLoading]       = useState(true)
  const [error,         setError]         = useState(null)
  const [disabled,      setDisabled]      = useState(false)
  const [selected,      setSelected]      = useState(null)
  const [search,        setSearch]        = useState('')
  const [filter,        setFilter]        = useState('all')
  const [smartFilters,  setSmartFilters]  = useState({})
  const [hostFilter,    setHostFilter]    = useState('all')
  const [sort,          setSort]          = useState('name-asc')
  const [layout,        setLayout]        = useState('grid')
  const [refreshing,    setRefreshing]    = useState(false)
  const [surfaceNewFirst,    setSurfaceNewFirst]    = useState(() => localStorage.getItem('inspectre_containers_surface_new') !== 'false')
  const [acknowledgedContainers, setAcknowledgedContainers] = useState(loadAcknowledgedContainers)

  // Vuln scan state keyed by container ID — persists across drawer open/close
  const [trivyScansByContainer, setTrivyScansByContainer] = useState({})
  function updateTrivyScan(containerId, patchOrFn) {
    setTrivyScansByContainer(prev => {
      const cur = prev[containerId] || { logs: [], vulns: null, scanning: false, scannedAt: null }
      const patch = typeof patchOrFn === 'function' ? patchOrFn(cur) : patchOrFn
      return { ...prev, [containerId]: { ...cur, ...patch } }
    })
  }

  function acknowledgeContainer(id) {
    setAcknowledgedContainers(prev => {
      const next = new Set(prev)
      next.add(id)
      saveAcknowledgedContainers(next)
      return next
    })
  }

  function toggleSurfaceNewFirst() {
    setSurfaceNewFirst(prev => {
      const next = !prev
      localStorage.setItem('inspectre_containers_surface_new', String(next))
      return next
    })
  }

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    else setRefreshing(true)
    setError(null)
    setDisabled(false)
    try {
      const [statsData, containerList, vulnData] = await Promise.all([
        api.dockerStats(),
        api.dockerContainers(),
        api.dockerVulnSummary().catch(() => []),
      ])
      setStats(statsData)
      setContainers(containerList)
      setVulnSummary(Array.isArray(vulnData) ? vulnData : [])
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

  // Open a specific container's drawer on the vuln tab (used from SecurityDashboard).
  // consumed ref prevents containers auto-refresh from re-opening a drawer the user closed.
  const openContainerConsumed = useRef(false)
  useEffect(() => { openContainerConsumed.current = false }, [openContainer])
  useEffect(() => {
    if (!openContainer || openContainerConsumed.current) return
    const found = containers.find(c => c.name === openContainer)
    if (found) {
      setSelected(found)
      openContainerConsumed.current = true
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

  const vulnNameSet = useMemo(() => {
    const s = new Set()
    for (const v of vulnSummary) {
      if (v.severity && v.severity !== 'clean') s.add(v.name)
    }
    return s
  }, [vulnSummary])

  const filtered = containers.filter(c => {
    if (hostFilter !== 'all' && c.host_id !== hostFilter) return false
    if (filter === 'stopped' && !STOPPED_STATES.includes(c.status)) return false
    if (filter === 'other' && !['paused', 'restarting'].includes(c.status)) return false
    if (filter !== 'all' && filter !== 'stopped' && filter !== 'other' && c.status !== filter) return false
    const _sfMatch = {
      vulnerable: () => vulnNameSet.has(c.name),
      host_net:   () => (c.networks || []).includes('host'),
      bridge_net: () => (c.networks || []).includes('bridge'),
    }
    for (const [key, mode] of Object.entries(smartFilters)) {
      const fn = _sfMatch[key]
      if (!fn) continue
      if (mode === 'include' && !fn()) return false
      if (mode === 'exclude' &&  fn()) return false
    }
    if (search.trim()) {
      const q = search.toLowerCase().trim()
      const portMatch = q.match(/^port:(\d+)$/)
      if (portMatch) {
        const portNum = portMatch[1]
        return (c.ports || []).some(p =>
          String(p.host_port) === portNum || String(p.container_port?.split('/')[0]) === portNum
        )
      }
      return c.name.toLowerCase().includes(q)
          || c.image.toLowerCase().includes(q)
          || c.short_id.toLowerCase().includes(q)
          || (c.networks || []).some(n => n.toLowerCase().includes(q))
    }
    return true
  })

  const sortedBase = [...filtered].sort((a, b) => {
    switch (sort) {
      case 'name-desc': return b.name.localeCompare(a.name)
      case 'status': {
        const ai = STATUS_SORT_ORDER.indexOf(a.status)
        const bi = STATUS_SORT_ORDER.indexOf(b.status)
        if (ai !== bi) return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi)
        return a.name.localeCompare(b.name)
      }
      case 'host':
        return (a.host_name || '').localeCompare(b.host_name || '') || a.name.localeCompare(b.name)
      case 'newest': {
        const at = a.state?.started_at || ''
        const bt = b.state?.started_at || ''
        if (at && bt) return bt.localeCompare(at)
        if (at) return -1
        if (bt) return 1
        return a.name.localeCompare(b.name)
      }
      default:
        return a.name.localeCompare(b.name)
    }
  })

  const sorted = surfaceNewFirst
    ? [
        ...sortedBase.filter(c => isNewContainer(c) && !acknowledgedContainers.has(c.id)),
        ...sortedBase.filter(c => !isNewContainer(c) || acknowledgedContainers.has(c.id)),
      ]
    : sortedBase

  return (
    <div className="space-y-8">

      {/* Stat cards */}
      {stats && (
        <section>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard label="Total Containers"    value={stats.total}     icon={Box}     color="brand"
              onClick={() => setFilter('all')}      active={filter === 'all'} />
            <StatCard label="Running Containers"   value={stats.running}   icon={Play}    color="emerald"
              onClick={() => setFilter('running')}  active={filter === 'running'} />
            <StatCard label="Stopped Containers"   value={stats.stopped}   icon={Square}  color="red"
              onClick={() => setFilter('stopped')}  active={filter === 'stopped'} />
            <StatCard label="Paused / Restarting"  value={(stats.paused || 0) + (stats.restarting || 0)} icon={Loader2} color="amber"
              onClick={() => setFilter(filter === 'other' ? 'all' : 'other')} active={filter === 'other'} />
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
            {search && (
              <button onClick={() => setSearch('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-0.5 transition-colors hover:opacity-70"
                style={{ color: 'var(--color-text-muted)' }} aria-label="Clear search">
                <X size={13} />
              </button>
            )}
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

          {/* Smart filters — click to cycle: off → include (green) → exclude (red) → off */}
          <div className="flex items-center gap-1 flex-wrap">
            {[
              { key: 'vulnerable',  label: 'Vulnerable',     icon: ShieldAlert },
              { key: 'host_net',    label: 'Host Network',   icon: Network },
              { key: 'bridge_net',  label: 'Bridge Network', icon: GitBranch },
            ].map(({ key, label, icon: Icon }) => {
              const state = smartFilters[key] || null
              const style = state === 'include'
                ? { background: 'rgba(34,197,94,0.18)',  color: '#22c55e', borderColor: 'rgba(34,197,94,0.45)' }
                : state === 'exclude'
                  ? { background: 'rgba(239,68,68,0.15)', color: '#ef4444', borderColor: 'rgba(239,68,68,0.4)' }
                  : { background: 'var(--color-surface-offset)', color: 'var(--color-text-muted)', borderColor: 'var(--color-border)' }
              return (
                <button key={key}
                  onClick={() => setSmartFilters(prev => {
                    const cur = prev[key]
                    if (!cur)              return { ...prev, [key]: 'include' }
                    if (cur === 'include') return { ...prev, [key]: 'exclude' }
                    const next = { ...prev }; delete next[key]; return next
                  })}
                  title={state ? `${label}: ${state} — click to cycle` : `${label}: off — click to include`}
                  className="flex items-center gap-1 px-3 py-1.5 rounded-xl text-xs font-medium border transition-colors"
                  style={style}>
                  <Icon size={11} />
                  {label}{state && <span className="ml-0.5 opacity-70 text-[10px]">{state === 'include' ? '✓' : '✕'}</span>}
                </button>
              )
            })}
            {Object.keys(smartFilters).length > 0 && (
              <button onClick={() => setSmartFilters({})}
                className="px-2 py-1.5 rounded-xl text-xs border transition-colors"
                style={{ color: 'var(--color-text-faint)', borderColor: 'var(--color-border)', background: 'transparent' }}>
                Clear
              </button>
            )}
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
            {/* Surface new first toggle */}
            <button
              onClick={toggleSurfaceNewFirst}
              title={surfaceNewFirst ? 'New containers surfaced to top (click to disable)' : 'New containers not surfaced (click to enable)'}
              className="flex items-center gap-1 px-2.5 py-1.5 rounded-xl text-xs font-medium border transition-colors"
              style={surfaceNewFirst
                ? { background: 'rgba(16,185,129,0.12)', color: '#10b981', borderColor: 'rgba(16,185,129,0.35)' }
                : { background: 'var(--color-surface-offset)', color: 'var(--color-text-faint)', borderColor: 'var(--color-border)' }}
            >
              <Sparkles size={11} />
              <span>New first</span>
            </button>
            {/* Sort */}
            <div className="flex items-center gap-1 mr-1">
              <ArrowUpDown size={13} style={{ color: 'var(--color-text-faint)' }} />
              <select className="input text-xs py-1" value={sort} onChange={e => setSort(e.target.value)}>
                {SORT_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>
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
      ) : sorted.length === 0 ? (
        <EmptyState search={search} filter={filter} />
      ) : (
        <section>
          <p className="text-xs mb-4" style={{ color: 'var(--color-text-faint)' }}>
            Showing {sorted.length} of {containers.length} container{containers.length !== 1 ? 's' : ''}
            {filter !== 'all' && (
              <span className="ml-2 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase"
                style={{ background: 'var(--color-brand)', color: 'white' }}>{filter}</span>
            )}
          </p>

          {layout === 'grid' ? (
            <div className={`grid gap-4 grid-cols-1 sm:grid-cols-2 ${skin === 'phantom' ? 'xl:grid-cols-3' : 'lg:grid-cols-3 xl:grid-cols-4'}`}>
              {sorted.map(c => (
                <ContainerCard key={c.id} container={c} onClick={() => setSelected(c)}
                  isAcknowledged={acknowledgedContainers.has(c.id)}
                  isTrivyScanning={trivyScansByContainer[c.id]?.scanning || false}
                  onAcknowledge={acknowledgeContainer} />
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
              {sorted.map(c => (
                <ContainerRow key={c.id} container={c} onClick={() => setSelected(c)}
                  isAcknowledged={acknowledgedContainers.has(c.id)}
                  onAcknowledge={acknowledgeContainer} />
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
