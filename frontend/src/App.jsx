import { useState, useMemo } from 'react'
import {
  Wifi, WifiOff, Monitor, ScanSearch, Settings,
  RefreshCw, Search, Filter, AlertCircle, CheckCircle2,
  LayoutGrid, List, Sun, Moon, ChevronDown,
} from 'lucide-react'
import { useDevices } from './hooks/useDevices'
import { useTheme }   from './hooks/useTheme'
import { api }        from './api'
import { Logo }           from './components/Logo'
import { StatCard }       from './components/StatCard'
import { DeviceCard }     from './components/DeviceCard'
import { DeviceRow }      from './components/DeviceRow'
import { DeviceDrawer }   from './components/DeviceDrawer'
import { SettingsPanel }  from './components/SettingsPanel'

const FILTERS = ['all', 'online', 'offline']

const SORT_OPTIONS = [
  { value: 'last_seen_desc', label: 'Last seen (newest)' },
  { value: 'last_seen_asc',  label: 'Last seen (oldest)' },
  { value: 'ip_asc',         label: 'IP address (asc)'   },
  { value: 'ip_desc',        label: 'IP address (desc)'  },
  { value: 'name_asc',       label: 'Name (A–Z)'         },
  { value: 'name_desc',      label: 'Name (Z–A)'         },
  { value: 'vendor_asc',     label: 'Vendor (A–Z)'       },
  { value: 'status',         label: 'Status (online first)' },
]

function ipToNum(ip) {
  if (!ip) return 0
  return ip.split('.').reduce((acc, o) => (acc << 8) + parseInt(o, 10), 0) >>> 0
}

function sortDevices(list, sort) {
  const copy = [...list]
  switch (sort) {
    case 'last_seen_asc':  return copy.sort((a, b) => new Date(a.last_seen) - new Date(b.last_seen))
    case 'last_seen_desc': return copy.sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen))
    case 'ip_asc':         return copy.sort((a, b) => ipToNum(a.ip_address) - ipToNum(b.ip_address))
    case 'ip_desc':        return copy.sort((a, b) => ipToNum(b.ip_address) - ipToNum(a.ip_address))
    case 'name_asc':       return copy.sort((a, b) => (a.display_name||'').localeCompare(b.display_name||''))
    case 'name_desc':      return copy.sort((a, b) => (b.display_name||'').localeCompare(a.display_name||''))
    case 'vendor_asc':     return copy.sort((a, b) => (a.vendor||'').localeCompare(b.vendor||''))
    case 'status':         return copy.sort((a, b) => (b.is_online ? 1 : 0) - (a.is_online ? 1 : 0))
    default:               return copy
  }
}

export default function App() {
  const { devices, stats, loading, error, refresh, lastRefresh } = useDevices(10000)
  const { theme, toggle: toggleTheme } = useTheme()

  const [search, setSearch]             = useState('')
  const [filter, setFilter]             = useState('all')
  const [sort, setSort]                 = useState('last_seen_desc')
  const [layout, setLayout]             = useState('grid')   // 'grid' | 'list'
  const [selected, setSelected]         = useState(null)
  const [showSettings, setShowSettings] = useState(false)
  const [refreshing, setRefreshing]     = useState(false)

  const filtered = useMemo(() => {
    let list = devices
    if (filter === 'online')  list = list.filter(d => d.is_online)
    if (filter === 'offline') list = list.filter(d => !d.is_online)
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter(d =>
        (d.ip_address    || '').toLowerCase().includes(q) ||
        (d.mac_address   || '').toLowerCase().includes(q) ||
        (d.hostname      || '').toLowerCase().includes(q) ||
        (d.custom_name   || '').toLowerCase().includes(q) ||
        (d.vendor        || '').toLowerCase().includes(q) ||
        (d.display_name  || '').toLowerCase().includes(q)
      )
    }
    return sortDevices(list, sort)
  }, [devices, filter, search, sort])

  async function handleRefresh() {
    setRefreshing(true)
    await refresh()
    setRefreshing(false)
  }

  async function handleRename(mac, name) {
    await api.updateDevice(mac, { custom_name: name })
    await refresh()
    setSelected(d => d?.mac_address === mac ? { ...d, custom_name: name, display_name: name || d.hostname || d.ip_address } : d)
  }

  async function handleResolveName(mac) {
    await api.resolveName(mac)
    await refresh()
  }

  const lastRefreshStr = lastRefresh ? lastRefresh.toLocaleTimeString() : null
  const isDark = theme === 'dark'

  return (
    <div className="min-h-screen bg-bg flex flex-col transition-colors duration-200">
      <div className="noise-overlay" />
      <div className="fixed top-0 left-1/2 -translate-x-1/2 w-[600px] h-[300px] bg-brand/10 blur-[120px] rounded-full pointer-events-none z-0" />

      <div className="relative z-10 flex flex-col min-h-screen">

        {/* ── Navbar ── */}
        <header className="sticky top-0 z-30 border-b border-border bg-surface/80 backdrop-blur-xl">
          <div className="max-w-[1400px] mx-auto px-4 sm:px-6 h-16 flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <Logo size={32} />
              <div>
                <span className="font-bold text-text tracking-tight">InSpectre</span>
                <span className="hidden sm:inline text-xs text-text-muted ml-2">Network Security Suite</span>
              </div>
            </div>
            <div className="flex items-center gap-1">
              {lastRefreshStr && (
                <span className="hidden md:block text-xs text-text-muted mr-2">Updated {lastRefreshStr}</span>
              )}
              <button onClick={handleRefresh} className="btn-ghost p-2" aria-label="Refresh">
                <RefreshCw size={16} className={refreshing ? 'animate-spin' : ''} />
              </button>
              <button
                onClick={toggleTheme}
                className="btn-ghost p-2"
                aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
              >
                {isDark ? <Sun size={16} /> : <Moon size={16} />}
              </button>
              <button onClick={() => setShowSettings(true)} className="btn-ghost p-2" aria-label="Settings">
                <Settings size={16} />
              </button>
            </div>
          </div>
        </header>

        <main className="flex-1 max-w-[1400px] mx-auto w-full px-4 sm:px-6 py-8 space-y-8">

          {error && (
            <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
              <AlertCircle size={16} className="shrink-0" />
              {error}
            </div>
          )}

          {/* Stat cards */}
          <section>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <StatCard label="Total Devices" value={stats?.total_devices} icon={Monitor}   color="brand"   />
              <StatCard label="Online"        value={stats?.online}        icon={Wifi}       color="emerald" />
              <StatCard label="Offline"       value={stats?.offline}       icon={WifiOff}    color="red"     />
              <StatCard label="Deep Scanned"  value={stats?.deep_scanned}  icon={ScanSearch} color="amber"   />
            </div>
          </section>

          {/* Toolbar */}
          <section className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center">
            {/* Search */}
            <div className="relative flex-1">
              <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted pointer-events-none" />
              <input
                className="input pl-9"
                placeholder="Search IP, MAC, hostname, vendor…"
                value={search}
                onChange={e => setSearch(e.target.value)}
              />
            </div>

            {/* Filter pills */}
            <div className="flex items-center gap-1 glass rounded-xl p-1">
              <Filter size={13} className="text-text-muted ml-2" />
              {FILTERS.map(f => (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium capitalize transition-all duration-150 ${
                    filter === f ? 'bg-brand text-white' : 'text-text-muted hover:text-text hover:bg-surface-hover'
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>

            {/* Sort dropdown */}
            <div className="relative">
              <select
                value={sort}
                onChange={e => setSort(e.target.value)}
                className="input pr-8 appearance-none cursor-pointer"
                aria-label="Sort devices"
              >
                {SORT_OPTIONS.map(o => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
              <ChevronDown size={14} className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted pointer-events-none" />
            </div>

            {/* Layout toggle */}
            <div className="flex items-center gap-1 glass rounded-xl p-1">
              <button
                onClick={() => setLayout('grid')}
                className={`p-2 rounded-lg transition-all duration-150 ${
                  layout === 'grid' ? 'bg-brand text-white' : 'text-text-muted hover:text-text hover:bg-surface-hover'
                }`}
                aria-label="Grid layout"
              >
                <LayoutGrid size={15} />
              </button>
              <button
                onClick={() => setLayout('list')}
                className={`p-2 rounded-lg transition-all duration-150 ${
                  layout === 'list' ? 'bg-brand text-white' : 'text-text-muted hover:text-text hover:bg-surface-hover'
                }`}
                aria-label="List layout"
              >
                <List size={15} />
              </button>
            </div>
          </section>

          {/* Device grid / list */}
          <section>
            {loading ? (
              <SkeletonGrid layout={layout} />
            ) : filtered.length === 0 ? (
              <EmptyState search={search} filter={filter} />
            ) : (
              <>
                <p className="text-xs text-text-muted mb-4">
                  Showing {filtered.length} of {devices.length} device{devices.length !== 1 ? 's' : ''}
                </p>
                {layout === 'grid' ? (
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                    {filtered.map(d => (
                      <DeviceCard key={d.mac_address} device={d} onClick={() => setSelected(d)} />
                    ))}
                  </div>
                ) : (
                  <div className="card overflow-hidden">
                    {/* List header */}
                    <div className="grid grid-cols-[1.5rem_2fr_1fr_1fr_1fr_6rem] gap-4 px-4 py-2.5 border-b border-border text-xs font-semibold text-text-muted uppercase tracking-wider">
                      <span></span>
                      <span>Name / IP</span>
                      <span>MAC</span>
                      <span>Vendor</span>
                      <span>Last Seen</span>
                      <span>Status</span>
                    </div>
                    {filtered.map((d, i) => (
                      <DeviceRow
                        key={d.mac_address}
                        device={d}
                        onClick={() => setSelected(d)}
                        striped={i % 2 === 1}
                      />
                    ))}
                  </div>
                )}
              </>
            )}
          </section>

        </main>

        <footer className="border-t border-border py-4">
          <div className="max-w-[1400px] mx-auto px-4 sm:px-6 flex items-center justify-between">
            <span className="text-xs text-text-muted">InSpectre &copy; {new Date().getFullYear()}</span>
            <div className="flex items-center gap-1.5 text-xs text-emerald-500">
              <CheckCircle2 size={12} />
              <span>API connected</span>
            </div>
          </div>
        </footer>
      </div>

      {selected && (
        <DeviceDrawer
          device={selected}
          onClose={() => setSelected(null)}
          onRename={handleRename}
          onResolveName={handleResolveName}
        />
      )}
      {showSettings && (
        <SettingsPanel onClose={() => setShowSettings(false)} />
      )}
    </div>
  )
}

function SkeletonGrid({ layout }) {
  if (layout === 'list') {
    return (
      <div className="card overflow-hidden">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="grid grid-cols-[1.5rem_2fr_1fr_1fr_1fr_6rem] gap-4 px-4 py-3 border-b border-border last:border-0 animate-pulse">
            <div className="w-2.5 h-2.5 rounded-full bg-surface-offset mt-1" />
            <div className="h-4 bg-surface-offset rounded w-3/4" />
            <div className="h-4 bg-surface-offset rounded w-4/5" />
            <div className="h-4 bg-surface-offset rounded w-2/3" />
            <div className="h-4 bg-surface-offset rounded w-3/5" />
            <div className="h-5 bg-surface-offset rounded-full w-16" />
          </div>
        ))}
      </div>
    )
  }
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
      {[...Array(8)].map((_, i) => (
        <div key={i} className="card p-5 flex flex-col gap-4 animate-pulse">
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-surface-offset" />
            <div className="h-4 w-32 bg-surface-offset rounded-lg" />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="h-3 bg-surface-offset rounded" />
            <div className="h-3 bg-surface-offset rounded" />
          </div>
          <div className="h-px bg-surface-offset/50" />
          <div className="h-3 w-24 bg-surface-offset rounded" />
        </div>
      ))}
    </div>
  )
}

function EmptyState({ search, filter }) {
  return (
    <div className="flex flex-col items-center text-center py-24 gap-4">
      <div className="w-16 h-16 rounded-2xl bg-surface border border-border flex items-center justify-center">
        <Monitor size={28} className="text-text-muted" />
      </div>
      <div>
        <h3 className="font-semibold text-text">
          {search ? 'No matches found' : filter !== 'all' ? `No ${filter} devices` : 'No devices yet'}
        </h3>
        <p className="text-sm text-text-muted mt-1 max-w-xs">
          {search ? 'Try a different search term' : 'The probe will discover devices on the next ARP sweep'}
        </p>
      </div>
    </div>
  )
}
