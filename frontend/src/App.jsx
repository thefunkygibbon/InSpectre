import { useState, useMemo } from 'react'
import {
  Wifi, WifiOff, Monitor, ScanSearch, Settings,
  RefreshCw, Search, Filter, AlertCircle, CheckCircle2,
} from 'lucide-react'
import { useDevices } from './hooks/useDevices'
import { api } from './api'
import { Logo }           from './components/Logo'
import { StatCard }       from './components/StatCard'
import { DeviceCard }     from './components/DeviceCard'
import { DeviceDrawer }   from './components/DeviceDrawer'
import { SettingsPanel }  from './components/SettingsPanel'

const FILTERS = ['all', 'online', 'offline']

export default function App() {
  const { devices, stats, loading, error, refresh, lastRefresh } = useDevices(10000)
  const [search, setSearch]             = useState('')
  const [filter, setFilter]             = useState('all')
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
        (d.ip_address  || '').toLowerCase().includes(q) ||
        (d.mac_address || '').toLowerCase().includes(q) ||
        (d.hostname    || '').toLowerCase().includes(q) ||
        (d.custom_name || '').toLowerCase().includes(q) ||
        (d.vendor      || '').toLowerCase().includes(q)
      )
    }
    return list
  }, [devices, filter, search])

  async function handleRefresh() {
    setRefreshing(true)
    await refresh()
    setRefreshing(false)
  }

  async function handleRename(mac, name) {
    await api.updateDevice(mac, { custom_name: name })
    await refresh()
    setSelected(d => d?.mac_address === mac ? { ...d, custom_name: name } : d)
  }

  const lastRefreshStr = lastRefresh ? lastRefresh.toLocaleTimeString() : null

  return (
    <div className="min-h-screen bg-gray-950 flex flex-col">
      {/* Noise texture overlay - class defined in index.css */}
      <div className="noise-overlay" />

      {/* Ambient glow */}
      <div className="fixed top-0 left-1/2 -translate-x-1/2 w-[600px] h-[300px] bg-brand-900/20 blur-[120px] rounded-full pointer-events-none z-0" />

      <div className="relative z-10 flex flex-col min-h-screen">

        {/* ── Navbar ─────────────────────────────────────────── */}
        <header className="sticky top-0 z-30 border-b border-white/5 bg-gray-950/80 backdrop-blur-xl">
          <div className="max-w-[1400px] mx-auto px-4 sm:px-6 h-16 flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <Logo size={32} />
              <div>
                <span className="font-bold text-gray-100 tracking-tight">InSpectre</span>
                <span className="hidden sm:inline text-xs text-gray-600 ml-2">Network Security Suite</span>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {lastRefreshStr && (
                <span className="hidden md:block text-xs text-gray-600">Updated {lastRefreshStr}</span>
              )}
              <button onClick={handleRefresh} className="btn-ghost p-2" aria-label="Refresh">
                <RefreshCw size={16} className={refreshing ? 'animate-spin' : ''} />
              </button>
              <button onClick={() => setShowSettings(true)} className="btn-ghost p-2" aria-label="Settings">
                <Settings size={16} />
              </button>
            </div>
          </div>
        </header>

        <main className="flex-1 max-w-[1400px] mx-auto w-full px-4 sm:px-6 py-8 space-y-8">

          {/* Error banner */}
          {error && (
            <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-sm animate-slide-up">
              <AlertCircle size={16} className="shrink-0" />
              {error}
            </div>
          )}

          {/* ── Stat cards ──────────────────────────────────── */}
          <section>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <StatCard label="Total Devices" value={stats?.total_devices} icon={Monitor}   color="brand"   />
              <StatCard label="Online"        value={stats?.online}        icon={Wifi}       color="emerald" />
              <StatCard label="Offline"       value={stats?.offline}       icon={WifiOff}    color="red"     />
              <StatCard label="Deep Scanned"  value={stats?.deep_scanned}  icon={ScanSearch} color="amber"   />
            </div>
          </section>

          {/* ── Toolbar ─────────────────────────────────────── */}
          <section className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center">
            <div className="relative flex-1">
              <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500 pointer-events-none" />
              <input
                className="input pl-9"
                placeholder="Search by IP, MAC, hostname, vendor…"
                value={search}
                onChange={e => setSearch(e.target.value)}
              />
            </div>
            <div className="flex items-center gap-1 glass rounded-xl p-1">
              <Filter size={13} className="text-gray-600 ml-2" />
              {FILTERS.map(f => (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium capitalize transition-all duration-150 ${
                    filter === f
                      ? 'bg-brand-600 text-white'
                      : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>
          </section>

          {/* ── Device grid ─────────────────────────────────── */}
          <section>
            {loading ? (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                {[...Array(8)].map((_, i) => <SkeletonCard key={i} />)}
              </div>
            ) : filtered.length === 0 ? (
              <EmptyState search={search} filter={filter} />
            ) : (
              <>
                <p className="text-xs text-gray-600 mb-4">
                  Showing {filtered.length} of {devices.length} device{devices.length !== 1 ? 's' : ''}
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                  {filtered.map(d => (
                    <DeviceCard key={d.mac_address} device={d} onClick={() => setSelected(d)} />
                  ))}
                </div>
              </>
            )}
          </section>

        </main>

        {/* Footer */}
        <footer className="border-t border-white/5 py-4">
          <div className="max-w-[1400px] mx-auto px-4 sm:px-6 flex items-center justify-between">
            <span className="text-xs text-gray-700">InSpectre &copy; {new Date().getFullYear()}</span>
            <div className="flex items-center gap-1.5 text-xs text-emerald-600">
              <CheckCircle2 size={12} />
              <span>API connected</span>
            </div>
          </div>
        </footer>
      </div>

      {/* ── Drawers ─────────────────────────────────────────── */}
      {selected && (
        <DeviceDrawer
          device={selected}
          onClose={() => setSelected(null)}
          onRename={handleRename}
        />
      )}
      {showSettings && (
        <SettingsPanel onClose={() => setShowSettings(false)} />
      )}
    </div>
  )
}

function SkeletonCard() {
  return (
    <div className="card p-5 flex flex-col gap-4 animate-pulse">
      <div className="flex items-center gap-2">
        <div className="w-2.5 h-2.5 rounded-full bg-gray-800" />
        <div className="h-4 w-32 bg-gray-800 rounded-lg" />
      </div>
      <div className="grid grid-cols-2 gap-2">
        <div className="h-3 bg-gray-800 rounded" />
        <div className="h-3 bg-gray-800 rounded" />
      </div>
      <div className="h-px bg-gray-800/50" />
      <div className="h-3 w-24 bg-gray-800 rounded" />
    </div>
  )
}

function EmptyState({ search, filter }) {
  return (
    <div className="flex flex-col items-center text-center py-24 gap-4 animate-fade-in">
      <div className="w-16 h-16 rounded-2xl bg-gray-900 border border-white/5 flex items-center justify-center">
        <Monitor size={28} className="text-gray-700" />
      </div>
      <div>
        <h3 className="font-semibold text-gray-300">
          {search ? 'No matches found' : filter !== 'all' ? `No ${filter} devices` : 'No devices yet'}
        </h3>
        <p className="text-sm text-gray-600 mt-1 max-w-xs">
          {search
            ? 'Try a different search term'
            : 'The probe will discover devices automatically on the next ARP sweep'}
        </p>
      </div>
    </div>
  )
}
