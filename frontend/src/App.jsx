import { useState, useMemo, useEffect, useCallback, useRef } from 'react'
import {
  Wifi, WifiOff, Monitor, ScanSearch, Settings,
  RefreshCw, Search, AlertCircle, Activity,
  LayoutGrid, List, Sun, Moon, ChevronDown,
  Bell, X, Layers, Star, ShieldAlert, Wrench,
} from 'lucide-react'
import { useDevices }          from './hooks/useDevices'
import { useTheme }            from './hooks/useTheme'
import { useSmartFilters }     from './hooks/useSmartFilters'
import { api }                 from './api'
import { Logo }                from './components/Logo'
import { StatCard }            from './components/StatCard'
import { DeviceCard }          from './components/DeviceCard'
import { DeviceRow }           from './components/DeviceRow'
import { DeviceDrawer }        from './components/DeviceDrawer'
import { SettingsPanel }       from './components/SettingsPanel'
import { SecurityDashboard }   from './components/SecurityDashboard'
import { NetworkTools }        from './components/NetworkTools'
import { CategoryView }        from './components/CategoryView'
import { SmartFilterBar }      from './components/SmartFilterBar'

const APP_VERSION = '1.0.0'

const SORT_OPTIONS = [
  { value: 'last_seen_desc', label: 'Last seen (newest)' },
  { value: 'last_seen_asc',  label: 'Last seen (oldest)' },
  { value: 'ip_asc',         label: 'IP address (asc)'   },
  { value: 'ip_desc',        label: 'IP address (desc)'  },
  { value: 'name_asc',       label: 'Name (A–Z)'    },
  { value: 'name_desc',      label: 'Name (Z–A)'    },
  { value: 'vendor_asc',     label: 'Vendor (A–Z)'  },
  { value: 'status',         label: 'Status (online first)' },
  { value: 'important',      label: 'Watched first' },
]

const TOAST_DURATION = 7000

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
    case 'important':      return copy.sort((a, b) => (b.is_important ? 1 : 0) - (a.is_important ? 1 : 0))
    default:               return copy
  }
}

function useClock() {
  const [time, setTime] = useState(() => new Date().toLocaleTimeString())
  useEffect(() => {
    const id = setInterval(() => setTime(new Date().toLocaleTimeString()), 1000)
    return () => clearInterval(id)
  }, [])
  return time
}

// ── Toast ─────────────────────────────────────────────────────────────────────────────
function Toast({ alert, kind, onDismiss, onDeviceClick }) {
  const timerRef = useRef(null)

  useEffect(() => {
    timerRef.current = setTimeout(() => onDismiss(alert.id), TOAST_DURATION)
    return () => clearTimeout(timerRef.current)
  }, [alert.id, onDismiss])

  function handleClick(e) {
    if (e.target.closest('[data-dismiss]')) return
    onDeviceClick && onDeviceClick(alert)
    onDismiss(alert.id)
  }

  const isImportant = kind === 'offline' && alert.is_important

  return (
    <div
      onClick={handleClick}
      className="flex items-start gap-3 px-4 py-3 rounded-xl shadow-lg text-sm animate-fade-in"
      style={{
        pointerEvents: 'auto',
        cursor: 'pointer',
        ...(kind === 'new' ? {
          background: 'var(--toast-new-bg)',
          border: '1px solid var(--toast-new-border)',
        } : {
          background: isImportant ? 'rgba(239,68,68,0.15)' : 'var(--toast-offline-bg)',
          border: `1px solid ${isImportant ? 'rgba(239,68,68,0.4)' : 'var(--toast-offline-border)'}`,
        }),
      }}
    >
      {kind === 'new'
        ? <Bell    size={14} style={{ color: 'var(--color-brand)', flexShrink: 0, marginTop: 2 }} />
        : <WifiOff size={14} style={{ color: '#ef4444',            flexShrink: 0, marginTop: 2 }} />
      }
      <div className="flex-1 min-w-0">
        {kind === 'new' ? (
          <>
            <p className="font-semibold" style={{ color: 'var(--color-brand)' }}>New device detected</p>
            <p className="text-xs mt-0.5 truncate" style={{ color: 'var(--color-text)' }}>
              <span className="font-mono">{alert.ip}</span>
              {(alert.hostname || alert.vendor) && <> &mdash; {alert.hostname || alert.vendor}</>}
            </p>
            <p className="mt-0.5 font-mono" style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>{alert.mac}</p>
          </>
        ) : (
          <>
            <p className="font-semibold flex items-center gap-1.5" style={{ color: '#ef4444' }}>
              {isImportant && <Star size={11} fill="currentColor" />}
              {isImportant ? 'Watched device offline' : 'Device went offline'}
            </p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--color-text)' }}>
              <span className="font-medium">{alert.name}</span>
              <span className="ml-1.5" style={{ color: 'var(--color-text-muted)' }}>{alert.ip}</span>
            </p>
          </>
        )}
        <p className="text-xs mt-1" style={{ color: 'var(--color-text-faint)', fontSize: '10px' }}>Click to view device</p>
      </div>
      <button
        data-dismiss="true"
        onClick={e => { e.stopPropagation(); onDismiss(alert.id) }}
        aria-label="Dismiss notification"
        className="opacity-50 hover:opacity-100 transition-opacity shrink-0"
        style={{ marginTop: 2 }}
      >
        <X size={13} />
      </button>
    </div>
  )
}

function NotificationToasts({ newAlerts, offlineAlerts, onDismissNew, onDismissOffline, onDeviceClick }) {
  const all = [
    ...newAlerts.map(a     => ({ ...a, kind: 'new'     })),
    ...offlineAlerts.map(a => ({ ...a, kind: 'offline' })),
  ]
  if (!all.length) return null
  return (
    <div
      className="fixed z-50 flex flex-col gap-2"
      style={{ top: '5rem', right: '1rem', width: '320px', pointerEvents: 'none' }}
    >
      {all.map(a => (
        <Toast
          key={`${a.kind}-${a.id}`}
          alert={a}
          kind={a.kind}
          onDismiss={a.kind === 'new' ? onDismissNew : onDismissOffline}
          onDeviceClick={onDeviceClick}
        />
      ))}
    </div>
  )
}

// ── Main App ────────────────────────────────────────────────────────────────────────────
export default function App() {
  // Notification state must be declared before useDevices so handleAlert can close over them
  const [notificationsEnabled,  setNotificationsEnabled]  = useState(true)
  const [browserNotifsEnabled,  setBrowserNotifsEnabled]  = useState(false)
  const [pushbulletConfigured,  setPushbulletConfigured]  = useState(false)

  const handleAlert = useCallback((alert) => {
    if (browserNotifsEnabled &&
        typeof Notification !== 'undefined' &&
        Notification.permission === 'granted') {
      const title = alert.kind === 'new_device' ? 'New device detected' : 'Device went offline'
      const body  = alert.kind === 'new_device'
        ? `${alert.ip}${alert.hostname || alert.vendor ? ' — ' + (alert.hostname || alert.vendor) : ''}`
        : alert.name || alert.ip || ''
      try { new Notification(title, { body, icon: '/favicon.svg' }) } catch {}
    }
    if (pushbulletConfigured) {
      const title = alert.kind === 'new_device' ? 'New device on network' : 'Device went offline'
      const body  = alert.kind === 'new_device'
        ? `${alert.ip}${alert.hostname || alert.vendor ? ' — ' + (alert.hostname || alert.vendor) : ''}`
        : alert.name || alert.ip || ''
      api.sendPushbullet(title, body).catch(() => {})
    }
  }, [browserNotifsEnabled, pushbulletConfigured])

  const {
    devices, stats, loading, error, refresh, lastRefresh,
    newDeviceAlerts, offlineAlerts,
    dismissNewDevice, dismissOffline,
    dismissAllNew, dismissAllOffline,
    optimisticUpdate,
  } = useDevices(10000, { onAlert: handleAlert })

  // Vuln scan state lives here so it survives DeviceDrawer close/reopen
  const [vulnScansByMac, setVulnScansByMac] = useState({})
  function updateVulnScan(mac, patchOrFn) {
    setVulnScansByMac(prev => {
      const current = { lines: [], scanning: false, ...(prev[mac] || {}) }
      const patch = typeof patchOrFn === 'function' ? patchOrFn(current) : patchOrFn
      return { ...prev, [mac]: { ...current, ...patch } }
    })
  }
  const { theme, toggle: toggleTheme } = useTheme()
  const clock = useClock()
  const { activeFilters, toggleFilter, clearFilters, applyFilters, savedViews, saveView, loadView, deleteView } = useSmartFilters()

  const [search,        setSearch]        = useState('')
  const [filter,        setFilter]        = useState('all')
  const [sort,          setSort]          = useState('last_seen_desc')
  const [layout,        setLayout]        = useState('grid')
  const [selected,         setSelected]         = useState(null)
  const [drawerInitialTab, setDrawerInitialTab] = useState('overview')
  const [showSettings,     setShowSettings]     = useState(false)
  const [showSecurity,     setShowSecurity]     = useState(false)
  const [showNetTools,     setShowNetTools]     = useState(false)
  const [refreshing,    setRefreshing]    = useState(false)
  const [showAlertDrop, setShowAlertDrop] = useState(false)

  useEffect(() => {
    api.getSettings().then(s => {
      const n  = s.find(x => x.key === 'notifications_enabled')
      const bn = s.find(x => x.key === 'browser_notifications_enabled')
      const pb = s.find(x => x.key === 'pushbullet_api_key')
      if (n)  setNotificationsEnabled(n.value === 'true')
      if (bn) setBrowserNotifsEnabled(bn.value === 'true')
      if (pb) setPushbulletConfigured((pb.value || '').trim().length > 0)
    }).catch(() => {})
  }, [])

  function handleSettingChange(key, value) {
    if (key === 'notifications_enabled')         setNotificationsEnabled(value === 'true')
    if (key === 'browser_notifications_enabled') setBrowserNotifsEnabled(value === 'true')
    if (key === 'pushbullet_api_key')            setPushbulletConfigured((value || '').trim().length > 0)
  }

  const totalAlerts = newDeviceAlerts.length

  function handleCardFilter(cardKey) {
    setFilter(prev => prev === cardKey ? 'all' : cardKey)
  }

  function handleToastDeviceClick(alert) {
    const mac = alert.mac || alert.mac_address
    if (!mac) return
    const device = devices.find(d => d.mac_address === mac)
    if (device) openDevice(device)
  }

  function openDevice(dev, tab = 'overview') {
    setDrawerInitialTab(tab)
    setSelected(dev)
  }

  // Star toggle — optimistic update then persist
  async function handleStarToggle(mac, value) {
    optimisticUpdate(mac, { is_important: value })
    try {
      const updated = await api.updateMetadata(mac, { is_important: value })
      // sync selected drawer if open
      setSelected(prev => prev?.mac_address === mac ? { ...prev, ...updated } : prev)
    } catch (e) {
      // revert on failure
      optimisticUpdate(mac, { is_important: !value })
    }
  }

  const filtered = useMemo(() => {
    let list = devices
    // Hide ignored devices unless the 'ignored' smart filter is explicitly active
    if (!activeFilters.includes('ignored')) {
      list = list.filter(d => !d.is_ignored)
    }
    // Hide virtual interfaces (macvlan/container MACs) — they appear as duplicates
    // of the physical NIC on the same host. Accessible via IP History on the real device.
    list = list.filter(d => !d.is_virtual_interface)
    if (filter === 'online')    list = list.filter(d => d.is_online)
    if (filter === 'offline')   list = list.filter(d => !d.is_online)
    if (filter === 'scanned')   list = list.filter(d => d.deep_scanned)
    if (filter === 'important') list = list.filter(d => d.is_important)
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter(d =>
        (d.ip_address   || '').toLowerCase().includes(q) ||
        (d.mac_address  || '').toLowerCase().includes(q) ||
        (d.hostname     || '').toLowerCase().includes(q) ||
        (d.custom_name  || '').toLowerCase().includes(q) ||
        (d.vendor       || '').toLowerCase().includes(q) ||
        (d.display_name || '').toLowerCase().includes(q) ||
        (d.tags         || '').toLowerCase().includes(q) ||
        (d.location     || '').toLowerCase().includes(q) ||
        (d.zone         || '').toLowerCase().includes(q)
      )
    }
    // Apply smart filters (AND logic)
    list = applyFilters(list)
    return sortDevices(list, sort)
  }, [devices, filter, search, sort, applyFilters, activeFilters])

  async function handleRefresh() {
    setRefreshing(true)
    await refresh()
    setRefreshing(false)
  }

  async function handleRename(mac, name) {
    await api.updateDevice(mac, { custom_name: name })
    await refresh()
    setSelected(d => d?.mac_address === mac
      ? { ...d, custom_name: name, display_name: name || d.hostname || d.ip_address }
      : d
    )
  }

  async function handleResolveName(mac) {
    await api.resolveName(mac)
    await refresh()
  }

  const isDark = theme === 'dark'
  const isCategoryMode = layout === 'category'
  const hasActiveSmartFilters = activeFilters.length > 0

  return (
    <div className="min-h-screen bg-bg flex flex-col transition-colors duration-200">
      <div className="noise-overlay" />
      <div className="header-glow" />

      <div className="relative z-10 flex flex-col min-h-screen">

        {/* ── Navbar ── */}
        <header className="sticky top-0 z-30 border-b border-border bg-surface/80 backdrop-blur-xl">
          <div className="max-w-[1400px] mx-auto px-4 sm:px-6 h-16 flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <Logo size={30} />
              <div>
                <span className="font-bold tracking-tight" style={{ color: 'var(--color-text)' }}>InSpectre</span>
                <span className="hidden sm:inline text-xs ml-2" style={{ color: 'var(--color-text-faint)' }}>Network Security Suite</span>
              </div>
            </div>

            <div className="flex items-center gap-1">
              <div className="hidden md:flex items-center gap-2 mr-3">
                <span className="live-ping" aria-hidden><span className="live-ping-dot" /></span>
                <span className="text-xs font-mono" style={{ color: 'var(--color-text-faint)' }}>live &middot; {clock}</span>
              </div>

              {/* Bell / alerts */}
              <div className="relative">
                <button
                  onClick={() => setShowAlertDrop(v => !v)}
                  className="btn-ghost p-2 relative"
                  aria-label={`${totalAlerts} new device alert${totalAlerts !== 1 ? 's' : ''}`}
                >
                  <Bell size={16} />
                  {totalAlerts > 0 && (
                    <span
                      className="absolute top-1 right-1 w-4 h-4 rounded-full text-[10px] font-bold
                                 flex items-center justify-center text-white"
                      style={{ background: 'var(--color-brand)' }}
                    >
                      {totalAlerts > 9 ? '9+' : totalAlerts}
                    </span>
                  )}
                </button>

                {showAlertDrop && (
                  <>
                    <div className="fixed inset-0 z-30" onClick={() => setShowAlertDrop(false)} />
                    <div
                      className="absolute right-0 top-full mt-2 w-80 rounded-xl shadow-xl z-40 p-4 space-y-3"
                      style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)' }}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--color-text-muted)' }}>Alerts</span>
                        {totalAlerts > 0 && (
                          <button onClick={() => { dismissAllNew(); setShowAlertDrop(false) }}
                            className="text-xs opacity-60 hover:opacity-100" style={{ color: 'var(--color-brand)' }}>
                            Clear all
                          </button>
                        )}
                      </div>
                      {newDeviceAlerts.length === 0 ? (
                        <p className="text-xs text-center py-4" style={{ color: 'var(--color-text-faint)' }}>No new alerts</p>
                      ) : (
                        newDeviceAlerts.map(a => (
                          <div key={a.id}
                            className="flex items-start gap-2 p-2.5 rounded-lg cursor-pointer hover:opacity-80 transition-opacity"
                            style={{ background: 'var(--color-surface-offset)' }}
                            onClick={() => { handleToastDeviceClick(a); dismissNewDevice(a.id); setShowAlertDrop(false) }}
                          >
                            <Bell size={12} className="mt-0.5 shrink-0" style={{ color: 'var(--color-brand)' }} />
                            <div className="flex-1 min-w-0">
                              <p className="text-xs font-medium" style={{ color: 'var(--color-text)' }}>
                                New device: <span className="font-mono" style={{ color: 'var(--color-brand)' }}>{a.ip}</span>
                              </p>
                              <p className="text-xs mt-0.5 truncate" style={{ color: 'var(--color-text-muted)', fontSize: '11px' }}>
                                {a.hostname || a.vendor} &middot; {a.mac}
                              </p>
                            </div>
                            <button onClick={e => { e.stopPropagation(); dismissNewDevice(a.id) }} aria-label="Dismiss"
                              className="opacity-40 hover:opacity-100 transition-opacity shrink-0 mt-0.5">
                              <X size={11} />
                            </button>
                          </div>
                        ))
                      )}
                    </div>
                  </>
                )}
              </div>

              <button onClick={handleRefresh} className="btn-ghost p-2" aria-label="Refresh">
                <RefreshCw size={16} className={refreshing ? 'animate-spin' : ''} />
              </button>
              <button onClick={toggleTheme} className="btn-ghost p-2"
                aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}>
                {isDark ? <Sun size={16} /> : <Moon size={16} />}
              </button>
              <button onClick={() => setShowNetTools(true)} className="btn-ghost p-2" aria-label="Network Tools">
                <Wrench size={16} />
              </button>
              <button onClick={() => setShowSecurity(true)} className="btn-ghost p-2" aria-label="Security overview">
                <ShieldAlert size={16} />
              </button>
              <button onClick={() => setShowSettings(true)} className="btn-ghost p-2" aria-label="Settings">
                <Settings size={16} />
              </button>
            </div>
          </div>
        </header>

        <main className="flex-1 max-w-[1400px] mx-auto w-full px-4 sm:px-6 py-8 space-y-8">

          {error && (
            <div className="flex items-center gap-3 px-4 py-3 rounded-xl text-sm"
              style={{ background: 'rgb(239 68 68 / 0.1)', border: '1px solid rgb(239 68 68 / 0.2)', color: '#ef4444' }}>
              <AlertCircle size={16} className="shrink-0" />
              {error}
            </div>
          )}

          {/* Stat cards */}
          <section>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <StatCard label="Total Devices" value={stats?.total_devices} icon={Monitor}   color="brand"
                onClick={() => handleCardFilter('all')}    active={filter === 'all'} />
              <StatCard label="Online"        value={stats?.online}        icon={Wifi}       color="emerald"
                onClick={() => handleCardFilter('online')}  active={filter === 'online'} />
              <StatCard label="Offline"       value={stats?.offline}       icon={WifiOff}    color="red"
                onClick={() => handleCardFilter('offline')} active={filter === 'offline'} />
              <StatCard label="Watched"       value={stats?.important}     icon={Star}       color="amber"
                onClick={() => handleCardFilter('important')} active={filter === 'important'} />
            </div>
          </section>

          {/* Search / filter / sort / layout row */}
          <section className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center">
            <div className="relative flex-1">
              <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
                style={{ color: 'var(--color-text-muted)' }} />
              <input className="input pl-9" placeholder="Search IP, MAC, hostname, vendor, tags…"
                value={search} onChange={e => setSearch(e.target.value)} />
            </div>

            {!isCategoryMode && (
              <div className="relative">
                <select value={sort} onChange={e => setSort(e.target.value)}
                  className="input pr-8 appearance-none cursor-pointer" aria-label="Sort devices">
                  {SORT_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
                <ChevronDown size={14} className="absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none"
                  style={{ color: 'var(--color-text-muted)' }} />
              </div>
            )}

            <div className="flex items-center gap-1 glass rounded-xl p-1">
              <button onClick={() => setLayout('grid')}
                className="p-2 rounded-lg transition-all duration-150"
                style={layout === 'grid' ? { background: 'var(--color-brand)', color: 'white' } : { color: 'var(--color-text-muted)' }}
                aria-label="Grid layout">
                <LayoutGrid size={15} /></button>
              <button onClick={() => setLayout('list')}
                className="p-2 rounded-lg transition-all duration-150"
                style={layout === 'list' ? { background: 'var(--color-brand)', color: 'white' } : { color: 'var(--color-text-muted)' }}
                aria-label="List layout">
                <List size={15} /></button>
              <button onClick={() => setLayout('category')}
                className="p-2 rounded-lg transition-all duration-150"
                style={layout === 'category' ? { background: 'var(--color-brand)', color: 'white' } : { color: 'var(--color-text-muted)' }}
                aria-label="Category view">
                <Layers size={15} /></button>
            </div>
          </section>

          {/* Smart filter bar */}
          <section>
            <SmartFilterBar
              devices={devices}
              activeFilters={activeFilters}
              onToggle={toggleFilter}
              onClear={clearFilters}
              savedViews={savedViews}
              onSaveView={saveView}
              onLoadView={loadView}
              onDeleteView={deleteView}
            />
          </section>

          {/* Device list */}
          <section>
            {loading ? (
              <SkeletonGrid layout={layout === 'category' ? 'grid' : layout} />
            ) : filtered.length === 0 ? (
              <EmptyState search={search} filter={filter} hasSmartFilters={hasActiveSmartFilters} onClearSmartFilters={clearFilters} />
            ) : isCategoryMode ? (
              <>
                <p className="text-xs mb-4" style={{ color: 'var(--color-text-faint)' }}>
                  Showing {filtered.length} of {devices.length} device{devices.length !== 1 ? 's' : ''} &middot; grouped by device type
                </p>
                <CategoryView devices={filtered} layout="grid" onDeviceClick={openDevice} />
              </>
            ) : (
              <>
                <p className="text-xs mb-4" style={{ color: 'var(--color-text-faint)' }}>
                  Showing {filtered.length} of {devices.length} device{devices.length !== 1 ? 's' : ''}
                  {filter !== 'all' && (
                    <span className="ml-2 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase"
                      style={{ background: 'var(--color-brand)', color: 'white' }}>{filter}</span>
                  )}
                  {hasActiveSmartFilters && (
                    <span className="ml-2 px-2 py-0.5 rounded-full text-[10px] font-semibold"
                      style={{ background: 'var(--color-surface-offset)', color: 'var(--color-text-muted)' }}>
                      + smart filters
                    </span>
                  )}
                </p>
                {layout === 'grid' ? (
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                    {filtered.map(d => (
                      <DeviceCard key={d.mac_address} device={d}
                        onClick={() => openDevice(d)}
                        onStarToggle={handleStarToggle}
                        isVulnScanning={vulnScansByMac[d.mac_address]?.scanning || false}
                      />
                    ))}
                  </div>
                ) : (
                  <div className="card overflow-hidden">
                    <div
                      className="grid grid-cols-[1.5rem_2fr_1fr_1fr_1fr_6rem_2rem] gap-4 px-4 py-2.5 border-b
                                 text-xs font-semibold uppercase tracking-wider"
                      style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}
                    >
                      <span /><span>Name / IP</span><span>MAC</span><span>Vendor</span>
                      <span>Last Seen</span><span>Status</span><span />
                    </div>
                    {filtered.map((d, i) => (
                      <DeviceRow key={d.mac_address} device={d} onClick={() => openDevice(d)}
                        striped={i % 2 === 1} onStarToggle={handleStarToggle}
                        isVulnScanning={vulnScansByMac[d.mac_address]?.scanning || false} />
                    ))}
                  </div>
                )}
              </>
            )}
          </section>

        </main>

        <footer className="border-t py-4" style={{ borderColor: 'var(--color-border)' }}>
          <div className="max-w-[1400px] mx-auto px-4 sm:px-6 flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-3 text-xs" style={{ color: 'var(--color-text-faint)' }}>
              <span>InSpectre &copy; {new Date().getFullYear()}</span>
              <span style={{ color: 'var(--color-border)' }}>|</span>
              <span>v{APP_VERSION}</span>
              <span style={{ color: 'var(--color-border)' }}>|</span>
              <span>Developed by{' '}
                <a href="mailto:inspectre@thefunkygibbon.net" style={{ color: 'var(--color-brand)' }}
                  className="hover:underline">thefunkygibbon</a>
              </span>
            </div>
            <div className="flex items-center gap-1.5 text-xs" style={{ color: '#10b981' }}>
              <Activity size={12} />
              <span>API connected</span>
            </div>
          </div>
        </footer>
      </div>

      {notificationsEnabled && (
        <NotificationToasts
          newAlerts={newDeviceAlerts}
          offlineAlerts={offlineAlerts}
          onDismissNew={dismissNewDevice}
          onDismissOffline={dismissOffline}
          onDeviceClick={handleToastDeviceClick}
        />
      )}

      {selected && (
        <DeviceDrawer
          key={selected.mac_address}
          device={selected}
          onClose={() => setSelected(null)}
          onRename={handleRename}
          onResolveName={handleResolveName}
          onRefresh={refresh}
          onStarToggle={handleStarToggle}
          onMetadataUpdate={async (mac, patch) => {
            const updated = await api.updateMetadata(mac, patch)
            setSelected(prev => prev?.mac_address === mac ? { ...prev, ...updated } : prev)
            await refresh()
          }}
          onZoneChange={(zone) => setSelected(prev => prev?.mac_address === selected.mac_address ? { ...prev, zone } : prev)}
          vulnScanState={vulnScansByMac[selected.mac_address] || { lines: [], scanning: false }}
          onVulnScanChange={(patchOrFn) => updateVulnScan(selected.mac_address, patchOrFn)}
          initialTab={drawerInitialTab}
        />
      )}
      {showNetTools && (
        <NetworkTools onClose={() => setShowNetTools(false)} />
      )}
      {showSettings && (
        <SettingsPanel onClose={() => setShowSettings(false)} onSettingChange={handleSettingChange} />
      )}
      {showSecurity && (
        <SecurityDashboard
          onClose={() => setShowSecurity(false)}
          onDeviceClick={(mac, tab) => {
            setShowSecurity(false)
            const dev = devices.find(d => d.mac_address === mac)
            if (dev) openDevice(dev, tab || 'overview')
          }}
        />
      )}
    </div>
  )
}

function SkeletonGrid({ layout }) {
  if (layout === 'list') {
    return (
      <div className="card overflow-hidden">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="grid grid-cols-[1.5rem_2fr_1fr_1fr_1fr_6rem] gap-4 px-4 py-3 border-b last:border-0"
            style={{ borderColor: 'var(--color-border)' }}>
            <div className="skeleton w-2.5 h-2.5 rounded-full mt-1" />
            <div className="skeleton h-4 w-3/4" />
            <div className="skeleton h-4 w-4/5" />
            <div className="skeleton h-4 w-2/3" />
            <div className="skeleton h-4 w-3/5" />
            <div className="skeleton h-5 w-16 rounded-full" />
          </div>
        ))}
      </div>
    )
  }
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
      {[...Array(8)].map((_, i) => (
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

function EmptyState({ search, filter, hasSmartFilters, onClearSmartFilters }) {
  return (
    <div className="flex flex-col items-center text-center py-24 gap-4">
      <div className="w-16 h-16 rounded-2xl flex items-center justify-center"
        style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)' }}>
        <Monitor size={28} style={{ color: 'var(--color-text-muted)' }} />
      </div>
      <div>
        <h3 className="font-semibold" style={{ color: 'var(--color-text)' }}>
          {search ? 'No matches found' : filter !== 'all' ? `No ${filter} devices` : 'No devices yet'}
        </h3>
        <p className="text-sm mt-1 max-w-xs" style={{ color: 'var(--color-text-muted)' }}>
          {search ? 'Try a different search term' : 'The probe will discover devices on the next ARP sweep'}
        </p>
        {hasSmartFilters && (
          <button onClick={onClearSmartFilters}
            className="mt-3 text-xs px-3 py-1.5 rounded-full border transition-colors"
            style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}>
            Clear smart filters
          </button>
        )}
      </div>
    </div>
  )
}
