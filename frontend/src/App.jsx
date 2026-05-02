import { useState, useMemo, useEffect, useCallback, useRef } from 'react'
import {
  Wifi, WifiOff, Monitor, Settings,
  Search, AlertCircle, Activity,
  LayoutGrid, List, Sun, Moon, ChevronDown,
  Bell, X, Layers, Star, ShieldAlert, Wrench, Ban, BarChart2,
  ArrowLeft, SlidersHorizontal, LogOut, Eye, EyeOff,
} from 'lucide-react'
import { TrafficPage } from './components/TrafficPage'
import { useDevices }          from './hooks/useDevices'
import { useTheme }            from './hooks/useTheme'
import { useSmartFilters }     from './hooks/useSmartFilters'
import { api, getToken, clearToken } from './api'
import { Logo }                from './components/Logo'
import { StatCard }            from './components/StatCard'
import { DeviceCard }          from './components/DeviceCard'
import { DeviceRow }           from './components/DeviceRow'
import { DeviceDrawer }        from './components/DeviceDrawer'
import { SettingsPanel }       from './components/SettingsPanel'
import { SecurityDashboard }   from './components/SecurityDashboard'
import { NetworkTools }        from './components/NetworkTools'
import { DeviceBlocking }      from './components/DeviceBlocking'
import { NetworkTimeline }     from './components/NetworkTimeline'
import { CategoryView }        from './components/CategoryView'
import { SmartFilterBar }      from './components/SmartFilterBar'
import { LoginPage }           from './components/LoginPage'
import { SetupWizard }         from './components/SetupWizard'
import { StatusButton }        from './components/StatusButton'

const APP_VERSION = '1.1.0'

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

// Page definitions for the nav
const PAGES = [
  { id: 'tools',    label: 'Network Tools',       Icon: Wrench,     title: 'Network Tools' },
  { id: 'security', label: 'Vulnerability Report', Icon: ShieldAlert, title: 'Vulnerability Report' },
  { id: 'blocking', label: 'Device Blocking',      Icon: Ban,        title: 'Device Blocking' },
  { id: 'timeline', label: 'Device Timeline',      Icon: BarChart2,  title: 'Device Timeline' },
  { id: 'traffic',  label: 'Traffic Monitor',      Icon: Activity,   title: 'Traffic Monitor' },
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
function MainApp({ onLogout }) {
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
    devices, stats, loading, error, refresh,
    newDeviceAlerts, offlineAlerts,
    dismissNewDevice, dismissOffline,
    dismissAllNew, dismissAllOffline,
    optimisticUpdate,
  } = useDevices(10000, { onAlert: handleAlert })

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
  const [activePage,       setActivePage]       = useState(null) // null | 'tools' | 'security' | 'blocking' | 'timeline'
  const [showAlertDrop,    setShowAlertDrop]    = useState(false)
  const [showFilters,      setShowFilters]      = useState(false)

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

  // Total alerts = new device + offline alerts
  const totalAlerts = newDeviceAlerts.length + offlineAlerts.length

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

  async function handleStarToggle(mac, value) {
    optimisticUpdate(mac, { is_important: value })
    try {
      const updated = await api.updateMetadata(mac, { is_important: value })
      setSelected(prev => prev?.mac_address === mac ? { ...prev, ...updated } : prev)
    } catch (e) {
      optimisticUpdate(mac, { is_important: !value })
    }
  }

  const filtered = useMemo(() => {
    let list = devices
    if (activeFilters['ignored'] !== 'include') {
      list = list.filter(d => !d.is_ignored)
    }
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
    list = applyFilters(list)
    return sortDevices(list, sort)
  }, [devices, filter, search, sort, applyFilters, activeFilters])

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
  const hasActiveSmartFilters = Object.keys(activeFilters).length > 0
  const activepageInfo = PAGES.find(p => p.id === activePage)

  return (
    <div className="min-h-screen bg-bg flex flex-col transition-colors duration-200">
      <div className="noise-overlay" />
      <div className="header-glow" />

      <div className="relative z-10 flex flex-col min-h-screen">

        {/* ── Navbar ── */}
        <header className="sticky top-0 z-30 border-b border-border bg-surface/80 backdrop-blur-xl">
          <div className="max-w-[1400px] mx-auto px-4 sm:px-6 h-16 flex items-center gap-2 sm:gap-4">

            {/* Logo + back button */}
            <div className="flex items-center gap-3 shrink-0">
              {activePage ? (
                <button onClick={() => setActivePage(null)}
                  className="btn-ghost p-2 flex items-center gap-1.5 text-xs font-medium"
                  aria-label="Back to dashboard"
                  title="Back to dashboard">
                  <ArrowLeft size={15} />
                  <span className="hidden sm:inline">Dashboard</span>
                </button>
              ) : (
                <>
                  <Logo size={30} />
                  <div className="hidden sm:block">
                    <span className="font-bold tracking-tight" style={{ color: 'var(--color-text)' }}>InSpectre</span>
                    <span className="hidden md:inline text-xs ml-2" style={{ color: 'var(--color-text-faint)' }}>Network Security Suite</span>
                  </div>
                </>
              )}
            </div>

            {/* Page nav icons — left of clock */}
            {!activePage && (
              <div className="flex items-center gap-0.5 ml-2">
                {PAGES.map(p => (
                  <button key={p.id}
                    onClick={() => setActivePage(p.id)}
                    className="btn-ghost p-2 relative"
                    aria-label={p.label}
                    title={p.label}>
                    <p.Icon size={16} />
                  </button>
                ))}
              </div>
            )}

            {/* Page title when on a page */}
            {activePage && (
              <span className="text-sm font-semibold truncate" style={{ color: 'var(--color-text)' }}>
                {activepageInfo?.title}
              </span>
            )}

            {/* Spacer */}
            <div className="flex-1" />

            {/* Live clock — center-right */}
            <div className="hidden md:flex items-center gap-2">
              <span className="live-ping" aria-hidden><span className="live-ping-dot" /></span>
              <span className="text-xs font-mono" style={{ color: 'var(--color-text-faint)' }}>live &middot; {clock}</span>
            </div>

            {/* Right-side utility icons */}
            <div className="flex items-center gap-0.5">

              {/* Bell / alerts */}
              <div className="relative">
                <button
                  onClick={() => setShowAlertDrop(v => !v)}
                  className="btn-ghost p-2 relative"
                  aria-label={`${totalAlerts} alert${totalAlerts !== 1 ? 's' : ''}`}
                  title="Alerts">
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
                      className="fixed right-4 top-[4.5rem] w-80 max-w-[calc(100vw-2rem)] rounded-xl shadow-xl z-40 p-4 space-y-3"
                      style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)' }}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--color-text-muted)' }}>Alerts</span>
                        {totalAlerts > 0 && (
                          <button onClick={() => { dismissAllNew(); dismissAllOffline(); setShowAlertDrop(false) }}
                            className="text-xs opacity-60 hover:opacity-100" style={{ color: 'var(--color-brand)' }}>
                            Clear all
                          </button>
                        )}
                      </div>

                      {totalAlerts === 0 ? (
                        <p className="text-xs text-center py-4" style={{ color: 'var(--color-text-faint)' }}>No new alerts</p>
                      ) : (
                        <>
                          {newDeviceAlerts.map(a => (
                            <div key={`new-${a.id}`}
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
                          ))}
                          {offlineAlerts.map(a => (
                            <div key={`off-${a.id}`}
                              className="flex items-start gap-2 p-2.5 rounded-lg cursor-pointer hover:opacity-80 transition-opacity"
                              style={{ background: a.is_important ? 'rgba(239,68,68,0.08)' : 'var(--color-surface-offset)',
                                       border: a.is_important ? '1px solid rgba(239,68,68,0.2)' : 'none' }}
                              onClick={() => { handleToastDeviceClick(a); dismissOffline(a.id); setShowAlertDrop(false) }}
                            >
                              <WifiOff size={12} className="mt-0.5 shrink-0" style={{ color: '#ef4444' }} />
                              <div className="flex-1 min-w-0">
                                <p className="text-xs font-medium flex items-center gap-1" style={{ color: '#ef4444' }}>
                                  {a.is_important && <Star size={9} fill="currentColor" />}
                                  {a.is_important ? 'Watched device offline' : 'Device offline'}
                                </p>
                                <p className="text-xs mt-0.5 truncate font-medium" style={{ color: 'var(--color-text)', fontSize: '11px' }}>
                                  {a.name} <span className="font-mono font-normal" style={{ color: 'var(--color-text-muted)' }}>{a.ip}</span>
                                </p>
                              </div>
                              <button onClick={e => { e.stopPropagation(); dismissOffline(a.id) }} aria-label="Dismiss"
                                className="opacity-40 hover:opacity-100 transition-opacity shrink-0 mt-0.5">
                                <X size={11} />
                              </button>
                            </div>
                          ))}
                        </>
                      )}
                    </div>
                  </>
                )}
              </div>

              <button onClick={toggleTheme} className="btn-ghost p-2"
                aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
                title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}>
                {isDark ? <Sun size={16} /> : <Moon size={16} />}
              </button>

              <button onClick={() => setShowSettings(true)} className="btn-ghost p-2"
                aria-label="Settings" title="Settings">
                <Settings size={16} />
              </button>
              <button onClick={onLogout} className="btn-ghost p-2"
                aria-label="Sign out" title="Sign out">
                <LogOut size={16} />
              </button>
            </div>
          </div>
        </header>

        {/* ── Page content ── */}
        <main className="flex-1 max-w-[1400px] mx-auto w-full px-4 sm:px-6 py-8">

          {error && !activePage && (
            <div className="flex items-center gap-3 px-4 py-3 rounded-xl text-sm mb-8"
              style={{ background: 'rgb(239 68 68 / 0.1)', border: '1px solid rgb(239 68 68 / 0.2)', color: '#ef4444' }}>
              <AlertCircle size={16} className="shrink-0" />
              {error}
            </div>
          )}

          {/* ── Full page views ── */}
          {activePage === 'tools' && (
            <NetworkTools />
          )}

          {activePage === 'security' && (
            <SecurityDashboard
              onDeviceClick={(mac, tab) => {
                setActivePage(null)
                const dev = devices.find(d => d.mac_address === mac)
                if (dev) openDevice(dev, tab || 'overview')
              }}
            />
          )}

          {activePage === 'blocking' && (
            <DeviceBlocking devices={devices} onDeviceClick={dev => {
              setActivePage(null)
              openDevice(typeof dev === 'object' ? dev : devices.find(d => d.mac_address === dev))
            }} />
          )}

          {activePage === 'timeline' && (
            <NetworkTimeline onDeviceClick={mac => {
              setActivePage(null)
              const dev = devices.find(d => d.mac_address === mac)
              if (dev) openDevice(dev)
            }} />
          )}

          {activePage === 'traffic' && (
            <TrafficPage />
          )}

          {/* ── Main dashboard ── */}
          {!activePage && (
            <div className="space-y-8">
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
              <section className="flex flex-wrap gap-2 items-center">
                <div className="relative" style={{ minWidth: '160px', flex: '1 1 160px', maxWidth: '340px' }}>
                  <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
                    style={{ color: 'var(--color-text-muted)' }} />
                  <input className="input pl-9 w-full" placeholder="Search…"
                    value={search} onChange={e => setSearch(e.target.value)} />
                </div>

                {/* Filters toggle */}
                <button
                  onClick={() => setShowFilters(v => !v)}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border transition-colors relative"
                  style={showFilters || Object.keys(activeFilters).length > 0
                    ? { background: 'var(--color-brand)', color: 'white', borderColor: 'transparent' }
                    : { background: 'var(--color-surface-offset)', color: 'var(--color-text-muted)', borderColor: 'var(--color-border)' }}
                  title="Toggle smart filters"
                  aria-label="Toggle smart filters"
                >
                  <SlidersHorizontal size={13} />
                  <span>Filters</span>
                  {Object.keys(activeFilters).length > 0 && !showFilters && (
                    <span className="ml-0.5 px-1.5 py-0.5 rounded-full text-[10px] font-bold"
                      style={{ background: 'rgba(255,255,255,0.25)', color: 'white' }}>
                      {Object.keys(activeFilters).length}
                    </span>
                  )}
                </button>

                {/* Sort — only in non-category mode */}
                {!isCategoryMode && (
                  <div className="relative">
                    <select value={sort} onChange={e => setSort(e.target.value)}
                      className="input pr-8 appearance-none cursor-pointer text-xs" aria-label="Sort devices">
                      {SORT_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                    </select>
                    <ChevronDown size={14} className="absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none"
                      style={{ color: 'var(--color-text-muted)' }} />
                  </div>
                )}

                <div className="flex items-center gap-1 glass rounded-xl p-1 ml-auto">
                  <button onClick={() => setLayout('grid')}
                    className="p-2 rounded-lg transition-all duration-150"
                    style={layout === 'grid' ? { background: 'var(--color-brand)', color: 'white' } : { color: 'var(--color-text-muted)' }}
                    aria-label="Grid layout" title="Grid layout">
                    <LayoutGrid size={15} /></button>
                  <button onClick={() => setLayout('list')}
                    className="p-2 rounded-lg transition-all duration-150"
                    style={layout === 'list' ? { background: 'var(--color-brand)', color: 'white' } : { color: 'var(--color-text-muted)' }}
                    aria-label="List layout" title="List layout">
                    <List size={15} /></button>
                  <button onClick={() => setLayout('category')}
                    className="p-2 rounded-lg transition-all duration-150"
                    style={layout === 'category' ? { background: 'var(--color-brand)', color: 'white' } : { color: 'var(--color-text-muted)' }}
                    aria-label="Category view" title="Category view">
                    <Layers size={15} /></button>
                </div>
              </section>

              {/* Smart filter bar — collapsible */}
              {showFilters && (
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
              )}

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
                          className="grid grid-cols-[1.5rem_1fr_5rem_1.5rem] sm:grid-cols-[1.5rem_2fr_1fr_1fr_1fr_6rem_1.5rem] gap-3 sm:gap-4 px-4 py-2.5 border-b
                                     text-xs font-semibold uppercase tracking-wider"
                          style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}
                        >
                          <span />
                          <span>Name / IP</span>
                          <span className="hidden sm:block">MAC</span>
                          <span className="hidden sm:block">Vendor</span>
                          <span className="hidden sm:block">Last Seen</span>
                          <span>Status</span>
                          <span />
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
            </div>
          )}
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
            <StatusButton />
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
      {showSettings && (
        <SettingsPanel onClose={() => setShowSettings(false)} onSettingChange={handleSettingChange} />
      )}
    </div>
  )
}

function SkeletonGrid({ layout }) {
  if (layout === 'list') {
    return (
      <div className="card overflow-hidden">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="grid grid-cols-[1.5rem_1fr_5rem_1.5rem] sm:grid-cols-[1.5rem_2fr_1fr_1fr_1fr_6rem_1.5rem] gap-3 sm:gap-4 px-4 py-3 border-b last:border-0 items-center"
            style={{ borderColor: 'var(--color-border)' }}>
            <div className="skeleton w-2.5 h-2.5 rounded-full" />
            <div className="skeleton h-4 w-3/4" />
            <div className="skeleton hidden sm:block h-4 w-4/5" />
            <div className="skeleton hidden sm:block h-4 w-2/3" />
            <div className="skeleton hidden sm:block h-4 w-3/5" />
            <div className="skeleton h-5 w-14 rounded-full" />
            <div />
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

// ── Auth loading screen ──────────────────────────────────────────────────────
function AppLoadingScreen() {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center"
      style={{ background: 'var(--color-bg)' }}>
      <div className="noise-overlay" />
      <div className="relative z-10 flex flex-col items-center gap-4">
        <Logo size={48} />
        <p className="text-sm animate-pulse" style={{ color: 'var(--color-text-muted)' }}>Loading…</p>
      </div>
    </div>
  )
}

// ── Root App — handles auth routing ─────────────────────────────────────────
// authState: 'loading' | 'setup' | 'login' | 'app'
// ── Forced password change (shown when must_change_password = true) ──────────
function ForcePasswordChange({ onDone }) {
  const [current,  setCurrent]  = useState('')
  const [next,     setNext]     = useState('')
  const [confirm,  setConfirm]  = useState('')
  const [showPw,   setShowPw]   = useState(false)
  const [error,    setError]    = useState('')
  const [loading,  setLoading]  = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    if (next !== confirm) { setError('Passwords do not match'); return }
    if (next.length < 8)  { setError('Password must be at least 8 characters'); return }
    setError('')
    setLoading(true)
    try {
      await api.changePassword(current, next)
      onDone()
    } catch {
      setError('Current password is incorrect')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-4"
      style={{ background: 'var(--color-bg)' }}>
      <div className="noise-overlay" />
      <div className="relative z-10 w-full max-w-sm space-y-6">
        <div className="flex flex-col items-center gap-3">
          <Logo size={48} />
          <div className="text-center">
            <h1 className="text-2xl font-bold" style={{ color: 'var(--color-text)' }}>Change Password</h1>
            <p className="text-sm mt-1" style={{ color: 'var(--color-text-muted)' }}>
              You must set a new password before continuing.
            </p>
          </div>
        </div>
        <div className="card p-6 space-y-3">
          <div className="text-xs px-3 py-2 rounded-lg" style={{ background: 'rgba(239,168,68,0.1)', color: '#f59e0b', border: '1px solid rgba(239,168,68,0.3)' }}>
            Default credentials were detected. Please choose a secure password.
          </div>
          <form onSubmit={handleSubmit} className="space-y-3">
            <input className="input w-full" type="password" placeholder="Current password (admin)"
              value={current} onChange={e => setCurrent(e.target.value)} disabled={loading} autoComplete="current-password" />
            <div className="relative">
              <input className="input w-full pr-10" type={showPw ? 'text' : 'password'}
                placeholder="New password" value={next}
                onChange={e => { setNext(e.target.value); setError('') }} disabled={loading} autoComplete="new-password" />
              <button type="button" onClick={() => setShowPw(v => !v)} tabIndex={-1}
                className="absolute right-3 top-1/2 -translate-y-1/2 opacity-50 hover:opacity-100 transition-opacity">
                {showPw ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
            <input className="input w-full" type="password" placeholder="Confirm new password"
              value={confirm} onChange={e => { setConfirm(e.target.value); setError('') }} disabled={loading} autoComplete="new-password" />
            {error && <p className="text-xs px-1" style={{ color: '#ef4444' }}>{error}</p>}
            <button type="submit" disabled={loading || !current || !next || !confirm}
              className="w-full py-2.5 rounded-xl font-semibold text-sm transition-all"
              style={{ background: 'var(--color-brand)', color: 'white',
                       opacity: loading || !current || !next || !confirm ? 0.6 : 1 }}>
              {loading ? 'Saving…' : 'Set Password'}
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}

// ── Root App — handles auth routing ─────────────────────────────────────────
// authState: 'loading' | 'setup' | 'login' | 'change_password' | 'app'
export default function App() {
  const [authState, setAuthState] = useState('loading')

  useEffect(() => {
    async function boot() {
      // First check if setup has been completed (public endpoint)
      try {
        const status = await api.setupStatus()
        if (!status.setup_complete) {
          setAuthState('setup')
          return
        }
      } catch {
        // Server unreachable or old version without setup endpoint — fall through to auth
      }

      // Check for a stored token
      const token = getToken()
      if (!token) {
        setAuthState('login')
        return
      }

      // Validate the token and check if password change is required
      try {
        const me = await api.authMe()
        setAuthState(me.must_change_password ? 'change_password' : 'app')
      } catch {
        clearToken()
        setAuthState('login')
      }
    }
    boot()
  }, [])

  function handleLogin(mustChange) {
    setAuthState(mustChange ? 'change_password' : 'app')
  }

  function handleLogout() {
    clearToken()
    setAuthState('login')
  }

  if (authState === 'loading')         return <AppLoadingScreen />
  if (authState === 'setup')           return <SetupWizard onComplete={() => setAuthState('login')} />
  if (authState === 'login')           return <LoginPage onLogin={handleLogin} />
  if (authState === 'change_password') return <ForcePasswordChange onDone={() => setAuthState('app')} />
  return <MainApp onLogout={handleLogout} />
}
