import { useState, useEffect, useMemo } from 'react'
import { Search, Download, RefreshCw, Pin, ChevronDown, ChevronRight, Wifi, WifiOff } from 'lucide-react'
import { api } from '../api'

function ipToNum(ip) {
  if (!ip) return 0
  return ip.split('.').reduce((acc, o) => (acc << 8) + parseInt(o, 10) >>> 0, 0) >>> 0
}

// Two-hour window: IPs seen within this period are "currently active"
const ACTIVE_MS = 2 * 60 * 60 * 1000

function ipRole(ipRow, device) {
  const { ip, seen_while_online, last_seen } = ipRow
  const pinned  = device.primary_ip
  const current = device.ip_address
  if (pinned  && ip === pinned)  return 'pinned'
  if (!pinned && ip === current) return 'primary'
  if (pinned  && ip === current) return 'active_secondary'
  if (seen_while_online === true) {
    const recent = last_seen && (Date.now() - new Date(last_seen).getTime()) < ACTIVE_MS
    return recent ? 'active_secondary' : 'past_secondary'
  }
  return 'dhcp_history'
}

const ROLE_CFG = {
  pinned:          { label: 'Pinned',        color: 'var(--color-brand)', bg: 'rgba(99,102,241,0.12)', border: 'rgba(99,102,241,0.3)'   },
  primary:         { label: 'Current',       color: '#22c55e',            bg: 'rgba(34,197,94,0.12)',  border: 'rgba(34,197,94,0.3)'    },
  active_secondary:{ label: 'Secondary',     color: '#f59e0b',            bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.3)'   },
  past_secondary:  { label: 'Was secondary', color: 'var(--color-text-faint)', bg: 'rgba(255,255,255,0.04)', border: 'rgba(255,255,255,0.08)' },
  dhcp_history:    { label: 'DHCP history',  color: 'var(--color-text-faint)', bg: 'rgba(255,255,255,0.04)', border: 'rgba(255,255,255,0.08)' },
}

function RoleBadge({ role }) {
  const cfg = ROLE_CFG[role] || ROLE_CFG.historical
  return (
    <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold"
      style={{ color: cfg.color, background: cfg.bg, border: `1px solid ${cfg.border}` }}>
      {cfg.label}
    </span>
  )
}

function fmt(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}

export function IpManagementPage({ onDeviceClick }) {
  const [data,     setData]     = useState(null)
  const [loading,  setLoading]  = useState(true)
  const [error,    setError]    = useState(null)
  const [search,   setSearch]   = useState('')
  const [expanded, setExpanded] = useState({})
  const [setting,  setSetting]  = useState(null)
  const [exporting,setExporting]= useState(false)

  function load() {
    setLoading(true)
    api.getIpManagement()
      .then(setData)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }
  useEffect(load, [])

  const filtered = useMemo(() => {
    if (!data) return []
    const q = search.toLowerCase()
    if (!q) return data
    return data.filter(d =>
      d.effective_ip?.includes(q) ||
      d.name?.toLowerCase().includes(q) ||
      d.mac_address?.toLowerCase().includes(q) ||
      d.vendor?.toLowerCase().includes(q) ||
      d.ips?.some(i => i.ip.includes(q))
    )
  }, [data, search])

  // Flat list of IP rows sorted by IP for the full table view
  const ipRows = useMemo(() => {
    const rows = []
    for (const d of filtered) {
      for (const ip of d.ips || []) {
        rows.push({ ...ip, device: d, role: ipRole(ip, d) })
      }
      if ((!d.ips || d.ips.length === 0) && d.ip_address) {
        rows.push({ ip: d.ip_address, role: 'primary', first_seen: null, last_seen: null, device: d })
      }
    }
    return rows.sort((a, b) => ipToNum(a.ip) - ipToNum(b.ip))
  }, [filtered])

  const totalIps = data ? data.reduce((acc, d) => acc + Math.max(d.ips?.length || 0, 1), 0) : 0
  const pinnedCount = data ? data.filter(d => d.primary_ip).length : 0

  async function handleSetPrimary(mac, ip) {
    setSetting(mac + ip)
    try {
      await api.setPrimaryIp(mac, ip)
      load()
    } catch (e) {
      alert('Failed: ' + e.message)
    } finally {
      setSetting(null)
    }
  }

  async function handleExport() {
    setExporting(true)
    try {
      const res = await api.exportIpsCsv()
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url; a.download = 'inspectre-ip-management.csv'; a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      alert('Export failed: ' + e.message)
    } finally {
      setExporting(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center gap-3">
        <div className="flex-1">
          <h2 className="text-lg font-bold" style={{ color: 'var(--color-text)' }}>IP Management</h2>
          {data && (
            <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-muted)' }}>
              {data.length} device{data.length !== 1 ? 's' : ''} · {totalIps} IP record{totalIps !== 1 ? 's' : ''}
              {pinnedCount > 0 && ` · ${pinnedCount} pinned`}
            </p>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button onClick={load} disabled={loading}
            className="btn-ghost p-2" title="Refresh">
            <RefreshCw size={15} className={loading ? 'animate-spin' : ''} />
          </button>
          <button onClick={handleExport} disabled={exporting}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors"
            style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}>
            <Download size={13} />
            {exporting ? 'Exporting…' : 'Export CSV'}
          </button>
        </div>
      </div>

      {/* Search */}
      <div className="relative">
        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--color-text-faint)' }} />
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Filter by IP, device name, MAC, or vendor…"
          className="w-full pl-9 pr-3 py-2 rounded-xl text-sm border"
          style={{ background: 'var(--color-surface-offset)', borderColor: 'var(--color-border)', color: 'var(--color-text)' }}
        />
      </div>

      {error && <p className="text-sm text-red-400">{error}</p>}

      {loading && !data && (
        <div className="space-y-2">
          {[...Array(8)].map((_, i) => <div key={i} className="skeleton h-10 rounded-lg" />)}
        </div>
      )}

      {!loading && data && ipRows.length === 0 && (
        <p className="text-sm italic text-center py-8" style={{ color: 'var(--color-text-faint)' }}>
          No IP records found.
        </p>
      )}

      {ipRows.length > 0 && (
        <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--color-border)' }}>
          {/* Column headers */}
          <div className="grid grid-cols-[2fr_2.5fr_2fr_1fr_2fr_auto] gap-3 px-4 py-2"
            style={{ background: 'var(--color-surface-offset)', borderBottom: '1px solid var(--color-border)' }}>
            {['IP Address', 'Device', 'MAC', 'Status', 'Last Seen', ''].map(h => (
              <span key={h} className="text-[10px] font-semibold uppercase tracking-wider"
                style={{ color: 'var(--color-text-faint)' }}>{h}</span>
            ))}
          </div>

          {ipRows.map((row, i) => {
            const d       = row.device
            const isActive = row.role === 'pinned' || row.role === 'primary' || row.role === 'active_secondary'
            const isPinnable = row.role === 'active_secondary' && row.ip !== d.primary_ip
            return (
              <div key={`${d.mac_address}-${row.ip}`}
                className="grid grid-cols-[2fr_2.5fr_2fr_1fr_2fr_auto] gap-3 px-4 py-2.5 items-center"
                style={{
                  borderTop: i > 0 ? '1px solid var(--color-border)' : 'none',
                  opacity: isActive ? 1 : 0.55,
                }}>

                {/* IP */}
                <div className="flex items-center gap-1.5 min-w-0">
                  <span className="font-mono text-xs font-medium truncate"
                    style={{ color: isActive ? 'var(--color-text)' : 'var(--color-text-faint)' }}>
                    {row.ip}
                  </span>
                  <RoleBadge role={row.role} />
                </div>

                {/* Device name */}
                <button
                  onClick={() => onDeviceClick && onDeviceClick(d.mac_address)}
                  className="text-xs text-left truncate hover:underline"
                  style={{ color: 'var(--color-text)' }}>
                  {d.name}
                </button>

                {/* MAC */}
                <span className="font-mono text-[11px] truncate" style={{ color: 'var(--color-text-faint)' }}>
                  {d.mac_address}
                </span>

                {/* Online status */}
                <span className="flex items-center gap-1 text-[11px]"
                  style={{ color: d.is_online ? '#22c55e' : 'var(--color-text-faint)' }}>
                  {d.is_online ? <Wifi size={11} /> : <WifiOff size={11} />}
                  {d.is_online ? 'Online' : 'Offline'}
                </span>

                {/* Last seen */}
                <span className="text-[11px]" style={{ color: 'var(--color-text-faint)' }}>
                  {fmt(row.last_seen)}
                </span>

                {/* Pin action — only offer for active secondaries (multi-homed) */}
                <div className="flex justify-end">
                  {isPinnable && (
                    <button
                      onClick={() => handleSetPrimary(d.mac_address, row.ip)}
                      disabled={setting !== null}
                      title="Pin as primary IP — use this IP for scanning this device"
                      className="flex items-center gap-1 text-[10px] px-2 py-1 rounded border font-medium transition-colors hover:opacity-80"
                      style={{ borderColor: 'rgba(245,158,11,0.4)', color: '#f59e0b' }}>
                      <Pin size={10} />
                      {setting === d.mac_address + row.ip ? '…' : 'Pin'}
                    </button>
                  )}
                  {row.role === 'pinned' && (
                    <span className="flex items-center gap-1 text-[10px]" style={{ color: 'var(--color-brand)' }}>
                      <Pin size={10} />
                    </span>
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
