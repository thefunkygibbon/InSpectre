import { useState, useEffect, useRef, useCallback } from 'react'
import { Activity, Play, Square, Globe, Shield, Wifi, AlertTriangle, RefreshCw } from 'lucide-react'
import { api } from '../api'

function fmtBytes(b) {
  if (!b) return '0 B'
  if (b < 1024) return `${b} B`
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MB`
  return `${(b / 1073741824).toFixed(2)} GB`
}

function BandwidthBar({ label, bytes, maxBytes, color }) {
  const pct = maxBytes > 0 ? Math.min(100, (bytes / maxBytes) * 100) : 0
  return (
    <div>
      <div className="flex justify-between text-xs mb-1" style={{ color: 'var(--color-text-muted)' }}>
        <span>{label}</span>
        <span style={{ color: 'var(--color-text)' }}>{fmtBytes(bytes)}</span>
      </div>
      <div className="h-2 rounded-full overflow-hidden" style={{ background: 'var(--color-border)' }}>
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${pct}%`, background: color }}
        />
      </div>
    </div>
  )
}

function TopList({ title, items, icon: Icon }) {
  if (!items || items.length === 0) return null
  const max = items[0]?.v || 1
  return (
    <div>
      <div className="flex items-center gap-1.5 mb-2">
        {Icon && <Icon size={13} style={{ color: 'var(--color-brand)' }} />}
        <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--color-text-muted)' }}>{title}</span>
      </div>
      <div className="space-y-1.5">
        {items.slice(0, 8).map((item, i) => (
          <div key={i} className="flex items-center gap-2">
            <div className="flex-1 min-w-0">
              <div className="flex justify-between text-xs mb-0.5">
                <span className="truncate font-mono" style={{ color: 'var(--color-text)', maxWidth: '75%' }}>{item.k}</span>
                <span style={{ color: 'var(--color-text-faint)' }}>{item.v}</span>
              </div>
              <div className="h-1 rounded-full overflow-hidden" style={{ background: 'var(--color-border)' }}>
                <div
                  className="h-full rounded-full"
                  style={{
                    width: `${Math.max(4, (item.v / max) * 100)}%`,
                    background: 'var(--color-brand)',
                    opacity: 0.7,
                  }}
                />
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function ProtoSplit({ protocols }) {
  if (!protocols || protocols.length === 0) return null
  const total = protocols.reduce((s, p) => s + p.v, 0) || 1
  const colors = { TCP: '#6366f1', UDP: '#10b981', ICMP: '#f59e0b' }
  return (
    <div>
      <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--color-text-muted)' }}>Protocols</span>
      <div className="flex gap-1 mt-2 h-3 rounded-full overflow-hidden">
        {protocols.map((p, i) => (
          <div
            key={i}
            className="h-full transition-all duration-500"
            style={{
              width: `${(p.v / total) * 100}%`,
              background: colors[p.k] || '#6b7280',
            }}
            title={`${p.k}: ${p.v}`}
          />
        ))}
      </div>
      <div className="flex gap-3 mt-1.5 flex-wrap">
        {protocols.map((p, i) => (
          <span key={i} className="text-xs flex items-center gap-1" style={{ color: 'var(--color-text-faint)' }}>
            <span className="inline-block w-2 h-2 rounded-full" style={{ background: colors[p.k] || '#6b7280' }} />
            {p.k} {((p.v / total) * 100).toFixed(0)}%
          </span>
        ))}
      </div>
    </div>
  )
}

export function TrafficPanel({ device }) {
  const mac = device.mac_address
  const [monitoring, setMonitoring] = useState(false)
  const [stats,      setStats]      = useState(null)
  const [loading,    setLoading]    = useState(true)
  const [toggling,   setToggling]   = useState(false)
  const [error,      setError]      = useState(null)
  const abortRef = useRef(null)

  const fetchStats = useCallback(async () => {
    try {
      const data = await api.trafficLive(mac)
      setStats(data)
      setMonitoring(true)
      setError(null)
    } catch (e) {
      if (e.message?.includes('404')) {
        setMonitoring(false)
        setStats(null)
      } else {
        setError(e.message)
      }
    }
  }, [mac])

  // Initial check
  useEffect(() => {
    setLoading(true)
    fetchStats().finally(() => setLoading(false))
  }, [fetchStats])

  // Live SSE stream when monitoring
  useEffect(() => {
    if (!monitoring) return
    const ctrl = new AbortController()
    abortRef.current = ctrl

    api.trafficStream(mac, (line) => {
      try {
        const data = JSON.parse(line)
        if (!data.error) setStats(data)
      } catch (_) {}
    }, ctrl.signal).catch(() => {})

    return () => ctrl.abort()
  }, [monitoring, mac])

  async function handleToggle() {
    setToggling(true)
    setError(null)
    try {
      if (monitoring) {
        abortRef.current?.abort()
        await api.trafficStop(mac)
        setMonitoring(false)
        setStats(null)
      } else {
        await api.trafficStart(mac)
        setMonitoring(true)
        await fetchStats()
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setToggling(false)
    }
  }

  const cur = stats?.current

  return (
    <div className="space-y-5 p-1">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity size={15} style={{ color: 'var(--color-brand)' }} />
          <span className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>Traffic Monitor</span>
          {monitoring && (
            <span className="text-[10px] font-medium px-2 py-0.5 rounded-full"
              style={{ color: 'var(--color-brand)', background: 'color-mix(in srgb, var(--color-brand) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--color-brand) 25%, transparent)' }}>
              LIVE
            </span>
          )}
        </div>
        <button
          onClick={handleToggle}
          disabled={toggling || loading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors"
          style={monitoring
            ? { background: 'color-mix(in srgb, #ef4444 12%, transparent)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.25)' }
            : { background: 'color-mix(in srgb, var(--color-brand) 12%, transparent)', color: 'var(--color-brand)', border: '1px solid color-mix(in srgb, var(--color-brand) 25%, transparent)' }
          }
        >
          {toggling
            ? <RefreshCw size={12} className="animate-spin" />
            : monitoring ? <Square size={12} /> : <Play size={12} />
          }
          {monitoring ? 'Stop' : 'Start'}
        </button>
      </div>

      {error && (
        <div className="text-xs px-3 py-2 rounded-lg flex items-center gap-2"
          style={{ background: 'rgba(239,68,68,0.08)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.2)' }}>
          <AlertTriangle size={12} />
          {error}
        </div>
      )}

      {!monitoring && !loading && (
        <p className="text-xs text-center py-6" style={{ color: 'var(--color-text-faint)' }}>
          Start monitoring to capture live traffic for this device.
        </p>
      )}

      {loading && (
        <div className="flex justify-center py-6">
          <RefreshCw size={18} className="animate-spin" style={{ color: 'var(--color-text-faint)' }} />
        </div>
      )}

      {monitoring && cur && (
        <>
          {/* Bandwidth gauges */}
          <div className="card p-4 space-y-3">
            <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--color-text-muted)' }}>Bandwidth (current bucket)</span>
            {(() => {
              const maxBytes = Math.max(cur.bytes_in, cur.bytes_out, 1)
              return (
                <>
                  <BandwidthBar label="Download (in)" bytes={cur.bytes_in}  maxBytes={maxBytes} color="#6366f1" />
                  <BandwidthBar label="Upload (out)"  bytes={cur.bytes_out} maxBytes={maxBytes} color="#10b981" />
                </>
              )
            })()}
            <div className="flex gap-4 pt-1">
              {[
                { label: 'LAN',     bytes: cur.lan_bytes, color: '#10b981' },
                { label: 'WAN',     bytes: cur.wan_bytes, color: '#6366f1' },
                { label: 'Packets↓', bytes: cur.packets_in,  color: '#f59e0b', raw: true },
                { label: 'Packets↑', bytes: cur.packets_out, color: '#f59e0b', raw: true },
              ].map(({ label, bytes, color, raw }) => (
                <div key={label} className="flex-1 text-center">
                  <div className="text-xs font-mono font-semibold" style={{ color }}>{raw ? bytes : fmtBytes(bytes)}</div>
                  <div className="text-[10px]" style={{ color: 'var(--color-text-faint)' }}>{label}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Protocol split */}
          {cur.protocols?.length > 0 && (
            <div className="card p-4">
              <ProtoSplit protocols={cur.protocols} />
            </div>
          )}

          {/* Top domains (TLS SNI + HTTP hosts combined) */}
          {(() => {
            const merged = {}
            ;[...(cur.tls_sni || []), ...(cur.http_hosts || [])].forEach(({ k, v }) => {
              merged[k] = (merged[k] || 0) + v
            })
            const items = Object.entries(merged).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ k, v }))
            return items.length > 0 ? (
              <div className="card p-4">
                <TopList title="Top Domains" items={items} icon={Globe} />
              </div>
            ) : null
          })()}

          {/* DNS queries */}
          {cur.dns_queries?.length > 0 && (
            <div className="card p-4">
              <TopList title="DNS Queries" items={cur.dns_queries} icon={Wifi} />
            </div>
          )}

          {/* Countries */}
          {cur.top_countries?.length > 0 && (
            <div className="card p-4">
              <TopList title="Countries (WAN)" items={cur.top_countries} icon={Globe} />
            </div>
          )}

          {/* Unusual ports */}
          {cur.unusual_ports?.length > 0 && (
            <div className="card p-4">
              <TopList title="Unusual Ports" items={cur.unusual_ports} icon={Shield} />
            </div>
          )}

          {stats.started_at && (
            <p className="text-[10px] text-center" style={{ color: 'var(--color-text-faint)' }}>
              Monitoring since {new Date(stats.started_at).toLocaleTimeString()}
            </p>
          )}
        </>
      )}
    </div>
  )
}
