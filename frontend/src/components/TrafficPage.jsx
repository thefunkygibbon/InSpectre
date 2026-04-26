import { useState, useEffect, useCallback } from 'react'
import {
  Activity, Play, Square, RefreshCw, AlertTriangle,
  Globe, Wifi, ChevronDown, ChevronUp,
} from 'lucide-react'
import { api } from '../api'

function fmtBytes(b) {
  if (!b) return '0 B'
  if (b < 1024) return `${b} B`
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MB`
  return `${(b / 1073741824).toFixed(2)} GB`
}

function StatTile({ label, value, sub }) {
  return (
    <div className="card p-4 text-center">
      <div className="text-xl font-bold font-mono" style={{ color: 'var(--color-text)' }}>{value}</div>
      <div className="text-xs font-medium mt-0.5" style={{ color: 'var(--color-text-muted)' }}>{label}</div>
      {sub && <div className="text-[10px] mt-0.5" style={{ color: 'var(--color-text-faint)' }}>{sub}</div>}
    </div>
  )
}

function SessionCard({ session, onStop }) {
  const [expanded, setExpanded] = useState(false)
  const cur = session.current
  return (
    <div className="card overflow-hidden">
      <div
        className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-surface-offset/40 transition-colors"
        onClick={() => setExpanded(e => !e)}
      >
        <div className="w-2 h-2 rounded-full animate-pulse" style={{ background: '#22c55e' }} />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium truncate" style={{ color: 'var(--color-text)' }}>
            {session.target_ip}
          </p>
          <p className="text-xs font-mono truncate" style={{ color: 'var(--color-text-faint)' }}>
            {session.mac}
          </p>
        </div>
        <div className="text-right mr-2 hidden sm:block">
          <div className="text-xs font-mono" style={{ color: 'var(--color-text)' }}>
            ↓ {fmtBytes(cur?.bytes_in)} / ↑ {fmtBytes(cur?.bytes_out)}
          </div>
          <div className="text-[10px]" style={{ color: 'var(--color-text-faint)' }}>
            {cur?.packets_in + cur?.packets_out || 0} pkts
          </div>
        </div>
        <button
          onClick={e => { e.stopPropagation(); onStop(session.mac) }}
          className="flex items-center gap-1 px-2 py-1 rounded text-xs font-medium transition-colors"
          style={{ background: 'rgba(239,68,68,0.1)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.2)' }}
        >
          <Square size={10} /> Stop
        </button>
        {expanded ? <ChevronUp size={14} style={{ color: 'var(--color-text-faint)' }} /> : <ChevronDown size={14} style={{ color: 'var(--color-text-faint)' }} />}
      </div>

      {expanded && cur && (
        <div className="border-t px-4 py-3 space-y-3" style={{ borderColor: 'var(--color-border)' }}>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: 'Downloaded',  value: fmtBytes(cur.bytes_in) },
              { label: 'Uploaded',    value: fmtBytes(cur.bytes_out) },
              { label: 'LAN traffic', value: fmtBytes(cur.lan_bytes) },
              { label: 'WAN traffic', value: fmtBytes(cur.wan_bytes) },
            ].map(({ label, value }) => (
              <div key={label} className="text-center">
                <div className="text-sm font-semibold font-mono" style={{ color: 'var(--color-text)' }}>{value}</div>
                <div className="text-[10px]" style={{ color: 'var(--color-text-faint)' }}>{label}</div>
              </div>
            ))}
          </div>

          {/* Top domains */}
          {(() => {
            const merged = {}
            ;[...(cur.tls_sni || []), ...(cur.http_hosts || [])].forEach(({ k, v }) => {
              merged[k] = (merged[k] || 0) + v
            })
            const items = Object.entries(merged).sort((a, b) => b[1] - a[1]).slice(0, 5)
            return items.length > 0 ? (
              <div>
                <div className="text-[10px] font-semibold uppercase tracking-wider mb-1.5"
                  style={{ color: 'var(--color-text-faint)' }}>Top Domains</div>
                <div className="flex flex-wrap gap-1.5">
                  {items.map(([k, v]) => (
                    <span key={k} className="text-[10px] px-2 py-0.5 rounded-full font-mono"
                      style={{ background: 'color-mix(in srgb, var(--color-brand) 10%, transparent)', color: 'var(--color-text-muted)', border: '1px solid color-mix(in srgb, var(--color-brand) 20%, transparent)' }}>
                      {k} ({v})
                    </span>
                  ))}
                </div>
              </div>
            ) : null
          })()}

          {/* Top countries */}
          {cur.top_countries?.length > 0 && (
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-wider mb-1.5"
                style={{ color: 'var(--color-text-faint)' }}>Countries</div>
              <div className="flex flex-wrap gap-1.5">
                {cur.top_countries.slice(0, 6).map(({ k, v }) => (
                  <span key={k} className="text-[10px] px-2 py-0.5 rounded-full"
                    style={{ background: 'var(--color-surface-offset)', color: 'var(--color-text-muted)', border: '1px solid var(--color-border)' }}>
                    {k} ({v})
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Unusual ports */}
          {cur.unusual_ports?.length > 0 && (
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-wider mb-1.5"
                style={{ color: '#f59e0b' }}>Unusual Ports</div>
              <div className="flex flex-wrap gap-1.5">
                {cur.unusual_ports.slice(0, 6).map(({ k, v }) => (
                  <span key={k} className="text-[10px] px-2 py-0.5 rounded-full font-mono"
                    style={{ background: 'rgba(245,158,11,0.1)', color: '#f59e0b', border: '1px solid rgba(245,158,11,0.25)' }}>
                    :{k} ({v})
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export function TrafficPage() {
  const [sessions,  setSessions]  = useState([])
  const [summary,   setSummary]   = useState(null)
  const [loading,   setLoading]   = useState(true)
  const [error,     setError]     = useState(null)
  const [stopping,  setStopping]  = useState(null)

  const refresh = useCallback(async () => {
    try {
      const [actData, sumData] = await Promise.all([
        api.trafficActive(),
        api.trafficSummary(),
      ])
      setSessions(actData.sessions || [])
      setSummary(sumData)
      setError(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
    const id = setInterval(refresh, 5000)
    return () => clearInterval(id)
  }, [refresh])

  async function handleStop(mac) {
    setStopping(mac)
    try {
      await api.trafficStop(mac)
      await refresh()
    } catch (e) {
      setError(e.message)
    } finally {
      setStopping(null)
    }
  }

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 py-6 space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2" style={{ color: 'var(--color-text)' }}>
            <Activity size={20} style={{ color: 'var(--color-brand)' }} />
            Traffic Monitor
          </h1>
          <p className="text-sm mt-0.5" style={{ color: 'var(--color-text-faint)' }}>
            Passive per-device traffic analysis via ARP MITM. Open a device drawer and go to the Traffic tab to start monitoring.
          </p>
        </div>
        <button
          onClick={refresh}
          disabled={loading}
          className="p-2 rounded-lg transition-colors"
          style={{ background: 'var(--color-surface-offset)', color: 'var(--color-text-muted)' }}
          title="Refresh"
        >
          <RefreshCw size={15} className={loading ? 'animate-spin' : ''} />
        </button>
      </div>

      {error && (
        <div className="flex items-center gap-2 px-4 py-3 rounded-xl text-sm"
          style={{ background: 'rgba(239,68,68,0.08)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.2)' }}>
          <AlertTriangle size={14} />
          {error}
        </div>
      )}

      {/* Summary tiles */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
          <StatTile label="Active Sessions"   value={summary.active_sessions}           />
          <StatTile label="Total (24h)"       value={fmtBytes(summary.total_bytes)}     sub="in + out" />
          <StatTile label="WAN (24h)"         value={fmtBytes(summary.total_wan_bytes)} sub="internet" />
          <StatTile label="Download (24h)"    value={fmtBytes(summary.total_bytes_in)}  />
          <StatTile label="Upload (24h)"      value={fmtBytes(summary.total_bytes_out)} />
          <StatTile label="LAN (24h)"         value={fmtBytes(summary.total_lan_bytes)} sub="local" />
        </div>
      )}

      {/* Active sessions */}
      <div>
        <h2 className="text-sm font-semibold mb-3 flex items-center gap-2" style={{ color: 'var(--color-text-muted)' }}>
          <span className="w-2 h-2 rounded-full" style={{ background: '#22c55e' }} />
          Active Monitors
          {sessions.length > 0 && (
            <span className="text-xs font-mono px-2 py-0.5 rounded-full"
              style={{ background: 'var(--color-surface-offset)', color: 'var(--color-text-faint)' }}>
              {sessions.length}
            </span>
          )}
        </h2>

        {loading && sessions.length === 0 ? (
          <div className="flex justify-center py-10">
            <RefreshCw size={20} className="animate-spin" style={{ color: 'var(--color-text-faint)' }} />
          </div>
        ) : sessions.length === 0 ? (
          <div className="card p-8 text-center">
            <Activity size={32} className="mx-auto mb-3" style={{ color: 'var(--color-text-faint)', opacity: 0.4 }} />
            <p className="text-sm" style={{ color: 'var(--color-text-faint)' }}>No active traffic monitors.</p>
            <p className="text-xs mt-1" style={{ color: 'var(--color-text-faint)', opacity: 0.6 }}>
              Open a device and click the Traffic tab to start.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {sessions.map(s => (
              <SessionCard
                key={s.mac}
                session={s}
                onStop={handleStop}
              />
            ))}
          </div>
        )}
      </div>

      {/* Info callout */}
      <div className="rounded-xl px-4 py-3 flex items-start gap-3 text-xs"
        style={{ background: 'color-mix(in srgb, var(--color-brand) 6%, transparent)', border: '1px solid color-mix(in srgb, var(--color-brand) 15%, transparent)', color: 'var(--color-text-faint)' }}>
        <Wifi size={14} style={{ color: 'var(--color-brand)', flexShrink: 0, marginTop: 1 }} />
        <span>
          Traffic monitoring uses ARP MITM — the probe temporarily acts as a gateway for the monitored device.
          Packets are <strong style={{ color: 'var(--color-text-muted)' }}>forwarded</strong>, not dropped.
          You cannot monitor a device that is currently blocked.
        </span>
      </div>
    </div>
  )
}
