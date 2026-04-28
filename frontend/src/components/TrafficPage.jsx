import { useState, useEffect, useCallback, useRef } from 'react'
import {
  Activity, Play, Square, RefreshCw, AlertTriangle,
  Globe, Wifi, ChevronDown, ChevronUp,
  Gauge, Trash2, Clock, Download, Upload, Zap,
} from 'lucide-react'
import { api, streamSSE } from '../api'

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

function fmtDate(iso) {
  if (!iso) return ''
  return new Date(iso).toLocaleString()
}

const SPEEDTEST_PHASES = [
  { prefix: 'Retrieving speedtest.net', icon: '🔍', label: 'Finding servers…' },
  { prefix: 'Testing from',             icon: '📍', label: 'Located ISP' },
  { prefix: 'Hosted by',                icon: '🌐', label: 'Connected to server' },
  { prefix: 'Ping:',                    icon: '📡', label: 'Ping test' },
  { prefix: 'Download:',                icon: '⬇', label: 'Download test' },
  { prefix: 'Upload:',                  icon: '⬆', label: 'Upload test' },
]

function parseSpeedtestLine(line) {
  for (const phase of SPEEDTEST_PHASES) {
    if (line.includes(phase.prefix)) return phase
  }
  return null
}

function SpeedTestPanel() {
  const [running,    setRunning]    = useState(false)
  const [phase,      setPhase]      = useState(null)
  const [liveNums,   setLiveNums]   = useState({ down: null, up: null, ping: null })
  const [result,     setResult]     = useState(null)
  const [history,    setHistory]    = useState([])
  const [serverId,   setServerId]   = useState('')
  const [servers,    setServers]    = useState([])
  const [showServers,setShowServers]= useState(false)
  const [schedule,   setSchedule]   = useState('disabled')
  const abortRef = useRef(null)

  useEffect(() => {
    api.speedtestResults().then(setHistory).catch(() => {})
    api.getSettings().then(s => {
      const v = s.find(x => x.key === 'speedtest_schedule')?.value
      if (v) setSchedule(v)
    }).catch(() => {})
  }, [])

  async function handleRun() {
    setRunning(true)
    setPhase(null)
    setLiveNums({ down: null, up: null, ping: null })
    setResult(null)
    const ctrl = new AbortController()
    abortRef.current = ctrl
    const path = `/tools/speedtest${serverId ? `?server_id=${serverId}` : ''}`
    try {
      await streamSSE(path, (text) => {
        if (text.startsWith('RESULT:')) {
          try {
            const r = JSON.parse(text.slice(7))
            setResult(r)
            setPhase({ icon: '✓', label: 'Complete' })
            api.speedtestResults().then(setHistory).catch(() => {})
          } catch {}
        } else {
          const p = parseSpeedtestLine(text)
          if (p) setPhase(p)
          // Extract live numbers
          const downMatch = text.match(/Download:\s*([\d.]+)\s*Mbit/)
          const upMatch   = text.match(/Upload:\s*([\d.]+)\s*Mbit/)
          const pingMatch = text.match(/Ping:\s*([\d.]+)\s*ms/)
          if (downMatch) setLiveNums(n => ({ ...n, down: parseFloat(downMatch[1]) }))
          if (upMatch)   setLiveNums(n => ({ ...n, up:   parseFloat(upMatch[1]) }))
          if (pingMatch) setLiveNums(n => ({ ...n, ping: parseFloat(pingMatch[1]) }))
        }
      }, ctrl.signal)
    } catch {}
    setRunning(false)
  }

  function handleStop() {
    abortRef.current?.abort()
    setRunning(false)
  }

  async function handleLoadServers() {
    setShowServers(true)
    if (servers.length > 0) return
    try {
      const data = await api.speedtestServers()
      setServers(data.servers || [])
    } catch {}
  }

  async function handleDeleteResult(id) {
    await api.deleteSpeedtest(id).catch(() => {})
    setHistory(prev => prev.filter(r => r.id !== id))
  }

  return (
    <div className="card overflow-hidden mb-6">
      <div className="px-5 py-3 border-b flex items-center justify-between"
        style={{ borderColor: 'var(--color-border)', background: 'var(--color-surface-offset)' }}>
        <div className="flex items-center gap-2">
          <Gauge size={15} style={{ color: 'var(--color-brand)' }} />
          <span className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>Speed Test</span>
        </div>
        <span className="text-[10px]" style={{ color: 'var(--color-text-faint)' }}>Powered by Speedtest.net</span>
      </div>
      <div className="p-5 space-y-4">
        {/* Controls row */}
        <div className="flex flex-wrap gap-2 items-center">
          {!running ? (
            <button onClick={handleRun}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-semibold text-white"
              style={{ background: 'var(--color-brand)' }}>
              <Zap size={12} /> Run Speed Test
            </button>
          ) : (
            <button onClick={handleStop}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-semibold"
              style={{ background: 'rgba(239,68,68,0.15)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.3)' }}>
              <Square size={12} /> Stop
            </button>
          )}
          <button
            onClick={() => { if (showServers) { setShowServers(false) } else { handleLoadServers() } }}
            className="text-xs px-3 py-1.5 rounded-lg border"
            style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}>
            {showServers ? 'Hide server picker' : 'Choose server'}
          </button>
          {/* Schedule picker */}
          <div className="ml-auto flex items-center gap-2">
            <label className="text-[10px]" style={{ color: 'var(--color-text-faint)' }}>Auto-run:</label>
            <select className="input text-xs py-1"
              value={schedule}
              onChange={async e => {
                const v = e.target.value
                setSchedule(v)
                await api.updateSetting('speedtest_schedule', v).catch(() => {})
              }}>
              <option value="disabled">Off</option>
              <option value="30m">Every 30m</option>
              <option value="1h">Every hour</option>
              <option value="6h">Every 6h</option>
              <option value="24h">Daily</option>
            </select>
          </div>
        </div>

        {/* Server picker */}
        {showServers && (
          <div>
            <label className="text-xs mb-1 block" style={{ color: 'var(--color-text-muted)' }}>
              Test server
            </label>
            <select className="input text-xs w-full max-w-sm"
              value={serverId} onChange={e => setServerId(e.target.value)}>
              <option value="">Auto-select nearest</option>
              {servers.map(s => (
                <option key={s.id} value={s.id}>{s.label}</option>
              ))}
            </select>
          </div>
        )}

        {/* Live progress */}
        {running && (
          <div className="rounded-xl p-4 space-y-3" style={{ background: 'var(--color-surface-offset)', border: '1px solid var(--color-border)' }}>
            {phase && (
              <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--color-text)' }}>
                <span className="text-base">{phase.icon}</span>
                <span className="font-medium">{phase.label}</span>
                <span className="flex gap-1 ml-1">
                  <span className="w-1.5 h-1.5 rounded-full animate-bounce" style={{ background: 'var(--color-brand)', animationDelay: '0ms' }} />
                  <span className="w-1.5 h-1.5 rounded-full animate-bounce" style={{ background: 'var(--color-brand)', animationDelay: '150ms' }} />
                  <span className="w-1.5 h-1.5 rounded-full animate-bounce" style={{ background: 'var(--color-brand)', animationDelay: '300ms' }} />
                </span>
              </div>
            )}
            <div className="grid grid-cols-3 gap-3">
              {[
                { label: 'Download', value: liveNums.down,  unit: 'Mbit/s', color: '#10b981', Icon: Download },
                { label: 'Upload',   value: liveNums.up,    unit: 'Mbit/s', color: '#6366f1', Icon: Upload   },
                { label: 'Ping',     value: liveNums.ping,  unit: 'ms',     color: '#f59e0b', Icon: Zap      },
              ].map(({ label, value, unit, color, Icon }) => (
                <div key={label} className="text-center p-2 rounded-lg" style={{ background: 'var(--color-surface)' }}>
                  <div className="flex items-center justify-center gap-1 mb-1">
                    <Icon size={11} style={{ color }} />
                    <span className="text-[10px]" style={{ color: 'var(--color-text-muted)' }}>{label}</span>
                  </div>
                  <div className={`text-base font-bold font-mono transition-all ${value != null ? '' : 'opacity-30'}`}
                    style={{ color }}>
                    {value != null ? value.toFixed(value >= 100 ? 0 : 1) : '—'}
                  </div>
                  <div className="text-[9px]" style={{ color: 'var(--color-text-faint)' }}>{unit}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Result summary */}
        {result && (
          <div className="grid grid-cols-3 gap-3">
            <div className="text-center p-3 rounded-lg" style={{ background: 'var(--color-surface-offset)' }}>
              <div className="flex items-center justify-center gap-1 mb-1">
                <Download size={12} style={{ color: '#10b981' }} />
                <span className="text-[10px]" style={{ color: 'var(--color-text-muted)' }}>Download</span>
              </div>
              <div className="text-lg font-bold font-mono" style={{ color: '#10b981' }}>
                {result.download_mbps?.toFixed(2) ?? '—'}
              </div>
              <div className="text-[9px]" style={{ color: 'var(--color-text-faint)' }}>Mbit/s</div>
            </div>
            <div className="text-center p-3 rounded-lg" style={{ background: 'var(--color-surface-offset)' }}>
              <div className="flex items-center justify-center gap-1 mb-1">
                <Upload size={12} style={{ color: '#6366f1' }} />
                <span className="text-[10px]" style={{ color: 'var(--color-text-muted)' }}>Upload</span>
              </div>
              <div className="text-lg font-bold font-mono" style={{ color: '#6366f1' }}>
                {result.upload_mbps?.toFixed(2) ?? '—'}
              </div>
              <div className="text-[9px]" style={{ color: 'var(--color-text-faint)' }}>Mbit/s</div>
            </div>
            <div className="text-center p-3 rounded-lg" style={{ background: 'var(--color-surface-offset)' }}>
              <div className="flex items-center justify-center gap-1 mb-1">
                <Zap size={12} style={{ color: '#f59e0b' }} />
                <span className="text-[10px]" style={{ color: 'var(--color-text-muted)' }}>Ping</span>
              </div>
              <div className="text-lg font-bold font-mono" style={{ color: '#f59e0b' }}>
                {result.ping_ms?.toFixed(1) ?? '—'}
              </div>
              <div className="text-[9px]" style={{ color: 'var(--color-text-faint)' }}>ms</div>
            </div>
          </div>
        )}

        {/* History graph + table */}
        {history.length > 0 && (
          <div className="space-y-3">
            <p className="text-[10px] font-semibold uppercase tracking-wider"
              style={{ color: 'var(--color-text-faint)' }}>
              History ({history.length} test{history.length !== 1 ? 's' : ''})
            </p>

            {/* SVG Line Chart */}
            {history.length >= 2 && (() => {
              const pts = [...history].reverse() // oldest first
              const H = 80, PAD = 8
              const W_AVAIL = 100 // percentage-based via viewBox

              // Compute x positions
              const xOf = (i) => PAD + (i / (pts.length - 1)) * (W_AVAIL * 4 - PAD * 2)
              const VB_W = W_AVAIL * 4

              const series = [
                { key: 'download_mbps', color: '#10b981', label: '↓ Down' },
                { key: 'upload_mbps',   color: '#6366f1', label: '↑ Up'   },
              ]

              return (
                <div className="rounded-xl p-3 space-y-2" style={{ background: 'var(--color-surface-offset)', border: '1px solid var(--color-border)' }}>
                  <svg viewBox={`0 0 ${VB_W} ${H + PAD * 2}`} className="w-full" style={{ height: 100 }}>
                    {series.map(({ key, color }) => {
                      const vals = pts.map(r => r[key] ?? 0)
                      const mx = Math.max(...vals, 1)
                      const yOf = (v) => PAD + (1 - v / mx) * H
                      const d = pts.map((r, i) => `${i === 0 ? 'M' : 'L'}${xOf(i)},${yOf(r[key] ?? 0)}`).join(' ')
                      return (
                        <g key={key}>
                          <path d={d} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" opacity="0.85" />
                          {pts.map((r, i) => (
                            <circle key={i} cx={xOf(i)} cy={yOf(r[key] ?? 0)} r="3" fill={color}
                              opacity="0.9">
                              <title>{`${r[key]?.toFixed(1) ?? '—'} Mbit/s\n${fmtDate(r.tested_at)}`}</title>
                            </circle>
                          ))}
                        </g>
                      )
                    })}
                    {/* X axis labels */}
                    {pts.map((r, i) => {
                      if (pts.length > 8 && i % Math.ceil(pts.length / 6) !== 0 && i !== pts.length - 1) return null
                      return (
                        <text key={i} x={xOf(i)} y={H + PAD * 2 - 1} textAnchor="middle"
                          fontSize="9" fill="var(--color-text-faint)" opacity="0.7">
                          {new Date(r.tested_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                        </text>
                      )
                    })}
                  </svg>
                  <div className="flex gap-4 text-[10px]" style={{ color: 'var(--color-text-faint)' }}>
                    {series.map(s => (
                      <span key={s.key} className="flex items-center gap-1">
                        <span className="w-3 h-0.5 inline-block rounded" style={{ background: s.color }} />
                        {s.label} (Mbit/s)
                      </span>
                    ))}
                  </div>
                </div>
              )
            })()}

            {/* Table */}
            <div className="space-y-1">
              {history.map(r => (
                <div key={r.id} className="flex items-center gap-3 text-xs px-3 py-2 rounded-lg"
                  style={{ background: 'var(--color-surface-offset)' }}>
                  <Clock size={11} style={{ color: 'var(--color-text-faint)' }} />
                  <span className="text-[10px]" style={{ color: 'var(--color-text-faint)' }}>
                    {fmtDate(r.tested_at)}
                  </span>
                  {r.server && (
                    <span className="text-[10px] truncate flex-1" style={{ color: 'var(--color-text-muted)' }}>
                      {r.server}
                    </span>
                  )}
                  <span className="font-mono" style={{ color: '#10b981' }}>
                    ↓ {r.download_mbps?.toFixed(1) ?? '—'}
                  </span>
                  <span className="font-mono" style={{ color: '#6366f1' }}>
                    ↑ {r.upload_mbps?.toFixed(1) ?? '—'}
                  </span>
                  <span className="font-mono" style={{ color: '#f59e0b' }}>
                    {r.ping_ms?.toFixed(0) ?? '—'}ms
                  </span>
                  <button onClick={() => handleDeleteResult(r.id)}
                    className="opacity-40 hover:opacity-100 transition-opacity"
                    style={{ color: 'var(--color-text-faint)' }}>
                    <Trash2 size={11} />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
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

      {/* Speed test panel */}
      <SpeedTestPanel />

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
