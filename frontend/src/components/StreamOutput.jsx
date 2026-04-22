/**
 * StreamOutput — replaces the raw TerminalBox with parsed, structured views
 * for ping, traceroute, and vuln-scan SSE streams.
 *
 * Props:
 *   lines    – string[]  raw lines received so far
 *   running  – bool
 *   onStop   – fn
 *   mode     – 'ping' | 'traceroute' | 'vuln' | 'generic'
 */
import { useState, useRef, useEffect } from 'react'
import { X, Square, ChevronDown, ChevronRight } from 'lucide-react'

// ---------------------------------------------------------------------------
// Shared chrome
// ---------------------------------------------------------------------------
function TermChrome({ onStop, running, children, rawLines, defaultOpen = false }) {
  const [showRaw, setShowRaw] = useState(defaultOpen)
  const rawRef = useRef(null)
  useEffect(() => {
    if (showRaw && rawRef.current) rawRef.current.scrollTop = rawRef.current.scrollHeight
  }, [showRaw, rawLines])

  return (
    <div className="mt-3 rounded-lg border border-[#30363d] bg-[#0d1117] overflow-hidden">
      {/* toolbar */}
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-[#21262d] bg-[#161b22]">
        <span className="text-[10px] font-mono text-[#8b949e] uppercase tracking-widest">
          {running ? <span className="flex items-center gap-1.5"><span className="inline-block w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />live</span> : 'done'}
        </span>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowRaw(r => !r)}
            className="flex items-center gap-1 text-[10px] text-[#8b949e] hover:text-[#c9d1d9] transition-colors">
            {showRaw ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
            raw
          </button>
          {running && (
            <button onClick={onStop} className="text-[#8b949e] hover:text-red-400 transition-colors" title="Stop">
              <X size={11} />
            </button>
          )}
        </div>
      </div>

      {/* structured content */}
      <div className="px-3 py-2">{children}</div>

      {/* raw output */}
      {showRaw && (
        <div ref={rawRef}
          className="border-t border-[#21262d] px-3 py-2 font-mono max-h-36 overflow-y-auto"
          style={{ fontSize: '9px', lineHeight: 1.6, color: '#8b949e' }}>
          {rawLines.map((l, i) => <div key={i} className="whitespace-pre-wrap break-all">{l}</div>)}
          {running && <span className="animate-pulse">▌</span>}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Ping view
// ---------------------------------------------------------------------------
const PING_RE = /^(\d+) bytes from ([\d.]+).*icmp_seq=(\d+).*ttl=(\d+).*time=([\d.]+)\s*ms/
const STAT_TX_RE = /(\d+) packets transmitted/
const STAT_RX_RE = /(\d+) received/
const STAT_LOSS_RE = /(\d+(?:\.\d+)?)% packet loss/
const STAT_RTT_RE = /rtt.*=\s*([\d.]+)\/([\d.]+)\/([\d.]+)\/([\d.]+)/

function parsePing(lines) {
  const packets = []
  let tx = null, rx = null, loss = null, rttMin = null, rttAvg = null, rttMax = null
  for (const l of lines) {
    const m = l.match(PING_RE)
    if (m) packets.push({ seq: +m[3], ttl: +m[4], ms: +m[5] })
    if (STAT_TX_RE.test(l))   tx   = +l.match(STAT_TX_RE)[1]
    if (STAT_RX_RE.test(l))   rx   = +l.match(STAT_RX_RE)[1]
    if (STAT_LOSS_RE.test(l)) loss = +l.match(STAT_LOSS_RE)[1]
    const rtt = l.match(STAT_RTT_RE)
    if (rtt) { rttMin = +rtt[1]; rttAvg = +rtt[2]; rttMax = +rtt[3] }
  }
  return { packets, tx, rx, loss, rttMin, rttAvg, rttMax }
}

function latencyColor(ms) {
  if (ms < 5)   return '#22c55e'
  if (ms < 20)  return '#84cc16'
  if (ms < 50)  return '#f59e0b'
  if (ms < 100) return '#f97316'
  return '#ef4444'
}

function PingView({ lines, running }) {
  const { packets, tx, rx, loss, rttMin, rttAvg, rttMax } = parsePing(lines)
  const maxMs = Math.max(...packets.map(p => p.ms), 1)

  return (
    <div className="space-y-3">
      {/* spark bars */}
      {packets.length > 0 && (
        <div>
          <div className="flex items-end gap-[3px]" style={{ height: 32 }}>
            {packets.slice(-40).map((p, i) => {
              const h = Math.max(3, Math.round((p.ms / maxMs) * 30))
              return (
                <div key={i} title={`seq ${p.seq}: ${p.ms} ms`}
                  style={{ width: 6, height: h, background: latencyColor(p.ms), borderRadius: 2, flexShrink: 0 }} />
              )
            })}
            {running && (
              <div style={{ width: 6, height: 4, background: '#374151', borderRadius: 2, animation: 'pulse 1s infinite', flexShrink: 0 }} />
            )}
          </div>
          <div className="flex justify-between mt-1">
            <span className="text-[9px] text-[#8b949e] font-mono">{packets.length} replies</span>
            <span className="text-[9px] font-mono" style={{ color: latencyColor(packets[packets.length - 1]?.ms ?? 0) }}>
              {packets[packets.length - 1]?.ms} ms last
            </span>
          </div>
        </div>
      )}

      {/* stats row */}
      {tx != null && (
        <div className="grid grid-cols-4 gap-1">
          {[
            { label: 'sent',    val: tx,                   color: '#8b949e' },
            { label: 'recv',    val: rx,                   color: '#22c55e' },
            { label: 'loss',    val: `${loss}%`,           color: loss > 0 ? '#ef4444' : '#22c55e' },
            { label: 'avg ms',  val: rttAvg != null ? rttAvg : '--', color: rttAvg != null ? latencyColor(rttAvg) : '#8b949e' },
          ].map(({ label, val, color }) => (
            <div key={label} className="rounded bg-[#161b22] px-2 py-1.5 text-center">
              <div className="font-mono font-semibold" style={{ fontSize: 13, color }}>{val}</div>
              <div className="text-[9px] text-[#8b949e] uppercase tracking-wide mt-0.5">{label}</div>
            </div>
          ))}
        </div>
      )}

      {tx == null && packets.length === 0 && running && (
        <p className="text-[10px] text-[#8b949e] animate-pulse">Waiting for responses…</p>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Traceroute view
// ---------------------------------------------------------------------------
// Handles both Linux traceroute and macOS/BSD traceroute line formats
const HOP_RE = /^\s*(\d+)\s+(.*)/
const HOP_MS_RE = /([\d.]+)\s*ms/g
const HOP_HOST_RE = /([\w.-]+(?:\.[a-z]{2,}))\s+\(/
const HOP_IP_RE = /\(?([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\)?/

function parseTraceroute(lines) {
  const hops = []
  for (const l of lines) {
    const m = l.match(HOP_RE)
    if (!m) continue
    const num  = +m[1]
    const rest = m[2]
    if (/^\*/.test(rest.trim()) || rest.trim() === '* * *') {
      hops.push({ num, host: null, ip: null, ms: [] })
      continue
    }
    const msMatches = [...rest.matchAll(HOP_MS_RE)].map(x => +x[1])
    const hostMatch = rest.match(HOP_HOST_RE)
    const ipMatch   = rest.match(HOP_IP_RE)
    hops.push({
      num,
      host: hostMatch ? hostMatch[1] : null,
      ip:   ipMatch   ? ipMatch[1]   : null,
      ms:   msMatches,
    })
  }
  return hops
}

function TracerouteView({ lines, running }) {
  const hops = parseTraceroute(lines)
  if (!hops.length && running) {
    return <p className="text-[10px] text-[#8b949e] animate-pulse">Probing hops…</p>
  }
  return (
    <div className="space-y-0">
      {/* header */}
      <div className="grid gap-2 pb-1 border-b border-[#21262d] mb-1"
        style={{ gridTemplateColumns: '18px 1fr 70px' }}>
        <span className="text-[9px] font-semibold uppercase tracking-wider text-[#8b949e]">#</span>
        <span className="text-[9px] font-semibold uppercase tracking-wider text-[#8b949e]">Host</span>
        <span className="text-[9px] font-semibold uppercase tracking-wider text-[#8b949e] text-right">ms</span>
      </div>
      {hops.map(hop => {
        const avgMs = hop.ms.length ? hop.ms.reduce((a, b) => a + b, 0) / hop.ms.length : null
        return (
          <div key={hop.num}
            className="grid gap-2 py-1 border-b border-[#21262d] last:border-0 items-center"
            style={{ gridTemplateColumns: '18px 1fr 70px' }}>
            <span className="font-mono text-[10px] text-[#8b949e]">{hop.num}</span>
            <div className="min-w-0">
              {hop.host || hop.ip ? (
                <>
                  {hop.host && <div className="text-[10px] text-[#c9d1d9] truncate">{hop.host}</div>}
                  {hop.ip   && <div className="font-mono text-[9px] text-[#8b949e] truncate">{hop.ip}</div>}
                </>
              ) : (
                <span className="text-[10px] text-[#8b949e] italic">* * *</span>
              )}
            </div>
            <div className="text-right">
              {avgMs != null ? (
                <span className="font-mono text-[10px]" style={{ color: latencyColor(avgMs) }}>
                  {avgMs.toFixed(1)}
                </span>
              ) : (
                <span className="text-[10px] text-[#8b949e]">—</span>
              )}
            </div>
          </div>
        )
      })}
      {running && hops.length > 0 && (
        <div className="py-1 text-[10px] text-[#8b949e] animate-pulse flex items-center gap-1">
          <span className="inline-block w-1.5 h-1.5 rounded-full bg-green-500 animate-ping" />
          probing…
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Vuln scan view — progress bar + findings summary
// ---------------------------------------------------------------------------
const SEV_STYLE = {
  critical: { bg: 'rgba(239,68,68,0.18)',   color: '#f87171' },
  high:     { bg: 'rgba(249,115,22,0.18)',  color: '#fb923c' },
  medium:   { bg: 'rgba(245,158,11,0.18)',  color: '#fbbf24' },
  low:      { bg: 'rgba(59,130,246,0.18)',  color: '#60a5fa' },
  info:     { bg: 'rgba(139,92,246,0.18)',  color: '#a78bfa' },
}

function parseVulnStream(lines) {
  let totalPhases      = 1
  let currentPhase     = 0
  let currentPhaseName = ''
  let currentPercent   = 0
  let lastRps          = null
  const findings       = []
  let done             = false
  let doneResult       = null

  for (const l of lines) {
    // Total phases from scan plan line
    const planM = l.match(/\[INFO\] Scan plan: (\d+) phase/)
    if (planM) totalPhases = Math.max(1, parseInt(planM[1]))

    // Phase start: "[INFO] → label"
    if (l.startsWith('[INFO] → ')) {
      currentPhase++
      currentPhaseName = l.slice('[INFO] → '.length)
      currentPercent   = 0
    }

    // Nuclei stats JSON (emitted as "[NUCLEI] {...}")
    if (l.startsWith('[NUCLEI] {')) {
      try {
        const s = JSON.parse(l.slice('[NUCLEI] '.length))
        if (s.percent !== undefined) currentPercent = parseInt(s.percent) || 0
        if (s.rps)                   lastRps        = s.rps
      } catch { /* ignore malformed lines */ }
    }

    // Findings emitted after all phases: "[SEVERITY] name — matched_at"
    const findM = l.match(/^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\] (.+?) — (.+)$/)
    if (findM) findings.push({ sev: findM[1].toLowerCase(), name: findM[2] })

    // Completion
    if (l.startsWith('RESULT:')) {
      done = true
      try { doneResult = JSON.parse(l.slice('RESULT:'.length)) } catch { /* ignore */ }
    }
  }

  const overallPercent = done ? 100
    : currentPhase === 0   ? 0
    : Math.min(99, Math.round(((currentPhase - 1) * 100 + currentPercent) / totalPhases))

  return { totalPhases, currentPhase, currentPhaseName, overallPercent, lastRps, findings, done, doneResult }
}

function VulnProgressView({ lines, running }) {
  if (!lines.length && running) {
    return <p className="text-[10px] text-[#8b949e] animate-pulse">Initialising scan…</p>
  }
  if (!lines.length) return null

  const { totalPhases, currentPhase, currentPhaseName, overallPercent,
          lastRps, findings, done, doneResult } = parseVulnStream(lines)

  return (
    <div className="space-y-2.5">

      {/* Progress bar */}
      <div className="space-y-1">
        <div className="flex items-center justify-between text-[10px]">
          <span className="truncate mr-2" style={{ color: '#c9d1d9' }}>
            {done        ? 'Scan complete'
             : currentPhase > 0 ? currentPhaseName
             : 'Preparing scan…'}
          </span>
          <span className="font-mono shrink-0" style={{ color: '#8b949e' }}>{overallPercent}%</span>
        </div>
        <div className="h-1.5 rounded-full overflow-hidden" style={{ background: '#21262d' }}>
          <div
            className="h-full rounded-full transition-all duration-700"
            style={{
              width:      `${overallPercent}%`,
              background: done ? '#22c55e' : 'var(--color-brand)',
            }}
          />
        </div>
        {(totalPhases > 1 || lastRps) && (
          <div className="flex justify-between text-[9px]" style={{ color: '#8b949e' }}>
            {totalPhases > 1 && currentPhase > 0
              ? <span>Phase {Math.min(currentPhase, totalPhases)} / {totalPhases}</span>
              : <span />}
            {lastRps && running && <span>{lastRps} req/s</span>}
          </div>
        )}
      </div>

      {/* Findings list */}
      {findings.length > 0 && (
        <div className="space-y-1">
          <p className="text-[9px] font-semibold uppercase tracking-wider" style={{ color: '#8b949e' }}>
            {findings.length} finding{findings.length !== 1 ? 's' : ''}
          </p>
          {findings.map((f, i) => {
            const sc = SEV_STYLE[f.sev] || SEV_STYLE.info
            return (
              <div key={i} className="flex items-center gap-1.5">
                <span className="px-1 py-0.5 rounded text-[9px] font-bold uppercase shrink-0"
                  style={{ background: sc.bg, color: sc.color }}>
                  {f.sev.slice(0, 4)}
                </span>
                <span className="text-[10px] truncate" style={{ color: '#c9d1d9' }}>{f.name}</span>
              </div>
            )
          })}
        </div>
      )}

      {/* Done summary (no findings) */}
      {done && findings.length === 0 && (
        <p className="text-[10px] font-medium" style={{ color: '#22c55e' }}>
          ✓ No vulnerabilities found
        </p>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Generic fallback (rescan status messages, etc.)
// ---------------------------------------------------------------------------
function GenericView({ lines, running }) {
  return (
    <div className="space-y-0.5">
      {lines.filter(l => l.trim()).map((l, i) => (
        <div key={i} className="font-mono leading-relaxed break-words"
          style={{ fontSize: '10px', ...lineStyle(l) }}>
          {l}
        </div>
      ))}
      {running && <span className="inline-block animate-pulse text-green-400" style={{ fontSize: 10 }}>▌</span>}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Public export
// ---------------------------------------------------------------------------
export function StreamOutput({ lines = [], running = false, onStop, mode = 'generic' }) {
  if (!lines.length && !running) return null

  const inner = (() => {
    switch (mode) {
      case 'ping':       return <PingView       lines={lines} running={running} />
      case 'traceroute': return <TracerouteView lines={lines} running={running} />
      case 'vuln':       return <VulnProgressView lines={lines} running={running} />
      default:           return <GenericView    lines={lines} running={running} />
    }
  })()

  return (
    <TermChrome onStop={onStop} running={running} rawLines={lines}
      defaultOpen={mode === 'generic'}>
      {inner}
    </TermChrome>
  )
}
