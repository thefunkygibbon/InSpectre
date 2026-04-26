import { useState, useCallback } from 'react'
import { Wifi, Globe, Shield, Server, Mail, ChevronRight, Loader, Menu, X } from 'lucide-react'
import { useStreamAction } from '../hooks/useStreamAction'
import { StreamOutput } from './StreamOutput'
import { api } from '../api'

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------
function useTool() {
  const [loading, setLoading] = useState(false)
  const [result,  setResult]  = useState(null)
  const [error,   setError]   = useState(null)

  const run = useCallback(async (fn) => {
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      setResult(await fn())
    } catch (e) {
      setError(e.message || String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  return { loading, result, error, run, setResult }
}

function ToolCard({ title, children }) {
  return (
    <div className="rounded-xl border border-[#30363d] bg-[#0d1117] overflow-hidden mb-4">
      <div className="px-4 py-2.5 border-b border-[#21262d] bg-[#161b22]">
        <span className="text-xs font-semibold uppercase tracking-wider text-[#8b949e]">{title}</span>
      </div>
      <div className="p-4">{children}</div>
    </div>
  )
}

function FieldRow({ label, value, mono = false }) {
  if (!value && value !== 0) return null
  return (
    <div className="flex gap-3 py-1 border-b border-[#21262d] last:border-0 text-xs">
      <span className="w-28 shrink-0 text-[#8b949e]">{label}</span>
      <span className={`flex-1 break-all ${mono ? 'font-mono text-[#c9d1d9]' : 'text-[#c9d1d9]'}`}>{String(value)}</span>
    </div>
  )
}

function ErrorBanner({ msg }) {
  if (!msg) return null
  return (
    <div className="mt-3 px-3 py-2 rounded-lg text-xs font-mono"
      style={{ background: 'rgba(239,68,68,0.1)', color: '#f87171', border: '1px solid rgba(239,68,68,0.2)' }}>
      {msg}
    </div>
  )
}

function SubmitBtn({ loading, children }) {
  return (
    <button type="submit" disabled={loading}
      className="mt-3 px-4 py-1.5 rounded-lg text-xs font-semibold text-white transition-opacity disabled:opacity-50"
      style={{ background: 'var(--color-brand)' }}>
      {loading ? <span className="flex items-center gap-1.5"><Loader size={11} className="animate-spin" />{children}</span> : children}
    </button>
  )
}

function RecordList({ records, mono = true }) {
  if (!records?.length) return <p className="text-xs text-[#8b949e] italic">None</p>
  return (
    <div className="space-y-1 mt-1">
      {records.map((r, i) => (
        <div key={i} className={`text-xs px-2 py-1 rounded bg-[#161b22] ${mono ? 'font-mono text-[#c9d1d9]' : 'text-[#c9d1d9]'} break-all`}>{r}</div>
      ))}
    </div>
  )
}

// ---------------------------------------------------------------------------
// IP Tools
// ---------------------------------------------------------------------------
function PingTool() {
  const [host, setHost] = useState('')
  const stream = useStreamAction()
  function handleSubmit(e) {
    e.preventDefault()
    if (!host.trim()) return
    stream.start(`/tools/ping?host=${encodeURIComponent(host.trim())}`)
  }
  return (
    <ToolCard title="Ping">
      <form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
        <input className="input flex-1 text-xs min-w-0" placeholder="Host or IP address"
          value={host} onChange={e => setHost(e.target.value)} />
        <button type="submit" disabled={stream.running}
          className="px-3 py-1.5 rounded-lg text-xs font-semibold text-white disabled:opacity-50"
          style={{ background: 'var(--color-brand)' }}>
          {stream.running ? 'Running…' : 'Ping'}
        </button>
        {stream.running && (
          <button type="button" onClick={stream.stop}
            className="px-3 py-1.5 rounded-lg text-xs text-[#8b949e] hover:text-white border border-[#30363d]">
            Stop
          </button>
        )}
      </form>
      {(stream.lines.length > 0 || stream.running) && (
        <StreamOutput lines={stream.lines} running={stream.running} onStop={stream.stop} mode="ping" />
      )}
    </ToolCard>
  )
}

function TracerouteTool() {
  const [host, setHost] = useState('')
  const stream = useStreamAction()
  function handleSubmit(e) {
    e.preventDefault()
    if (!host.trim()) return
    stream.start(`/tools/traceroute?host=${encodeURIComponent(host.trim())}`)
  }
  return (
    <ToolCard title="Traceroute">
      <form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
        <input className="input flex-1 text-xs min-w-0" placeholder="Host or IP address"
          value={host} onChange={e => setHost(e.target.value)} />
        <button type="submit" disabled={stream.running}
          className="px-3 py-1.5 rounded-lg text-xs font-semibold text-white disabled:opacity-50"
          style={{ background: 'var(--color-brand)' }}>
          {stream.running ? 'Running…' : 'Trace'}
        </button>
        {stream.running && (
          <button type="button" onClick={stream.stop}
            className="px-3 py-1.5 rounded-lg text-xs text-[#8b949e] hover:text-white border border-[#30363d]">
            Stop
          </button>
        )}
      </form>
      {(stream.lines.length > 0 || stream.running) && (
        <StreamOutput lines={stream.lines} running={stream.running} onStop={stream.stop} mode="traceroute" />
      )}
    </ToolCard>
  )
}

function PortScanTool() {
  const [host,  setHost]  = useState('')
  const [ports, setPorts] = useState('1-1024')
  const stream = useStreamAction()
  function handleSubmit(e) {
    e.preventDefault()
    if (!host.trim()) return
    stream.start(`/tools/portscan?host=${encodeURIComponent(host.trim())}&ports=${encodeURIComponent(ports.trim() || '1-1024')}`)
  }
  return (
    <ToolCard title="Port Scanner">
      <form onSubmit={handleSubmit} className="space-y-2">
        <div className="flex flex-wrap gap-2">
          <input className="input flex-1 text-xs min-w-0" placeholder="Host or IP address"
            value={host} onChange={e => setHost(e.target.value)} />
          <input className="input w-full sm:w-32 text-xs font-mono" placeholder="Ports (e.g. 1-1024)"
            value={ports} onChange={e => setPorts(e.target.value)} />
        </div>
        <div className="flex gap-2 items-center flex-wrap">
          <button type="submit" disabled={stream.running}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold text-white disabled:opacity-50"
            style={{ background: 'var(--color-brand)' }}>
            {stream.running ? 'Scanning…' : 'Scan'}
          </button>
          {stream.running && (
            <button type="button" onClick={stream.stop}
              className="px-3 py-1.5 rounded-lg text-xs text-[#8b949e] hover:text-white border border-[#30363d]">
              Stop
            </button>
          )}
          <span className="text-[10px] text-[#8b949e]">Common: 22,80,443 · All: 1-65535</span>
        </div>
      </form>
      {(stream.lines.length > 0 || stream.running) && (
        <StreamOutput lines={stream.lines} running={stream.running} onStop={stream.stop} mode="generic" />
      )}
    </ToolCard>
  )
}

function ReverseDnsTool() {
  const [ip, setIp] = useState('')
  const { loading, result, error, run } = useTool()
  function handleSubmit(e) {
    e.preventDefault()
    if (!ip.trim()) return
    run(() => api.toolsRdns(ip.trim()))
  }
  return (
    <ToolCard title="Reverse DNS (PTR)">
      <form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
        <input className="input flex-1 text-xs font-mono min-w-0" placeholder="IP address"
          value={ip} onChange={e => setIp(e.target.value)} />
        <SubmitBtn loading={loading}>Lookup</SubmitBtn>
      </form>
      {result && (
        <div className="mt-3 space-y-0">
          <FieldRow label="IP"       value={result.ip} mono />
          <FieldRow label="Hostname" value={result.hostname ?? '—'} mono />
          {result.error && <FieldRow label="Error" value={result.error} />}
        </div>
      )}
      <ErrorBanner msg={error} />
    </ToolCard>
  )
}

// ---------------------------------------------------------------------------
// DNS Tools
// ---------------------------------------------------------------------------
const DNS_TYPES = ['A', 'AAAA', 'MX', 'CNAME', 'TXT', 'NS', 'SOA', 'PTR']

function DnsLookupTool() {
  const [host, setHost]   = useState('')
  const [type, setType]   = useState('A')
  const { loading, result, error, run } = useTool()
  function handleSubmit(e) {
    e.preventDefault()
    if (!host.trim()) return
    run(() => api.toolsDns(host.trim(), type))
  }
  return (
    <ToolCard title="DNS Record Lookup">
      <form onSubmit={handleSubmit} className="flex gap-2 flex-wrap">
        <input className="input flex-1 text-xs min-w-0" placeholder="Domain or hostname"
          value={host} onChange={e => setHost(e.target.value)} style={{ minWidth: 140 }} />
        <select className="input w-24 text-xs" value={type} onChange={e => setType(e.target.value)}>
          {DNS_TYPES.map(t => <option key={t}>{t}</option>)}
        </select>
        <SubmitBtn loading={loading}>Lookup</SubmitBtn>
      </form>
      {result && (
        <div className="mt-3">
          <div className="flex items-center gap-2 mb-2 flex-wrap">
            <span className="text-xs font-mono text-[#8b949e]">{result.host}</span>
            <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-[#161b22] text-[#8b949e]">{result.type}</span>
            {result.ttl != null && <span className="text-[10px] text-[#8b949e]">TTL {result.ttl}s</span>}
          </div>
          {result.error
            ? <p className="text-xs text-[#f87171]">{result.error}</p>
            : <RecordList records={result.records} />}
        </div>
      )}
      <ErrorBanner msg={error} />
    </ToolCard>
  )
}

function DnsPropagationTool() {
  const [host, setHost] = useState('')
  const [type, setType] = useState('A')
  const { loading, result, error, run } = useTool()
  function handleSubmit(e) {
    e.preventDefault()
    if (!host.trim()) return
    run(() => api.toolsDnsPropagation(host.trim(), type))
  }
  const propTypes = ['A', 'AAAA', 'MX', 'CNAME', 'TXT', 'NS']
  return (
    <ToolCard title="DNS Propagation Checker">
      <form onSubmit={handleSubmit} className="flex gap-2 flex-wrap">
        <input className="input flex-1 text-xs min-w-0" placeholder="Domain name"
          value={host} onChange={e => setHost(e.target.value)} style={{ minWidth: 140 }} />
        <select className="input w-24 text-xs" value={type} onChange={e => setType(e.target.value)}>
          {propTypes.map(t => <option key={t}>{t}</option>)}
        </select>
        <SubmitBtn loading={loading}>Check</SubmitBtn>
      </form>
      {result && (
        <div className="mt-3 space-y-1">
          {result.results.map(r => (
            <div key={r.name} className="flex items-start gap-3 py-1.5 px-2 rounded-lg bg-[#161b22]">
              <span className={`mt-0.5 w-2 h-2 rounded-full shrink-0 ${r.error ? 'bg-red-500' : 'bg-green-500'}`} />
              <div className="flex-1 min-w-0">
                <span className="text-xs font-mono text-[#c9d1d9]">{r.name}</span>
                {r.error
                  ? <p className="text-[10px] text-[#f87171] mt-0.5">{r.error}</p>
                  : <p className="text-[10px] font-mono text-[#8b949e] mt-0.5 break-all">{r.records.join(' · ')}</p>}
              </div>
            </div>
          ))}
        </div>
      )}
      <ErrorBanner msg={error} />
    </ToolCard>
  )
}

// ---------------------------------------------------------------------------
// Web Tools
// ---------------------------------------------------------------------------
function HttpHeadersTool() {
  const [url, setUrl] = useState('https://')
  const { loading, result, error, run } = useTool()
  function handleSubmit(e) {
    e.preventDefault()
    if (!url.trim()) return
    run(() => api.toolsHttpHeaders(url.trim()))
  }
  const SECURITY_HEADERS = [
    'strict-transport-security', 'content-security-policy', 'x-frame-options',
    'x-content-type-options', 'referrer-policy', 'permissions-policy',
  ]
  return (
    <ToolCard title="HTTP Header Checker">
      <form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
        <input className="input flex-1 text-xs font-mono min-w-0" placeholder="https://example.com"
          value={url} onChange={e => setUrl(e.target.value)} />
        <SubmitBtn loading={loading}>Check</SubmitBtn>
      </form>
      {result && (
        <div className="mt-3 space-y-3">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`px-2 py-0.5 rounded text-xs font-mono font-semibold ${
              result.status < 300 ? 'bg-green-500/15 text-green-400' :
              result.status < 400 ? 'bg-yellow-500/15 text-yellow-400' : 'bg-red-500/15 text-red-400'
            }`}>
              {result.status} {result.reason}
            </span>
            {result.redirect && (
              <span className="text-xs text-[#8b949e] font-mono truncate max-w-xs">→ {result.redirect}</span>
            )}
          </div>
          <div>
            <p className="text-[10px] uppercase tracking-wider text-[#8b949e] mb-1">Security Headers</p>
            <div className="space-y-0.5">
              {SECURITY_HEADERS.map(h => {
                const val = Object.entries(result.headers).find(([k]) => k.toLowerCase() === h)?.[1]
                return (
                  <div key={h} className="flex items-start gap-2 text-xs py-1 px-2 rounded bg-[#161b22]">
                    <span className={`mt-0.5 w-1.5 h-1.5 rounded-full shrink-0 ${val ? 'bg-green-500' : 'bg-red-500/60'}`} />
                    <span className="font-mono text-[#8b949e] w-48 shrink-0 truncate text-[10px]">{h}</span>
                    {val ? <span className="text-[#c9d1d9] font-mono text-[10px] break-all">{val}</span>
                          : <span className="text-[#8b949e] italic text-[10px]">not set</span>}
                  </div>
                )
              })}
            </div>
          </div>
          <details className="text-xs">
            <summary className="cursor-pointer text-[#8b949e] hover:text-[#c9d1d9]">All headers ({Object.keys(result.headers).length})</summary>
            <div className="mt-2 space-y-0">
              {Object.entries(result.headers).map(([k, v]) => (
                <div key={k} className="flex gap-2 py-0.5 border-b border-[#21262d] last:border-0">
                  <span className="w-40 shrink-0 font-mono text-[10px] text-[#8b949e] truncate">{k}</span>
                  <span className="font-mono text-[10px] text-[#c9d1d9] break-all">{v}</span>
                </div>
              ))}
            </div>
          </details>
        </div>
      )}
      <ErrorBanner msg={error} />
    </ToolCard>
  )
}

function SslTool() {
  const [host, setHost] = useState('')
  const [port, setPort] = useState('443')
  const { loading, result, error, run } = useTool()
  function handleSubmit(e) {
    e.preventDefault()
    if (!host.trim()) return
    run(() => api.toolsSsl(host.trim(), parseInt(port) || 443))
  }
  function certAge(notAfter) {
    if (!notAfter) return null
    const d = new Date(notAfter)
    return Math.round((d - new Date()) / 86400000)
  }
  return (
    <ToolCard title="SSL/TLS Certificate">
      <form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
        <input className="input flex-1 text-xs min-w-0" placeholder="Hostname (no https://)"
          value={host} onChange={e => setHost(e.target.value)} />
        <input className="input w-20 text-xs font-mono" placeholder="Port"
          value={port} onChange={e => setPort(e.target.value)} />
        <SubmitBtn loading={loading}>Check</SubmitBtn>
      </form>
      {result && (
        <div className="mt-3 space-y-2">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`px-2 py-0.5 rounded text-xs font-semibold ${result.valid ? 'bg-green-500/15 text-green-400' : 'bg-red-500/15 text-red-400'}`}>
              {result.valid ? 'Valid' : 'Invalid'}
            </span>
            {result.not_after && (() => {
              const days = certAge(result.not_after)
              return (
                <span className={`text-xs ${days < 30 ? 'text-yellow-400' : days < 0 ? 'text-red-400' : 'text-[#8b949e]'}`}>
                  {days >= 0 ? `Expires in ${days} days` : `Expired ${Math.abs(days)} days ago`}
                </span>
              )
            })()}
          </div>
          {result.error && <p className="text-xs text-[#f87171]">{result.error}</p>}
          <FieldRow label="Common Name" value={result.subject?.commonName} mono />
          <FieldRow label="Issuer"      value={result.issuer?.organizationName || result.issuer?.commonName} />
          <FieldRow label="Valid From"  value={result.not_before} mono />
          <FieldRow label="Valid Until" value={result.not_after} mono />
          <FieldRow label="Protocol"    value={result.protocol} mono />
          <FieldRow label="Cipher"      value={result.cipher} mono />
          {result.san?.length > 0 && (
            <div className="text-xs py-1">
              <span className="text-[#8b949e] w-28 inline-block">SANs</span>
              <span className="font-mono text-[#c9d1d9]">{result.san.slice(0, 8).join(', ')}{result.san.length > 8 ? ` +${result.san.length - 8} more` : ''}</span>
            </div>
          )}
        </div>
      )}
      <ErrorBanner msg={error} />
    </ToolCard>
  )
}

// ---------------------------------------------------------------------------
// Infrastructure Tools
// ---------------------------------------------------------------------------
function GeoTool() {
  const [ip, setIp] = useState('')
  const { loading, result, error, run } = useTool()
  function handleSubmit(e) {
    e.preventDefault()
    if (!ip.trim()) return
    run(() => api.toolsGeo(ip.trim()))
  }
  return (
    <ToolCard title="IP Geolocation">
      <p className="text-[10px] text-[#8b949e] mb-2">Uses ip-api.com (free, no key required)</p>
      <form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
        <input className="input flex-1 text-xs font-mono min-w-0" placeholder="IP address"
          value={ip} onChange={e => setIp(e.target.value)} />
        <SubmitBtn loading={loading}>Lookup</SubmitBtn>
      </form>
      {result && (
        <div className="mt-3 space-y-0">
          {result.status === 'fail'
            ? <p className="text-xs text-[#f87171]">{result.message}</p>
            : <>
                <FieldRow label="IP"         value={result.query} mono />
                <FieldRow label="Country"    value={`${result.country} (${result.countryCode})`} />
                <FieldRow label="Region"     value={result.regionName} />
                <FieldRow label="City"       value={result.city} />
                <FieldRow label="Timezone"   value={result.timezone} mono />
                <FieldRow label="ISP"        value={result.isp} />
                <FieldRow label="Org"        value={result.org} />
                <FieldRow label="AS"         value={result.as} mono />
                {result.lat && <FieldRow label="Coordinates" value={`${result.lat}, ${result.lon}`} mono />}
              </>}
        </div>
      )}
      <ErrorBanner msg={error} />
    </ToolCard>
  )
}

function WhoisTool() {
  const [host, setHost] = useState('')
  const { loading, result, error, run } = useTool()
  function handleSubmit(e) {
    e.preventDefault()
    if (!host.trim()) return
    run(() => api.toolsWhois(host.trim()))
  }
  return (
    <ToolCard title="WHOIS Lookup">
      <form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
        <input className="input flex-1 text-xs min-w-0" placeholder="Domain or IP address"
          value={host} onChange={e => setHost(e.target.value)} />
        <SubmitBtn loading={loading}>Lookup</SubmitBtn>
      </form>
      {result && (
        <div className="mt-3">
          <pre className="text-[10px] font-mono text-[#8b949e] max-h-80 overflow-y-auto whitespace-pre-wrap break-all leading-relaxed bg-[#161b22] rounded-lg p-3">
            {result.output || 'No output'}
          </pre>
        </div>
      )}
      <ErrorBanner msg={error} />
    </ToolCard>
  )
}

// ---------------------------------------------------------------------------
// Email Tools
// ---------------------------------------------------------------------------
function EmailTool() {
  const [domain, setDomain] = useState('')
  const { loading, result, error, run } = useTool()
  function handleSubmit(e) {
    e.preventDefault()
    if (!domain.trim()) return
    run(() => api.toolsEmail(domain.trim()))
  }
  function spfStatus(records) {
    if (!records?.length) return { color: '#f87171', label: 'Missing' }
    return { color: '#22c55e', label: 'Present' }
  }
  function dmarcStatus(records) {
    if (!records?.length) return { color: '#f87171', label: 'Missing' }
    const r = records[0] || ''
    if (r.includes('p=none'))       return { color: '#fbbf24', label: 'None (monitoring only)' }
    if (r.includes('p=quarantine')) return { color: '#f59e0b', label: 'Quarantine' }
    if (r.includes('p=reject'))     return { color: '#22c55e', label: 'Reject' }
    return { color: '#fbbf24', label: 'Present' }
  }
  return (
    <ToolCard title="Email Server Analysis">
      <form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
        <input className="input flex-1 text-xs min-w-0" placeholder="Domain (e.g. example.com)"
          value={domain} onChange={e => setDomain(e.target.value)} />
        <SubmitBtn loading={loading}>Analyse</SubmitBtn>
      </form>
      {result && (
        <div className="mt-3 space-y-4">
          <div>
            <p className="text-[10px] uppercase tracking-wider text-[#8b949e] mb-1.5">MX Records</p>
            <RecordList records={result.mx} />
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            {[
              { name: 'SPF',   ...spfStatus(result.spf) },
              { name: 'DMARC', ...dmarcStatus(result.dmarc) },
              { name: 'DKIM',
                color: Object.keys(result.dkim || {}).length ? '#22c55e' : '#f87171',
                label: Object.keys(result.dkim || {}).length
                  ? `Found (${Object.keys(result.dkim).join(', ')})`
                  : 'Not detected',
              },
            ].map(s => (
              <div key={s.name} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#161b22]">
                <span className="w-2 h-2 rounded-full shrink-0" style={{ background: s.color }} />
                <span className="text-xs text-[#8b949e] w-14 shrink-0">{s.name}</span>
                <span className="text-xs font-semibold truncate" style={{ color: s.color }}>{s.label}</span>
              </div>
            ))}
          </div>
          {result.spf?.length > 0 && (
            <div>
              <p className="text-[10px] uppercase tracking-wider text-[#8b949e] mb-1">SPF Record</p>
              <RecordList records={result.spf} />
            </div>
          )}
          {result.dmarc?.length > 0 && (
            <div>
              <p className="text-[10px] uppercase tracking-wider text-[#8b949e] mb-1">DMARC Record</p>
              <RecordList records={result.dmarc} />
            </div>
          )}
          {Object.entries(result.dkim || {}).map(([sel, recs]) => (
            <div key={sel}>
              <p className="text-[10px] uppercase tracking-wider text-[#8b949e] mb-1">DKIM ({sel})</p>
              <RecordList records={recs} />
            </div>
          ))}
          {result.nameservers?.length > 0 && (
            <div>
              <p className="text-[10px] uppercase tracking-wider text-[#8b949e] mb-1">Nameservers</p>
              <RecordList records={result.nameservers} />
            </div>
          )}
        </div>
      )}
      <ErrorBanner msg={error} />
    </ToolCard>
  )
}

// ---------------------------------------------------------------------------
// Main page component
// ---------------------------------------------------------------------------
const SECTIONS = [
  { id: 'ip',    label: 'IP Tools',       Icon: Wifi,   desc: 'Ping · Traceroute · Port scan · Reverse DNS' },
  { id: 'dns',   label: 'DNS Tools',      Icon: Globe,  desc: 'Record lookup · Propagation checker' },
  { id: 'web',   label: 'Web Tools',      Icon: Shield, desc: 'HTTP headers · SSL/TLS certificate' },
  { id: 'infra', label: 'Infrastructure', Icon: Server, desc: 'IP geolocation · WHOIS lookup' },
  { id: 'email', label: 'Email Tools',    Icon: Mail,   desc: 'MX · SPF · DMARC · DKIM' },
]

export function NetworkTools() {
  const [section,      setSection]      = useState('ip')
  const [sidebarOpen,  setSidebarOpen]  = useState(false)

  const activeSection = SECTIONS.find(s => s.id === section)

  function selectSection(id) {
    setSection(id)
    setSidebarOpen(false)
  }

  return (
    <div className="flex gap-0 sm:gap-6 min-h-[60vh]">

      {/* Mobile nav toggle */}
      <div className="sm:hidden mb-4 flex items-center gap-3">
        <button onClick={() => setSidebarOpen(v => !v)}
          className="btn-ghost p-2 flex items-center gap-2 text-xs"
          aria-label="Toggle tool categories">
          <Menu size={16} />
          <span>{activeSection?.label}</span>
        </button>
      </div>

      {/* Sidebar — hidden on mobile unless open */}
      <div className={`
        sm:block w-48 shrink-0
        ${sidebarOpen ? 'fixed inset-0 z-40 flex items-start pt-16 bg-black/60' : 'hidden sm:block'}
      `}
        onClick={e => { if (e.target === e.currentTarget) setSidebarOpen(false) }}>
        <div className={`
          ${sidebarOpen ? 'w-56 rounded-xl mx-4 shadow-2xl' : 'w-48'}
          border rounded-xl overflow-hidden
        `} style={{ background: '#0d1117', borderColor: '#30363d' }}>
          <div className="px-4 py-3 border-b border-[#21262d] flex items-center justify-between">
            <div>
              <p className="text-xs font-semibold" style={{ color: 'var(--color-text)' }}>Network Tools</p>
              <p className="text-[10px] mt-0.5 text-[#8b949e]">Diagnostics & analysis</p>
            </div>
            {sidebarOpen && (
              <button onClick={() => setSidebarOpen(false)} className="p-1 text-[#8b949e]"><X size={14} /></button>
            )}
          </div>
          <nav className="p-2 space-y-0.5">
            {SECTIONS.map(s => (
              <button key={s.id}
                onClick={() => selectSection(s.id)}
                className="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-left transition-colors"
                style={section === s.id
                  ? { background: 'var(--color-brand)', color: 'white' }
                  : { color: '#8b949e' }}>
                <s.Icon size={14} className="shrink-0" />
                <span className="text-xs font-medium">{s.label}</span>
              </button>
            ))}
          </nav>
        </div>
      </div>

      {/* Content area */}
      <div className="flex-1 min-w-0">
        <div className="mb-4 hidden sm:block">
          <p className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>
            {activeSection?.label}
          </p>
          <p className="text-[10px] mt-0.5" style={{ color: 'var(--color-text-faint)' }}>
            {activeSection?.desc}
          </p>
        </div>

        {section === 'ip' && (
          <>
            <PingTool />
            <TracerouteTool />
            <PortScanTool />
            <ReverseDnsTool />
          </>
        )}
        {section === 'dns' && (
          <>
            <DnsLookupTool />
            <DnsPropagationTool />
          </>
        )}
        {section === 'web' && (
          <>
            <HttpHeadersTool />
            <SslTool />
          </>
        )}
        {section === 'infra' && (
          <>
            <GeoTool />
            <WhoisTool />
          </>
        )}
        {section === 'email' && (
          <EmailTool />
        )}
      </div>
    </div>
  )
}
