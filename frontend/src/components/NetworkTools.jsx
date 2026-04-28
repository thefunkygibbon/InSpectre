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
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] overflow-hidden mb-4">
      <div className="px-4 py-2.5 border-b border-[var(--color-border)] bg-[var(--color-surface-offset)]">
        <span className="text-xs font-semibold uppercase tracking-wider text-[var(--color-text-muted)]">{title}</span>
      </div>
      <div className="p-4">{children}</div>
    </div>
  )
}

function FieldRow({ label, value, mono = false }) {
  if (!value && value !== 0) return null
  return (
    <div className="flex gap-3 py-1 border-b border-[var(--color-border)] last:border-0 text-xs">
      <span className="w-28 shrink-0 text-[var(--color-text-muted)]">{label}</span>
      <span className={`flex-1 break-all ${mono ? 'font-mono text-[var(--color-text)]' : 'text-[var(--color-text)]'}`}>{String(value)}</span>
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
  if (!records?.length) return <p className="text-xs text-[var(--color-text-muted)] italic">None</p>
  return (
    <div className="space-y-1 mt-1">
      {records.map((r, i) => (
        <div key={i} className={`text-xs px-2 py-1 rounded bg-[var(--color-surface-offset)] ${mono ? 'font-mono text-[var(--color-text)]' : 'text-[var(--color-text)]'} break-all`}>{r}</div>
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
            className="px-3 py-1.5 rounded-lg text-xs text-[var(--color-text-muted)] hover:text-white border border-[var(--color-border)]">
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
            className="px-3 py-1.5 rounded-lg text-xs text-[var(--color-text-muted)] hover:text-white border border-[var(--color-border)]">
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
              className="px-3 py-1.5 rounded-lg text-xs text-[var(--color-text-muted)] hover:text-white border border-[var(--color-border)]">
              Stop
            </button>
          )}
          <span className="text-[10px] text-[var(--color-text-muted)]">Common: 22,80,443 · All: 1-65535</span>
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
const DNS_TYPES = ['A', 'AAAA', 'MX', 'CNAME', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'CAA', 'DS', 'DNSKEY', 'ALL']

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
            <span className="text-xs font-mono text-[var(--color-text-muted)]">{result.host}</span>
            <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-[var(--color-surface-offset)] text-[var(--color-text-muted)]">{result.type}</span>
            {result.ttl != null && <span className="text-[10px] text-[var(--color-text-muted)]">TTL {result.ttl}s</span>}
          </div>
          {result.error ? (
            <p className="text-xs text-[#f87171]">{result.error}</p>
          ) : result.type === 'ALL' ? (
            <div className="space-y-2">
              {Object.entries(
                (result.all_records || []).reduce((acc, r) => {
                  ;(acc[r.type] = acc[r.type] || []).push(r)
                  return acc
                }, {})
              ).map(([t, recs]) => (
                <div key={t}>
                  <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-[var(--color-surface-offset)] text-[var(--color-text-muted)] mr-2">
                    {t} <span className="opacity-60">TTL {recs[0]?.ttl}s</span>
                  </span>
                  {recs.map((r, i) => (
                    <div key={i} className="text-xs font-mono text-[var(--color-text)] bg-[var(--color-surface-offset)] px-2 py-1 rounded mt-1 break-all">
                      {r.value}
                    </div>
                  ))}
                </div>
              ))}
              {(result.all_records || []).length === 0 && (
                <p className="text-xs text-[var(--color-text-muted)] italic">No records found</p>
              )}
            </div>
          ) : (
            <RecordList records={result.records} />
          )}
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
            <div key={r.name} className="flex items-start gap-3 py-1.5 px-2 rounded-lg bg-[var(--color-surface-offset)]">
              <span className={`mt-0.5 w-2 h-2 rounded-full shrink-0 ${r.error ? 'bg-red-500' : 'bg-green-500'}`} />
              <div className="flex-1 min-w-0">
                <span className="text-xs font-mono text-[var(--color-text)]">{r.name}</span>
                {r.error
                  ? <p className="text-[10px] text-[#f87171] mt-0.5">{r.error}</p>
                  : <p className="text-[10px] font-mono text-[var(--color-text-muted)] mt-0.5 break-all">{r.records.join(' · ')}</p>}
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
              <span className="text-xs text-[var(--color-text-muted)] font-mono truncate max-w-xs">→ {result.redirect}</span>
            )}
          </div>
          <div>
            <p className="text-[10px] uppercase tracking-wider text-[var(--color-text-muted)] mb-1">Security Headers</p>
            <div className="space-y-0.5">
              {SECURITY_HEADERS.map(h => {
                const val = Object.entries(result.headers).find(([k]) => k.toLowerCase() === h)?.[1]
                return (
                  <div key={h} className="flex items-start gap-2 text-xs py-1 px-2 rounded bg-[var(--color-surface-offset)]">
                    <span className={`mt-0.5 w-1.5 h-1.5 rounded-full shrink-0 ${val ? 'bg-green-500' : 'bg-red-500/60'}`} />
                    <span className="font-mono text-[var(--color-text-muted)] w-48 shrink-0 truncate text-[10px]">{h}</span>
                    {val ? <span className="text-[var(--color-text)] font-mono text-[10px] break-all">{val}</span>
                          : <span className="text-[var(--color-text-muted)] italic text-[10px]">not set</span>}
                  </div>
                )
              })}
            </div>
          </div>
          <details className="text-xs">
            <summary className="cursor-pointer text-[var(--color-text-muted)] hover:text-[var(--color-text)]">All headers ({Object.keys(result.headers).length})</summary>
            <div className="mt-2 space-y-0">
              {Object.entries(result.headers).map(([k, v]) => (
                <div key={k} className="flex gap-2 py-0.5 border-b border-[var(--color-border)] last:border-0">
                  <span className="w-40 shrink-0 font-mono text-[10px] text-[var(--color-text-muted)] truncate">{k}</span>
                  <span className="font-mono text-[10px] text-[var(--color-text)] break-all">{v}</span>
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
                <span className={`text-xs ${days < 30 ? 'text-yellow-400' : days < 0 ? 'text-red-400' : 'text-[var(--color-text-muted)]'}`}>
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
              <span className="text-[var(--color-text-muted)] w-28 inline-block">SANs</span>
              <span className="font-mono text-[var(--color-text)]">{result.san.slice(0, 8).join(', ')}{result.san.length > 8 ? ` +${result.san.length - 8} more` : ''}</span>
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
      <p className="text-[10px] text-[var(--color-text-muted)] mb-2">Uses ip-api.com (free, no key required)</p>
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
          <pre className="text-[10px] font-mono text-[var(--color-text-muted)] max-h-80 overflow-y-auto whitespace-pre-wrap break-all leading-relaxed bg-[var(--color-surface-offset)] rounded-lg p-3">
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
            <p className="text-[10px] uppercase tracking-wider text-[var(--color-text-muted)] mb-1.5">MX Records</p>
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
              <div key={s.name} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[var(--color-surface-offset)]">
                <span className="w-2 h-2 rounded-full shrink-0" style={{ background: s.color }} />
                <span className="text-xs text-[var(--color-text-muted)] w-14 shrink-0">{s.name}</span>
                <span className="text-xs font-semibold truncate" style={{ color: s.color }}>{s.label}</span>
              </div>
            ))}
          </div>
          {result.spf?.length > 0 && (
            <div>
              <p className="text-[10px] uppercase tracking-wider text-[var(--color-text-muted)] mb-1">SPF Record</p>
              <RecordList records={result.spf} />
            </div>
          )}
          {result.dmarc?.length > 0 && (
            <div>
              <p className="text-[10px] uppercase tracking-wider text-[var(--color-text-muted)] mb-1">DMARC Record</p>
              <RecordList records={result.dmarc} />
            </div>
          )}
          {Object.entries(result.dkim || {}).map(([sel, recs]) => (
            <div key={sel}>
              <p className="text-[10px] uppercase tracking-wider text-[var(--color-text-muted)] mb-1">DKIM ({sel})</p>
              <RecordList records={recs} />
            </div>
          ))}
          {result.nameservers?.length > 0 && (
            <div>
              <p className="text-[10px] uppercase tracking-wider text-[var(--color-text-muted)] mb-1">Nameservers</p>
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
// IP Tools — ARP Lookup + Wake-on-LAN
// ---------------------------------------------------------------------------
function ArpLookupTool({ devices }) {
  const [query, setQuery] = useState('')
  const { loading, result, error, run } = useTool()
  function handleSubmit(e) {
    e.preventDefault()
    if (!query.trim()) return
    run(() => api.toolsArpLookup(query.trim()))
  }
  return (
    <ToolCard title="ARP Table Lookup">
      <p className="text-[10px] text-[var(--color-text-muted)] mb-2">Query the probe's live ARP table. Enter an IP or MAC address.</p>
      <form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
        <input className="input flex-1 text-xs font-mono min-w-0" placeholder="IP or MAC address"
          value={query} onChange={e => setQuery(e.target.value)} />
        <SubmitBtn loading={loading}>Lookup</SubmitBtn>
      </form>
      {result && (
        <div className="mt-3 space-y-1">
          {result.matches?.length === 0 ? (
            <p className="text-xs text-[var(--color-text-muted)] italic">No match in ARP table</p>
          ) : result.matches?.map((m, i) => (
            <div key={i} className="flex items-center gap-3 text-xs px-2 py-1.5 rounded bg-[var(--color-surface-offset)]">
              <span className="font-mono text-[var(--color-text)] w-28 shrink-0">{m.ip}</span>
              <span className="font-mono text-[var(--color-text)] flex-1">{m.mac}</span>
              <span className="text-[var(--color-text-muted)]">{m.state}</span>
              {devices?.find(d => d.mac_address?.toLowerCase() === m.mac?.toLowerCase()) && (
                <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'color-mix(in srgb, var(--color-brand) 15%, transparent)', color: 'var(--color-brand)' }}>
                  Known device
                </span>
              )}
            </div>
          ))}
          {result.error && <p className="text-xs text-[#f87171]">{result.error}</p>}
        </div>
      )}
      <ErrorBanner msg={error} />
    </ToolCard>
  )
}

function WakeOnLanTool({ devices }) {
  const [mac,   setMac]   = useState('')
  const [bcast, setBcast] = useState('255.255.255.255')
  const { loading, result, error, run } = useTool()

  function handleDevicePick(e) {
    const val = e.target.value
    if (val) setMac(val)
  }

  function handleSubmit(e) {
    e.preventDefault()
    if (!mac.trim()) return
    run(() => api.toolsWakeOnLan(mac.trim(), bcast.trim()))
  }

  return (
    <ToolCard title="Wake-on-LAN">
      <p className="text-[10px] text-[var(--color-text-muted)] mb-3">
        Send a magic packet to wake a sleeping device. The device must have Wake-on-LAN enabled and be on the same LAN.
      </p>
      <form onSubmit={handleSubmit} className="space-y-3">
        {/* Device picker — sets MAC, doesn't bind to it */}
        {(devices || []).length > 0 && (
          <div>
            <label className="block text-[10px] text-[var(--color-text-muted)] mb-1">Quick-fill from known device</label>
            <select className="input w-full text-xs" defaultValue="" onChange={handleDevicePick}>
              <option value="" disabled>— select a device —</option>
              {(devices || []).map(d => (
                <option key={d.mac_address} value={d.mac_address}>
                  {d.display_name || d.ip_address}
                </option>
              ))}
            </select>
          </div>
        )}
        <div>
          <label className="block text-[10px] text-[var(--color-text-muted)] mb-1">MAC address</label>
          <input className="input w-full text-xs font-mono" placeholder="AA:BB:CC:DD:EE:FF"
            value={mac} onChange={e => setMac(e.target.value)} />
        </div>
        <div className="flex gap-2 items-end">
          <div className="flex-1">
            <label className="block text-[10px] text-[var(--color-text-muted)] mb-1">Broadcast address</label>
            <input className="input w-full text-xs font-mono"
              value={bcast} onChange={e => setBcast(e.target.value)} />
          </div>
          <SubmitBtn loading={loading}>Send Magic Packet</SubmitBtn>
        </div>
      </form>
      {result?.ok && (
        <p className="mt-2 text-xs text-green-400">✓ Magic packet sent to {result.mac}</p>
      )}
      {result?.error && <p className="mt-2 text-xs text-[#f87171]">{result.error}</p>}
      <ErrorBanner msg={error} />
    </ToolCard>
  )
}

// ---------------------------------------------------------------------------
// DNS Tools — DoH tester, DNSSEC, Reverse DNS Bulk
// ---------------------------------------------------------------------------
function DohTesterTool() {
  const [host, setHost] = useState('')
  const [type, setType] = useState('A')
  const { loading, result, error, run } = useTool()
  function handleSubmit(e) {
    e.preventDefault()
    if (!host.trim()) return
    run(() => api.toolsDoh(host.trim(), type))
  }
  return (
    <ToolCard title="DNS over HTTPS Tester">
      <p className="text-[10px] text-[var(--color-text-muted)] mb-2">Compares your local DNS against Cloudflare, Google, and Quad9 DoH resolvers. Useful for spotting DNS hijacking.</p>
      <form onSubmit={handleSubmit} className="flex gap-2 flex-wrap">
        <input className="input flex-1 text-xs min-w-0" placeholder="Domain name"
          value={host} onChange={e => setHost(e.target.value)} style={{ minWidth: 140 }} />
        <select className="input w-24 text-xs" value={type} onChange={e => setType(e.target.value)}>
          {['A', 'AAAA', 'MX', 'TXT', 'NS'].map(t => <option key={t}>{t}</option>)}
        </select>
        <SubmitBtn loading={loading}>Test</SubmitBtn>
      </form>
      {result && (
        <div className="mt-3 space-y-2">
          {result.results?.map(r => (
            <div key={r.name} className="flex items-start gap-3 py-1.5 px-2 rounded-lg bg-[var(--color-surface-offset)]">
              <span className={`mt-0.5 w-2 h-2 rounded-full shrink-0 ${r.error ? 'bg-red-500' : 'bg-green-500'}`} />
              <div className="flex-1 min-w-0">
                <span className="text-xs font-mono text-[var(--color-text)]">{r.name}</span>
                {r.error
                  ? <p className="text-[10px] text-[#f87171] mt-0.5">{r.error}</p>
                  : <p className="text-[10px] font-mono text-[var(--color-text-muted)] mt-0.5 break-all">{r.records.join(' · ') || 'No records'}</p>}
              </div>
            </div>
          ))}
        </div>
      )}
      <ErrorBanner msg={error} />
    </ToolCard>
  )
}

function DnssecTool() {
  const [host, setHost] = useState('')
  const { loading, result, error, run } = useTool()
  function handleSubmit(e) {
    e.preventDefault()
    if (!host.trim()) return
    run(() => api.toolsDnssec(host.trim()))
  }
  return (
    <ToolCard title="DNSSEC Validator">
      <form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
        <input className="input flex-1 text-xs min-w-0" placeholder="Domain name (e.g. cloudflare.com)"
          value={host} onChange={e => setHost(e.target.value)} />
        <SubmitBtn loading={loading}>Validate</SubmitBtn>
      </form>
      {result && (
        <div className="mt-3 space-y-2">
          <div className={`flex items-center gap-2 text-sm font-semibold ${result.signed ? 'text-green-400' : 'text-[#f87171]'}`}>
            <span>{result.signed ? '✓ Signed with DNSSEC' : '✗ Not signed with DNSSEC'}</span>
          </div>
          {result.chain?.map(c => (
            <div key={c.record} className="flex items-start gap-2 text-xs px-2 py-1.5 rounded bg-[var(--color-surface-offset)]">
              <span className={`mt-0.5 w-2 h-2 rounded-full shrink-0 ${c.present ? 'bg-green-500' : 'bg-red-500/60'}`} />
              <span className="text-[var(--color-text-muted)] w-16 shrink-0">{c.record}</span>
              {c.present
                ? <span className="font-mono text-[10px] text-[var(--color-text-muted)] break-all">{c.values.slice(0, 1).join('')}</span>
                : <span className="text-[10px] text-[var(--color-text-muted)] italic">Not present</span>}
            </div>
          ))}
          {result.error && <p className="text-xs text-[#f87171]">{result.error}</p>}
        </div>
      )}
      <ErrorBanner msg={error} />
    </ToolCard>
  )
}

function RdnsBulkTool() {
  const [cidr, setCidr] = useState('')
  const { loading, result, error, run } = useTool()
  function handleSubmit(e) {
    e.preventDefault()
    if (!cidr.trim()) return
    run(() => api.toolsRdnsBulk(cidr.trim()))
  }
  return (
    <ToolCard title="Reverse DNS Bulk Lookup">
      <p className="text-[10px] text-[var(--color-text-muted)] mb-2">Reverse-resolve every host in a subnet. Max /24 (256 hosts).</p>
      <form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
        <input className="input flex-1 text-xs font-mono min-w-0" placeholder="CIDR e.g. 192.168.1.0/24"
          value={cidr} onChange={e => setCidr(e.target.value)} />
        <SubmitBtn loading={loading}>Resolve</SubmitBtn>
      </form>
      {result && (
        <div className="mt-3 max-h-64 overflow-y-auto space-y-0">
          {result.results?.map((r, i) => (
            <div key={i} className="flex gap-3 py-1 border-b border-[var(--color-border)] last:border-0 text-xs">
              <span className="font-mono text-[var(--color-text-muted)] w-36 shrink-0">{r.ip}</span>
              <span className={`font-mono flex-1 ${r.hostname ? 'text-[var(--color-text)]' : 'text-[var(--color-text-muted)] italic'}`}>
                {r.hostname || 'No PTR record'}
              </span>
            </div>
          ))}
        </div>
      )}
      <ErrorBanner msg={error} />
    </ToolCard>
  )
}

// ---------------------------------------------------------------------------
// Web Tools — Redirect Chain, TLS Versions, HTTP Timing
// ---------------------------------------------------------------------------
function RedirectChainTool() {
  const [url, setUrl] = useState('https://')
  const { loading, result, error, run } = useTool()
  function handleSubmit(e) {
    e.preventDefault()
    if (!url.trim()) return
    run(() => api.toolsRedirectChain(url.trim()))
  }
  const STATUS_COLOR = (s) => s < 300 ? '#22c55e' : s < 400 ? '#f59e0b' : '#f87171'
  return (
    <ToolCard title="Redirect Chain Follower">
      <form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
        <input className="input flex-1 text-xs font-mono min-w-0" placeholder="https://example.com"
          value={url} onChange={e => setUrl(e.target.value)} />
        <SubmitBtn loading={loading}>Follow</SubmitBtn>
      </form>
      {result && (
        <div className="mt-3 space-y-1">
          {result.chain?.map((hop, i) => (
            <div key={i} className="flex items-center gap-2 text-xs">
              <span className="text-[var(--color-text-muted)] w-5 shrink-0 text-center">{i + 1}</span>
              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold shrink-0"
                style={{ background: `${STATUS_COLOR(hop.status)}20`, color: STATUS_COLOR(hop.status) }}>
                {hop.status}
              </span>
              <span className="font-mono text-[10px] text-[var(--color-text)] flex-1 truncate" title={hop.url}>{hop.url}</span>
              <span className="text-[10px] text-[var(--color-text-muted)] shrink-0">{hop.ms}ms</span>
            </div>
          ))}
          <p className="text-[10px] text-[var(--color-text-muted)] mt-2">{result.hops} hop{result.hops !== 1 ? 's' : ''} total</p>
          {result.error && <p className="text-xs text-[#f87171]">{result.error}</p>}
        </div>
      )}
      <ErrorBanner msg={error} />
    </ToolCard>
  )
}

function TlsVersionsTool() {
  const [host, setHost] = useState('')
  const [port, setPort] = useState('443')
  const { loading, result, error, run } = useTool()
  function handleSubmit(e) {
    e.preventDefault()
    if (!host.trim()) return
    run(() => api.toolsTlsVersions(host.trim(), parseInt(port) || 443))
  }
  return (
    <ToolCard title="TLS Version & Cipher Suite Tester">
      <p className="text-[10px] text-[var(--color-text-muted)] mb-2">Uses nmap ssl-enum-ciphers to test which TLS versions and ciphers the server accepts.</p>
      <form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
        <input className="input flex-1 text-xs min-w-0" placeholder="Hostname"
          value={host} onChange={e => setHost(e.target.value)} />
        <input className="input w-20 text-xs font-mono" placeholder="Port"
          value={port} onChange={e => setPort(e.target.value)} />
        <SubmitBtn loading={loading}>Test</SubmitBtn>
      </form>
      {result && (
        <div className="mt-3 space-y-3">
          {result.error && <p className="text-xs text-[#f87171]">{result.error}</p>}
          {Object.entries(result.versions || {}).map(([ver, info]) => (
            <div key={ver}>
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xs font-semibold text-[var(--color-text)]">{ver}</span>
                {info.grade && (
                  <span className={`text-[10px] px-1.5 py-0.5 rounded font-semibold ${
                    info.grade === 'A' ? 'bg-green-500/15 text-green-400' :
                    info.grade === 'B' ? 'bg-yellow-500/15 text-yellow-400' : 'bg-red-500/15 text-red-400'
                  }`}>{info.grade}</span>
                )}
              </div>
              {info.ciphers.slice(0, 5).map((c, i) => (
                <div key={i} className="text-[10px] font-mono text-[var(--color-text-muted)] pl-2">{c}</div>
              ))}
            </div>
          ))}
          {Object.keys(result.versions || {}).length === 0 && !result.error && result.raw && (
            <div>
              <p className="text-[10px] text-[var(--color-text-muted)] mb-1 italic">No TLS versions parsed — raw output:</p>
              <pre className="text-[10px] text-[var(--color-text-muted)] max-h-60 overflow-y-auto whitespace-pre-wrap bg-[var(--color-surface)] rounded p-2 border border-[var(--color-border)]">{result.raw}</pre>
            </div>
          )}
          {Object.keys(result.versions || {}).length > 0 && result.raw && (
            <details className="text-xs mt-1">
              <summary className="cursor-pointer text-[var(--color-text-muted)] hover:text-[var(--color-text)]">Raw nmap output</summary>
              <pre className="mt-2 text-[10px] text-[var(--color-text-muted)] max-h-48 overflow-y-auto whitespace-pre-wrap bg-[var(--color-surface)] rounded p-2 border border-[var(--color-border)]">{result.raw}</pre>
            </details>
          )}
        </div>
      )}
      <ErrorBanner msg={error} />
    </ToolCard>
  )
}

function HttpTimingTool() {
  const [url, setUrl] = useState('https://')
  const { loading, result, error, run } = useTool()
  function handleSubmit(e) {
    e.preventDefault()
    if (!url.trim()) return
    run(() => api.toolsHttpTiming(url.trim()))
  }
  return (
    <ToolCard title="HTTP Response Time">
      <form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
        <input className="input flex-1 text-xs font-mono min-w-0" placeholder="https://example.com"
          value={url} onChange={e => setUrl(e.target.value)} />
        <SubmitBtn loading={loading}>Measure</SubmitBtn>
      </form>
      {result && (
        <div className="mt-3 space-y-1">
          {result.error && <p className="text-xs text-[#f87171]">{result.error}</p>}
          {result.total_ms != null && (
            <>
              <FieldRow label="Status" value={`${result.status}`} mono />
              <FieldRow label="Total time" value={`${result.total_ms} ms`} mono />
              {result.content_length > 0 && <FieldRow label="Content size" value={`${result.content_length} B`} mono />}
              {result.server && <FieldRow label="Server" value={result.server} mono />}
            </>
          )}
        </div>
      )}
      <ErrorBanner msg={error} />
    </ToolCard>
  )
}

// ---------------------------------------------------------------------------
// Infrastructure — BGP/ASN Lookup, Subnet Calculator
// ---------------------------------------------------------------------------
function BgpLookupTool() {
  const [query, setQuery] = useState('')
  const { loading, result, error, run } = useTool()
  function handleSubmit(e) {
    e.preventDefault()
    if (!query.trim()) return
    run(() => api.toolsBgp(query.trim()))
  }
  const d = result?.data
  return (
    <ToolCard title="BGP / ASN Lookup">
      <p className="text-[10px] text-[var(--color-text-muted)] mb-2">Via bgpview.io. Enter an IP address or ASN (e.g. AS13335).</p>
      <form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
        <input className="input flex-1 text-xs font-mono min-w-0" placeholder="IP address or ASN"
          value={query} onChange={e => setQuery(e.target.value)} />
        <SubmitBtn loading={loading}>Lookup</SubmitBtn>
      </form>
      {result && (
        <div className="mt-3 space-y-0">
          {result.error && <p className="text-xs text-[#f87171]">{result.error}</p>}
          {d && (
            <>
              <FieldRow label="ASN"       value={d.asn && `AS${d.asn}`} mono />
              <FieldRow label="Name"      value={d.name || d.description_short} />
              <FieldRow label="Country"   value={d.country_code} />
              <FieldRow label="IP"        value={d.rir_allocation?.prefix || d.ip} mono />
              {d.prefixes?.length > 0 && (
                <div className="py-1 border-b border-[var(--color-border)] text-xs">
                  <span className="w-28 shrink-0 text-[var(--color-text-muted)] inline-block">Prefixes</span>
                  <span className="font-mono text-[var(--color-text)]">{d.prefixes.slice(0, 5).map(p => p.prefix || p).join(', ')}</span>
                </div>
              )}
            </>
          )}
        </div>
      )}
      <ErrorBanner msg={error} />
    </ToolCard>
  )
}

function SubnetCalcTool() {
  const [cidr, setCidr] = useState('')
  const [calc, setCalc] = useState(null)
  const [err,  setErr]  = useState(null)

  function handleChange(v) {
    setCidr(v)
    setCalc(null)
    setErr(null)
    if (!v.includes('/')) return
    try {
      const [ipPart, prefixStr] = v.split('/')
      const prefix = parseInt(prefixStr, 10)
      if (isNaN(prefix) || prefix < 0 || prefix > 32) throw new Error('Prefix must be 0–32')
      const ipParts = ipPart.split('.').map(Number)
      if (ipParts.length !== 4 || ipParts.some(p => isNaN(p) || p < 0 || p > 255)) throw new Error('Invalid IP')
      const ipNum = ipParts.reduce((acc, p) => (acc << 8) | p, 0) >>> 0
      const mask  = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0
      const netNum = (ipNum & mask) >>> 0
      const bcast  = (netNum | (~mask >>> 0)) >>> 0
      const first  = prefix < 31 ? netNum + 1 : netNum
      const last   = prefix < 31 ? bcast  - 1 : bcast
      const hosts  = prefix >= 31 ? (prefix === 31 ? 2 : 1) : bcast - netNum - 1
      const toIp = n => [(n>>>24)&0xFF,(n>>>16)&0xFF,(n>>>8)&0xFF,n&0xFF].join('.')
      setCalc({
        network:   toIp(netNum) + '/' + prefix,
        netmask:   toIp(mask),
        broadcast: toIp(bcast),
        first:     toIp(first),
        last:      toIp(last),
        hosts,
        prefix,
      })
    } catch (e) {
      setErr(e.message)
    }
  }

  return (
    <ToolCard title="Subnet Calculator">
      <p className="text-[10px] text-[var(--color-text-muted)] mb-2">Pure client-side calculation — no network request.</p>
      <input className="input w-full text-xs font-mono" placeholder="CIDR e.g. 192.168.1.0/24"
        value={cidr} onChange={e => handleChange(e.target.value)} />
      {err && <p className="mt-2 text-xs text-[#f87171]">{err}</p>}
      {calc && (
        <div className="mt-3 space-y-0">
          <FieldRow label="Network"    value={calc.network}   mono />
          <FieldRow label="Netmask"    value={calc.netmask}   mono />
          <FieldRow label="Broadcast"  value={calc.broadcast} mono />
          <FieldRow label="First host" value={calc.first}     mono />
          <FieldRow label="Last host"  value={calc.last}      mono />
          <FieldRow label="Hosts"      value={calc.hosts.toLocaleString()} />
          <FieldRow label="Prefix"     value={`/${calc.prefix}`} mono />
        </div>
      )}
    </ToolCard>
  )
}

// ---------------------------------------------------------------------------
// Email Tools — SMTP Banner, BIMI, DNSBL
// ---------------------------------------------------------------------------
function SmtpBannerTool() {
  const [host, setHost] = useState('')
  const [port, setPort] = useState('25')
  const { loading, result, error, run } = useTool()
  function handleSubmit(e) {
    e.preventDefault()
    if (!host.trim()) return
    run(() => api.toolsSmtpBanner(host.trim(), parseInt(port) || 25))
  }
  return (
    <ToolCard title="SMTP Banner Grab">
      <p className="text-[10px] text-[var(--color-text-muted)] mb-2">Connect to a mail server and read its EHLO capabilities.</p>
      <form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
        <input className="input flex-1 text-xs min-w-0" placeholder="Mail server hostname"
          value={host} onChange={e => setHost(e.target.value)} />
        <input className="input w-20 text-xs font-mono" placeholder="Port"
          value={port} onChange={e => setPort(e.target.value)} />
        <SubmitBtn loading={loading}>Connect</SubmitBtn>
      </form>
      {result && (
        <div className="mt-3 space-y-1">
          {result.error && <p className="text-xs text-[#f87171]">{result.error}</p>}
          {result.banner && (
            <div className="text-xs font-mono px-2 py-1.5 rounded bg-[var(--color-surface-offset)] text-[var(--color-text)]">{result.banner}</div>
          )}
          {result.ehlo?.map((l, i) => (
            <div key={i} className="text-[10px] font-mono px-2 py-0.5 text-[var(--color-text-muted)]">{l}</div>
          ))}
        </div>
      )}
      <ErrorBanner msg={error} />
    </ToolCard>
  )
}

function BimiTool() {
  const [domain, setDomain] = useState('')
  const { loading, result, error, run } = useTool()
  function handleSubmit(e) {
    e.preventDefault()
    if (!domain.trim()) return
    run(() => api.toolsBimi(domain.trim()))
  }
  return (
    <ToolCard title="BIMI Checker">
      <p className="text-[10px] text-[var(--color-text-muted)] mb-2">Check the Brand Indicators for Message Identification (BIMI) record for a domain.</p>
      <form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
        <input className="input flex-1 text-xs min-w-0" placeholder="Domain (e.g. gmail.com)"
          value={domain} onChange={e => setDomain(e.target.value)} />
        <SubmitBtn loading={loading}>Check</SubmitBtn>
      </form>
      {result && (
        <div className="mt-3 space-y-1">
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full shrink-0 ${result.present ? 'bg-green-500' : 'bg-red-500/60'}`} />
            <span className="text-xs text-[var(--color-text)]">{result.present ? 'BIMI record found' : 'No BIMI record'}</span>
          </div>
          {result.record && (
            <div className="text-[10px] font-mono text-[var(--color-text-muted)] bg-[var(--color-surface-offset)] px-2 py-1.5 rounded break-all">{result.record}</div>
          )}
          {result.logo_url && <FieldRow label="Logo URL" value={result.logo_url} mono />}
          {result.vmc_url  && <FieldRow label="VMC URL"  value={result.vmc_url} mono />}
          {result.error    && <p className="text-xs text-[#f87171]">{result.error}</p>}
        </div>
      )}
      <ErrorBanner msg={error} />
    </ToolCard>
  )
}

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/

function DnsblTool() {
  const [ip, setIp] = useState('')
  const { loading, result, error, run } = useTool()
  function handleSubmit(e) {
    e.preventDefault()
    const v = ip.trim()
    if (!v) return
    if (!IPV4_RE.test(v)) {
      run(() => Promise.reject(new Error('Please enter an IPv4 address (e.g. 1.2.3.4), not a domain name.')))
      return
    }
    run(() => api.toolsDnsbl(v))
  }
  return (
    <ToolCard title="Email Blacklist (DNSBL) Checker">
      <form onSubmit={handleSubmit} className="flex flex-wrap gap-2">
        <input className="input flex-1 text-xs font-mono min-w-0" placeholder="IP address"
          value={ip} onChange={e => setIp(e.target.value)} />
        <SubmitBtn loading={loading}>Check</SubmitBtn>
      </form>
      {result && (
        <div className="mt-3 space-y-1">
          {result.listed_count > 0 && (
            <p className="text-xs text-[#f87171] font-semibold mb-2">
              Listed on {result.listed_count} of {result.total} blacklists
            </p>
          )}
          {result.results?.map(r => (
            <div key={r.list} className="flex items-center gap-2 text-xs py-1 px-2 rounded bg-[var(--color-surface-offset)]">
              <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                r.listed === true ? 'bg-red-500' : r.listed === false ? 'bg-green-500/60' : 'bg-yellow-500/60'}`} />
              <span className="text-[var(--color-text-muted)] flex-1">{r.list}</span>
              <span className={`text-[10px] font-semibold ${r.listed ? 'text-[#f87171]' : 'text-[var(--color-text-muted)]'}`}>
                {r.listed === true ? 'Listed' : r.listed === false ? 'Clean' : 'Error'}
              </span>
            </div>
          ))}
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
  { id: 'ip',    label: 'IP Tools',       Icon: Wifi,   desc: 'Ping · Traceroute · Port scan · Reverse DNS · ARP Lookup · Wake-on-LAN' },
  { id: 'dns',   label: 'DNS Tools',      Icon: Globe,  desc: 'Record lookup · Propagation · DoH/DoT · DNSSEC · Reverse DNS bulk' },
  { id: 'web',   label: 'Web Tools',      Icon: Shield, desc: 'HTTP headers · SSL/TLS cert · Redirect chain · TLS versions · HTTP timing' },
  { id: 'infra', label: 'Infrastructure', Icon: Server, desc: 'IP geolocation · WHOIS · BGP/ASN lookup · Subnet calculator' },
  { id: 'email', label: 'Email Tools',    Icon: Mail,   desc: 'MX · SPF · DMARC · DKIM · SMTP banner · BIMI · DNSBL' },
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
        `} style={{ background: 'var(--color-surface)', borderColor: 'var(--color-border)' }}>
          <div className="px-4 py-3 border-b border-[var(--color-border)] flex items-center justify-between">
            <div>
              <p className="text-xs font-semibold" style={{ color: 'var(--color-text)' }}>Network Tools</p>
              <p className="text-[10px] mt-0.5 text-[var(--color-text-muted)]">Diagnostics & analysis</p>
            </div>
            {sidebarOpen && (
              <button onClick={() => setSidebarOpen(false)} className="p-1 text-[var(--color-text-muted)]"><X size={14} /></button>
            )}
          </div>
          <nav className="p-2 space-y-0.5">
            {SECTIONS.map(s => (
              <button key={s.id}
                onClick={() => selectSection(s.id)}
                className="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-left transition-colors"
                style={section === s.id
                  ? { background: 'var(--color-brand)', color: 'white' }
                  : { color: 'var(--color-text-muted)' }}>
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
            <ArpLookupTool />
            <WakeOnLanTool />
          </>
        )}
        {section === 'dns' && (
          <>
            <DnsLookupTool />
            <DnsPropagationTool />
            <DohTesterTool />
            <DnssecTool />
            <RdnsBulkTool />
          </>
        )}
        {section === 'web' && (
          <>
            <HttpHeadersTool />
            <SslTool />
            <RedirectChainTool />
            <TlsVersionsTool />
            <HttpTimingTool />
          </>
        )}
        {section === 'infra' && (
          <>
            <GeoTool />
            <WhoisTool />
            <BgpLookupTool />
            <SubnetCalcTool />
          </>
        )}
        {section === 'email' && (
          <>
            <EmailTool />
            <SmtpBannerTool />
            <BimiTool />
            <DnsblTool />
          </>
        )}
      </div>
    </div>
  )
}
