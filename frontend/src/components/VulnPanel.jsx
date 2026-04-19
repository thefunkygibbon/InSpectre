import { useState, useEffect, useRef } from 'react'
import {
  ShieldAlert, ShieldCheck, ShieldQuestion, AlertTriangle,
  Info, ChevronDown, ChevronRight, Trash2,
  Clock, Square, Wrench, AlertOctagon, BookOpen, Tag, Globe,
  ExternalLink,
} from 'lucide-react'
import { api, streamSSE } from '../api'
import { StreamOutput }   from './StreamOutput'

// ---------------------------------------------------------------------------
// Severity config
// ---------------------------------------------------------------------------
const SEV_CONFIG = {
  critical: { label: 'Critical', color: '#ef4444', bg: 'rgba(239,68,68,0.12)',  border: 'rgba(239,68,68,0.3)',  Icon: ShieldAlert },
  high:     { label: 'High',     color: '#f97316', bg: 'rgba(249,115,22,0.12)', border: 'rgba(249,115,22,0.3)', Icon: ShieldAlert },
  medium:   { label: 'Medium',   color: '#f59e0b', bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.3)', Icon: AlertTriangle },
  low:      { label: 'Low',      color: '#3b82f6', bg: 'rgba(59,130,246,0.12)', border: 'rgba(59,130,246,0.3)', Icon: Info },
  info:     { label: 'Info',     color: '#8b5cf6', bg: 'rgba(139,92,246,0.12)', border: 'rgba(139,92,246,0.3)', Icon: Info },
  clean:    { label: 'Clean',    color: '#22c55e', bg: 'rgba(34,197,94,0.12)',  border: 'rgba(34,197,94,0.3)',  Icon: ShieldCheck },
}

function SevBadge({ severity }) {
  const cfg = SEV_CONFIG[severity] || SEV_CONFIG.info
  const { Icon } = cfg
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold"
      style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.border}` }}>
      <Icon size={10} />
      {cfg.label}
    </span>
  )
}

function cvssLabel(score) {
  if (score == null) return null
  if (score >= 9.0) return { tier: 'Critical', color: '#ef4444' }
  if (score >= 7.0) return { tier: 'High',     color: '#f97316' }
  if (score >= 4.0) return { tier: 'Medium',   color: '#f59e0b' }
  return               { tier: 'Low',      color: '#3b82f6' }
}

function fmt(iso) {
  if (!iso) return '--'
  return new Date(iso).toLocaleString()
}

// ---------------------------------------------------------------------------
// FindingCard — Nuclei finding (rich metadata from templates)
// ---------------------------------------------------------------------------
function FindingCard({ finding }) {
  const [open, setOpen] = useState(false)
  const cvssInfo  = cvssLabel(finding.cvss)
  const sevCfg    = SEV_CONFIG[finding.severity] || SEV_CONFIG.info

  // Build NVD links for CVE IDs
  const cves = finding.cves || []

  // Filter reference URLs: prefer NVD/NIST links first
  const refs = (finding.reference || []).filter(Boolean)

  return (
    <div className="rounded-lg border mb-2 overflow-hidden"
      style={{ borderColor: sevCfg.border }}>

      {/* ── Header row (always visible) ── */}
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-3 py-2.5 text-left"
        style={{ background: sevCfg.bg }}>
        <SevBadge severity={finding.severity} />

        {/* CVSS score pill */}
        {cvssInfo && (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold shrink-0"
            style={{ background: 'rgba(0,0,0,0.25)', color: cvssInfo.color, border: `1px solid ${cvssInfo.color}55` }}>
            CVSS {finding.cvss?.toFixed(1)}
            <span className="opacity-70">({cvssInfo.tier})</span>
          </span>
        )}

        <span className="flex-1 text-xs font-medium text-text truncate">{finding.name}</span>
        <span className="text-[10px] text-text-faint font-mono shrink-0 max-w-[120px] truncate">{finding.template_id}</span>
        {open
          ? <ChevronDown  size={12} className="text-text-faint shrink-0" />
          : <ChevronRight size={12} className="text-text-faint shrink-0" />}
      </button>

      {/* ── Expanded detail ── */}
      {open && (
        <div className="px-3 py-3 space-y-3" style={{ background: '#0d1117' }}>

          {/* Matched URL */}
          {(finding.matched_at || finding.host) && (
            <div className="flex items-center gap-1.5 text-[11px]" style={{ color: 'var(--color-text-muted)' }}>
              <Globe size={11} className="shrink-0" />
              <span className="font-mono truncate">{finding.matched_at || finding.host}</span>
            </div>
          )}

          {/* CVE links */}
          {cves.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {cves.map(cve => (
                <a key={cve}
                  href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                  target="_blank" rel="noopener noreferrer"
                  className="text-[10px] font-mono px-1.5 py-0.5 rounded
                             bg-[#161b22] text-brand hover:text-brand-light
                             border border-[#30363d] hover:border-brand transition-colors">
                  {cve}
                </a>
              ))}
            </div>
          )}

          {/* CVSS score row */}
          {cvssInfo && (
            <div className="flex items-center gap-2">
              <AlertOctagon size={12} style={{ color: cvssInfo.color, flexShrink: 0 }} />
              <span className="text-[11px]" style={{ color: 'var(--color-text-muted)' }}>
                CVSS Base Score:&nbsp;
                <span className="font-bold" style={{ color: cvssInfo.color }}>
                  {finding.cvss?.toFixed(1)} — {cvssInfo.tier}
                </span>
              </span>
              {finding.cwe_id && (
                <span className="text-[10px] font-mono px-1 py-0.5 rounded bg-[#161b22] text-text-faint border border-[#30363d]">
                  {finding.cwe_id}
                </span>
              )}
            </div>
          )}

          {/* CVSS vector string */}
          {finding.cvss_metrics && (
            <p className="text-[10px] font-mono leading-relaxed break-all"
               style={{ color: 'var(--color-text-faint)' }}>
              {finding.cvss_metrics}
            </p>
          )}

          {/* Description from Nuclei template */}
          {finding.description && (
            <InfoRow icon={<BookOpen size={11} />} label="Description">
              {finding.description}
            </InfoRow>
          )}

          {/* Remediation guidance if available via references */}
          {refs.length > 0 && (
            <InfoRow icon={<Wrench size={11} />} label="References" color="#22c55e">
              <div className="flex flex-col gap-1 mt-0.5">
                {refs.map((r, i) => (
                  <a key={i} href={r} target="_blank" rel="noopener noreferrer"
                    className="text-[10px] font-mono truncate text-brand hover:text-brand-light flex items-center gap-1">
                    <ExternalLink size={9} className="shrink-0" />
                    {r}
                  </a>
                ))}
              </div>
            </InfoRow>
          )}

          {/* Tags */}
          {finding.tags?.length > 0 && (
            <div className="flex items-center gap-1 flex-wrap">
              <Tag size={10} className="text-text-faint shrink-0" />
              {finding.tags.map(t => (
                <span key={t}
                  className="text-[10px] px-1.5 py-0.5 rounded bg-[#161b22] text-text-faint border border-[#30363d]">
                  {t}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function InfoRow({ icon, label, color = 'var(--color-text-muted)', children }) {
  return (
    <div className="rounded p-2" style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)' }}>
      <p className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider mb-1"
        style={{ color }}>
        {icon} {label}
      </p>
      <div className="text-[11px] leading-relaxed" style={{ color: 'var(--color-text-muted)' }}>
        {children}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Severity summary bar
// ---------------------------------------------------------------------------
function SeveritySummary({ findings }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const f of findings || []) {
    if (f.severity in counts) counts[f.severity]++
  }
  const bars = Object.entries(counts).filter(([, n]) => n > 0)
  if (!bars.length) return null
  return (
    <div className="flex flex-wrap gap-1.5">
      {bars.map(([sev, n]) => {
        const cfg = SEV_CONFIG[sev]
        return (
          <span key={sev}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold"
            style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.border}` }}>
            {n} {cfg.label}
          </span>
        )
      })}
    </div>
  )
}

// ---------------------------------------------------------------------------
// ReportDetail
// ---------------------------------------------------------------------------
function ReportDetail({ mac, report, onDelete }) {
  const [showRaw,  setShowRaw]  = useState(false)
  const [detail,   setDetail]   = useState(null)
  const [deleting, setDeleting] = useState(false)

  useEffect(() => {
    if (showRaw && !detail) {
      api.getVulnReportDetail(mac, report.id).then(setDetail).catch(() => {})
    }
  }, [showRaw, detail, mac, report.id])

  async function handleDelete() {
    if (!window.confirm('Delete this report?')) return
    setDeleting(true)
    try {
      await api.deleteVulnReport(mac, report.id)
      if (onDelete) onDelete(report.id)
    } catch (e) { alert(e.message) }
    finally { setDeleting(false) }
  }

  return (
    <div className="card p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <SevBadge severity={report.severity} />
          <span className="text-xs text-text-muted">{fmt(report.scanned_at)}</span>
          {report.duration_s != null && (
            <span className="text-[10px] text-text-faint">({report.duration_s}s)</span>
          )}
        </div>
        <button onClick={handleDelete} disabled={deleting}
          className="text-text-faint hover:text-red-400 transition-colors p-1" title="Delete report">
          <Trash2 size={13} />
        </button>
      </div>

      {report.vuln_count === 0 ? (
        <p className="text-sm text-green-400 flex items-center gap-1.5">
          <ShieldCheck size={14} /> No vulnerabilities found
        </p>
      ) : (
        <>
          <SeveritySummary findings={report.findings} />
          <p className="text-xs text-text-muted">
            {report.vuln_count} finding{report.vuln_count !== 1 ? 's' : ''} detected
          </p>
          <div>
            {(report.findings || []).map((f, i) => <FindingCard key={i} finding={f} />)}
          </div>
        </>
      )}

      <button onClick={() => setShowRaw(r => !r)}
        className="text-[11px] text-text-faint hover:text-text transition-colors">
        {showRaw ? 'Hide raw scan output' : 'Show raw scan output'}
      </button>
      {showRaw && (
        <pre className="text-[10px] leading-relaxed text-green-300 bg-[#0d1117]
                        border border-[#30363d] rounded p-2
                        max-h-64 overflow-y-auto whitespace-pre-wrap break-words">
          {detail?.raw_output || report.raw_output || 'Loading…'}
        </pre>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// VulnPanel — main export
// ---------------------------------------------------------------------------
export function VulnPanel({ device, onScanComplete }) {
  const mac = device?.mac_address
  const ip  = device?.ip_address

  const [reports,  setReports]  = useState(null)
  const [loading,  setLoading]  = useState(false)
  const [scanning, setScanning] = useState(false)
  const [lines,    setLines]    = useState([])
  const abortRef = useRef(null)

  useEffect(() => {
    if (!mac) return
    setLoading(true)
    api.getVulnReports(mac, 5)
      .then(setReports)
      .catch(() => setReports([]))
      .finally(() => setLoading(false))
  }, [mac])

  function stopScan() {
    if (abortRef.current) {
      abortRef.current.abort()
      abortRef.current = null
    }
    setScanning(false)
  }

  async function startScan() {
    if (scanning) { stopScan(); return }
    setScanning(true)
    setLines(['[INFO] Initiating Nuclei vulnerability scan…'])

    const ctrl = new AbortController()
    abortRef.current = ctrl

    try {
      await streamSSE(
        `/devices/${mac}/vuln-scan`,
        (line) => {
          if (line.startsWith('RESULT:')) {
            api.getVulnReports(mac, 5)
              .then(setReports)
              .catch(() => {})
            if (onScanComplete) onScanComplete()
          }
          setLines(prev => [...prev, line])
        },
        ctrl.signal,
      )
    } catch (e) {
      if (e.name !== 'AbortError') {
        setLines(prev => [...prev, `[ERROR] ${e.message}`])
      }
    } finally {
      setScanning(false)
      abortRef.current = null
    }
  }

  function handleDeleteReport(id) {
    setReports(prev => (prev || []).filter(r => r.id !== id))
  }

  const lastReport = reports?.[0]

  return (
    <div className="space-y-4">

      {/* Header row */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldAlert size={14} className="text-brand" />
          <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider">
            Nuclei Vulnerability Scan
          </h3>
          {lastReport && <SevBadge severity={lastReport.severity} />}
        </div>
        {device.vuln_last_scanned && (
          <span className="text-[10px] text-text-faint flex items-center gap-1">
            <Clock size={10} />
            {fmt(device.vuln_last_scanned)}
          </span>
        )}
      </div>

      {/* IP warning */}
      {!ip && (
        <p className="text-xs text-amber-400">
          This device has no IP address — cannot run a vulnerability scan.
        </p>
      )}

      {/* Scan button */}
      {ip && (
        <button
          onClick={startScan}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg border text-xs font-medium
                      transition-colors duration-150 w-full justify-center
                      ${ scanning
                        ? 'border-red-500/40 bg-red-500/10 text-red-400 hover:bg-red-500/20'
                        : 'border-brand bg-brand/10 text-brand hover:bg-brand/20'
                      }`}>
          {scanning
            ? <><Square size={12} className="fill-current" /> Stop Scan</>
            : <><ShieldAlert size={12} /> Run Nuclei Scan</>}
        </button>
      )}

      {/* Scan progress stream */}
      <StreamOutput
        lines={lines}
        running={scanning}
        onStop={stopScan}
        mode="vuln"
      />

      {/* Historical reports */}
      {loading && (
        <div className="space-y-2">
          {[...Array(2)].map((_, i) => <div key={i} className="skeleton h-12 rounded-lg" />)}
        </div>
      )}

      {!loading && reports?.length === 0 && !scanning && (
        <div className="card p-4 flex items-center gap-2">
          <ShieldQuestion size={16} className="text-text-faint" />
          <p className="text-sm text-text-muted italic">No vulnerability scans run yet.</p>
        </div>
      )}

      {!loading && reports && reports.length > 0 && (
        <div className="space-y-3">
          <p className="text-[11px] text-text-faint uppercase tracking-wider font-semibold">
            Last {reports.length} scan{reports.length !== 1 ? 's' : ''}
          </p>
          {reports.map(r => (
            <ReportDetail key={r.id} mac={mac} report={r} onDelete={handleDeleteReport} />
          ))}
        </div>
      )}
    </div>
  )
}
