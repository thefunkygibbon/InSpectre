import { useState, useEffect, useRef } from 'react'
import {
  ShieldAlert, ShieldCheck, ShieldQuestion, AlertTriangle,
  Info, ChevronDown, ChevronRight, Trash2, RefreshCw,
  Clock, X, Square,
} from 'lucide-react'
import { api, streamSSE } from '../api'

// ---------------------------------------------------------------------------
// Severity helpers
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

function fmt(iso) {
  if (!iso) return '--'
  return new Date(iso).toLocaleString()
}

// ---------------------------------------------------------------------------
// FindingCard
// ---------------------------------------------------------------------------
function FindingCard({ finding }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="rounded-lg border mb-2 overflow-hidden"
      style={{ borderColor: (SEV_CONFIG[finding.severity] || SEV_CONFIG.info).border }}>
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-3 py-2.5 text-left"
        style={{ background: (SEV_CONFIG[finding.severity] || SEV_CONFIG.info).bg }}>
        <SevBadge severity={finding.severity} />
        <span className="flex-1 text-xs font-medium text-text truncate">{finding.title}</span>
        <span className="text-[10px] text-text-faint font-mono shrink-0">{finding.script}</span>
        {open
          ? <ChevronDown  size={12} className="text-text-faint shrink-0" />
          : <ChevronRight size={12} className="text-text-faint shrink-0" />}
      </button>
      {open && (
        <div className="px-3 py-3 space-y-2 bg-[#0d1117]">
          {finding.cves?.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {finding.cves.map(cve => (
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
          {finding.cvss != null && (
            <p className="text-[11px] text-text-muted">
              CVSS score: <span className="font-semibold text-text">{finding.cvss}</span>
            </p>
          )}
          <pre className="text-[10px] leading-relaxed text-green-300 bg-[#0d1117]
                          border border-[#30363d] rounded p-2
                          max-h-48 overflow-y-auto whitespace-pre-wrap break-words">
            {finding.detail}
          </pre>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// ReportDetail
// ---------------------------------------------------------------------------
function ReportDetail({ mac, report, onDelete }) {
  const [showRaw, setShowRaw]   = useState(false)
  const [detail,  setDetail]    = useState(null)
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
        {showRaw ? 'Hide raw output' : 'Show raw nmap output'}
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
// TerminalBox (scan progress)
// ---------------------------------------------------------------------------
function TerminalBox({ lines, running, onStop }) {
  const ref = useRef(null)
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight
  }, [lines])
  if (!lines.length && !running) return null
  return (
    <div ref={ref}
      className="mt-3 rounded-lg bg-[#0d1117] border border-[#30363d] p-3 font-mono
                 text-green-400 max-h-56 overflow-y-auto relative"
      style={{ fontSize: '11px', lineHeight: '1.5' }}>
      {running && (
        <button onClick={onStop} className="absolute top-2 right-2 text-[#30363d] hover:text-red-400" title="Stop">
          <X size={12} />
        </button>
      )}
      {lines.map((l, i) => <div key={i} className="whitespace-pre overflow-x-auto">{l}</div>)}
      {running  && <div className="inline-block animate-pulse">&#9608;</div>}
      {!running && lines.length > 0 && <div className="text-green-600 mt-1">--- done ---</div>}
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

  // Load historical reports on mount
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
    setLines(['[INFO] Initiating vulnerability scan…'])

    const ctrl = new AbortController()
    abortRef.current = ctrl

    try {
      await streamSSE(
        `/devices/${mac}/vuln-scan`,
        (line) => {
          if (line.startsWith('RESULT:')) {
            // Scan done — reload reports
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
            Vulnerability Scan
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
            : <><ShieldAlert size={12} /> Run Vuln Scan</>}
        </button>
      )}

      {/* Live scan output */}
      <TerminalBox lines={lines} running={scanning} onStop={stopScan} />

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
