import { useState, useEffect, useRef } from 'react'
import {
  ShieldAlert, ShieldCheck, ShieldQuestion, AlertTriangle,
  Info, ChevronDown, ChevronRight, Trash2,
  Clock, X, Square, Wrench, AlertOctagon, BookOpen,
} from 'lucide-react'
import { api, streamSSE } from '../api'
import { StreamOutput }   from './StreamOutput'

// ---------------------------------------------------------------------------
// Human-readable knowledge base for common NSE scripts / CVE patterns
// ---------------------------------------------------------------------------
const VULN_KB = {
  // Script-level descriptions (keyed by nmap script name)
  'smb-vuln-ms17-010': {
    description: 'EternalBlue — a critical SMB (file-sharing) protocol vulnerability that allows an unauthenticated attacker to remotely execute arbitrary code by sending specially crafted packets to port 445.',
    impact:      'Full remote code execution with SYSTEM-level privileges. Used in the WannaCry and NotPetya ransomware outbreaks. Any unpatched Windows machine on the same network is at severe risk.',
    fix:         'Apply Microsoft security update MS17-010 immediately. If patching is not immediately possible, disable SMBv1 (Set-SmbServerConfiguration -EnableSMB1Protocol $false) and block port 445 at the firewall.',
  },
  'smb-vuln-cve-2020-0796': {
    description: 'SMBGhost — a critical buffer overflow in the Windows SMBv3 compression feature (CVE-2020-0796) that allows unauthenticated remote code execution on Windows 10 / Server 2019.',
    impact:      'Wormable remote code execution. An attacker can take full control of the device without any user interaction.',
    fix:         'Apply Microsoft patch KB4551762. As a temporary workaround, disable SMBv3 compression via PowerShell or block TCP port 445 inbound.',
  },
  'ssl-heartbleed': {
    description: 'Heartbleed (CVE-2014-0160) — a flaw in the OpenSSL TLS heartbeat extension that lets an attacker read up to 64 KB of server memory per request, without authentication.',
    impact:      'Leaks private keys, session tokens, passwords, and other sensitive data from server memory. Affects any service using a vulnerable OpenSSL version (1.0.1 through 1.0.1f).',
    fix:         'Upgrade OpenSSL to 1.0.1g or later. After patching, revoke and reissue all TLS certificates and force all users to change passwords.',
  },
  'ssl-poodle': {
    description: 'POODLE (CVE-2014-3566) — a protocol downgrade attack against SSLv3 that allows a man-in-the-middle attacker to decrypt HTTPS cookies and session tokens.',
    impact:      'Session hijacking leading to account takeover for any service still accepting SSLv3 connections.',
    fix:         'Disable SSLv3 entirely on the server. Configure the service to require TLS 1.2 or higher.',
  },
  'ssl-ccs-injection': {
    description: 'OpenSSL CCS Injection (CVE-2014-0224) — allows a man-in-the-middle attacker to force the use of weak keys during the TLS handshake, enabling decryption of traffic.',
    impact:      'Decryption and modification of encrypted TLS traffic between client and server.',
    fix:         'Upgrade OpenSSL to 0.9.8za, 1.0.0m, or 1.0.1h or later.',
  },
  'ftp-vsftpd-backdoor': {
    description: 'vsFTPd 2.3.4 Backdoor (CVE-2011-2523) — a malicious backdoor was inserted into the vsFTPd 2.3.4 source code. Sending a smiley face ":)" in the username opens a root shell on port 6200.',
    impact:      'Full unauthenticated remote root access to the device.',
    fix:         'Upgrade vsFTPd to version 2.3.5 or later immediately. Block port 6200 at the firewall as a temporary measure.',
  },
  'ftp-anon': {
    description: 'Anonymous FTP login is enabled — anyone on the network can connect to this FTP server without a username or password.',
    impact:      'Unauthorised read (and potentially write) access to files on the FTP server. May expose sensitive data or allow an attacker to upload malicious files.',
    fix:         'Disable anonymous FTP access in the server configuration. If anonymous access is intentional, ensure the FTP root is restricted to truly public files and the directory is not writable.',
  },
  'http-shellshock': {
    description: 'Shellshock (CVE-2014-6271) — a flaw in the Bash shell that allows remote code execution via maliciously crafted HTTP headers sent to CGI scripts.',
    impact:      'Remote code execution on the web server under the privileges of the web process. The attacker can read files, install backdoors, or pivot to other systems.',
    fix:         'Update Bash to a patched version (4.3 patch 25 or later). Remove or restrict access to CGI scripts if not needed.',
  },
  'http-vuln-cve2017-5638': {
    description: 'Apache Struts 2 Remote Code Execution (CVE-2017-5638) — a flaw in the Jakarta Multipart parser allows an attacker to execute arbitrary commands via a crafted Content-Type HTTP header.',
    impact:      'Full remote code execution on the web server. This vulnerability was used in the 2017 Equifax data breach.',
    fix:         'Upgrade Apache Struts to version 2.3.32 or 2.5.10.1 or later. As a workaround, use a Servlet filter to sanitise the Content-Type header.',
  },
  'vulners': {
    description: 'The Vulners NSE script cross-references detected software versions against the Vulners vulnerability database to identify known CVEs affecting services running on this device.',
    impact:      'Varies by individual CVE. Each identified CVE may allow denial of service, information disclosure, privilege escalation, or remote code execution depending on its severity.',
    fix:         'Review each CVE listed and apply the vendor-recommended patch or upgrade for the affected service. Prioritise critical and high severity items first.',
  },
}

// CVE-level fallback: look up by CVE ID prefix patterns
function getCveHint(cve) {
  if (!cve) return null
  const id = cve.toUpperCase()
  if (id.includes('2014-0160')) return 'Heartbleed — leaks server memory via TLS heartbeat. Upgrade OpenSSL.'
  if (id.includes('2017-0144') || id.includes('2017-0145')) return 'EternalBlue SMB exploit. Apply MS17-010.'
  if (id.includes('2014-3566')) return 'POODLE SSLv3 downgrade. Disable SSLv3.'
  if (id.includes('2020-0796')) return 'SMBGhost — wormable SMBv3 RCE. Apply KB4551762.'
  if (id.includes('2011-2523')) return 'vsFTPd backdoor — remote root shell. Upgrade vsFTPd.'
  if (id.includes('2014-6271') || id.includes('2014-7169')) return 'Shellshock — Bash RCE via HTTP headers. Patch Bash.'
  if (id.includes('2017-5638')) return 'Apache Struts RCE. Upgrade Struts.'
  return null
}

// ---------------------------------------------------------------------------
// CVSS score display helper
// ---------------------------------------------------------------------------
function cvssLabel(score) {
  if (score == null) return null
  if (score >= 9.0) return { tier: 'Critical', color: '#ef4444' }
  if (score >= 7.0) return { tier: 'High',     color: '#f97316' }
  if (score >= 4.0) return { tier: 'Medium',   color: '#f59e0b' }
  return               { tier: 'Low',      color: '#3b82f6' }
}

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
// FindingCard — rich expanded view
// ---------------------------------------------------------------------------
function FindingCard({ finding }) {
  const [open, setOpen] = useState(false)

  const kb      = VULN_KB[finding.script] || null
  const cvssInfo = cvssLabel(finding.cvss)

  // Build a CVE hint if no KB entry but we have CVEs
  const cveHints = (finding.cves || []).map(c => ({ cve: c, hint: getCveHint(c) })).filter(x => x.hint)

  return (
    <div className="rounded-lg border mb-2 overflow-hidden"
      style={{ borderColor: (SEV_CONFIG[finding.severity] || SEV_CONFIG.info).border }}>

      {/* ── Header row (always visible) ── */}
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-3 py-2.5 text-left"
        style={{ background: (SEV_CONFIG[finding.severity] || SEV_CONFIG.info).bg }}>
        <SevBadge severity={finding.severity} />

        {/* CVSS score pill */}
        {cvssInfo && (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold"
            style={{ background: 'rgba(0,0,0,0.25)', color: cvssInfo.color, border: `1px solid ${cvssInfo.color}55` }}>
            CVSS {finding.cvss.toFixed(1)}
            <span className="opacity-70">({cvssInfo.tier})</span>
          </span>
        )}

        <span className="flex-1 text-xs font-medium text-text truncate">{finding.title}</span>
        <span className="text-[10px] text-text-faint font-mono shrink-0">{finding.script}</span>
        {open
          ? <ChevronDown  size={12} className="text-text-faint shrink-0" />
          : <ChevronRight size={12} className="text-text-faint shrink-0" />}
      </button>

      {/* ── Expanded detail ── */}
      {open && (
        <div className="px-3 py-3 space-y-3" style={{ background: '#0d1117' }}>

          {/* CVE links */}
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

          {/* CVSS score — full line with tier label */}
          {cvssInfo && (
            <div className="flex items-center gap-2">
              <AlertOctagon size={12} style={{ color: cvssInfo.color, flexShrink: 0 }} />
              <span className="text-[11px]" style={{ color: 'var(--color-text-muted)' }}>
                CVSS Base Score: 
                <span className="font-bold" style={{ color: cvssInfo.color }}>
                  {finding.cvss.toFixed(1)} — {cvssInfo.tier}
                </span>
              </span>
            </div>
          )}

          {/* ── Knowledge-base block ── */}
          {kb ? (
            <div className="space-y-2">
              <KBRow icon={<BookOpen size={11} />} label="What is it?" text={kb.description} />
              <KBRow icon={<AlertOctagon size={11} />} label="Impact" text={kb.impact} color="#f97316" />
              <KBRow icon={<Wrench size={11} />} label="How to fix" text={kb.fix} color="#22c55e" />
            </div>
          ) : cveHints.length > 0 ? (
            <div className="space-y-1">
              {cveHints.map(({ cve, hint }) => (
                <p key={cve} className="text-[11px] leading-relaxed" style={{ color: 'var(--color-text-muted)' }}>
                  <span className="font-mono text-brand">{cve}</span>: {hint}
                </p>
              ))}
            </div>
          ) : (
            // Fallback: render nmap raw block but cleaned up
            <pre className="text-[10px] leading-relaxed text-green-300 bg-[#0d1117]
                            border border-[#30363d] rounded p-2
                            max-h-40 overflow-y-auto whitespace-pre-wrap break-words">
              {finding.detail}
            </pre>
          )}
        </div>
      )}
    </div>
  )
}

// Small helper for KB rows
function KBRow({ icon, label, text, color = 'var(--color-text-muted)' }) {
  return (
    <div className="rounded p-2" style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)' }}>
      <p className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider mb-1"
        style={{ color }}>
        {icon} {label}
      </p>
      <p className="text-[11px] leading-relaxed" style={{ color: 'var(--color-text-muted)' }}>{text}</p>
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
    setLines(['[INFO] Initiating vulnerability scan…'])

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

      {/* Structured scan progress — uses vuln mode */}
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
