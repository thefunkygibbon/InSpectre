// Generates styled HTML security reports and opens them in a print window.
// Uses the browser's native Print → Save as PDF — no dependencies needed.

// Inline version of Logo.jsx — same geometry, parametric by size
function logoSvg(size = 36) {
  const r     = size / 2
  const cx    = r, cy = r
  const outer = r * 0.875
  const inner = r * 0.5
  const dot   = r * 0.175
  const tick  = r * 0.12
  const sw1   = (size * 0.047).toFixed(2)  // outer ring / ticks
  const sw2   = (size * 0.09).toFixed(2)   // sweep arc
  const sw3   = (size * 0.031).toFixed(2)  // inner ring / crosshair
  const da1   = (size * 0.09).toFixed(2)
  const da2   = (size * 0.06).toFixed(2)
  const f = v => v.toFixed(2)
  return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" fill="none" xmlns="http://www.w3.org/2000/svg">
    <circle cx="${f(cx)}" cy="${f(cy)}" r="${f(outer)}" stroke="#4fa8b0" stroke-width="${sw1}"/>
    <path d="M ${f(cx)} ${f(cy-outer)} A ${f(outer)} ${f(outer)} 0 0 1 ${f(cx+outer)} ${f(cy)}"
      stroke="#0d9488" stroke-width="${sw2}" stroke-linecap="round" opacity="0.9"/>
    <circle cx="${f(cx)}" cy="${f(cy)}" r="${f(inner)}" stroke="#4fa8b0" stroke-width="${sw3}"
      stroke-dasharray="${da1} ${da2}" opacity="0.55"/>
    <line x1="${f(cx)}" y1="${f(cy-outer-1)}" x2="${f(cx)}" y2="${f(cy-outer+tick)}" stroke="#4fa8b0" stroke-width="${sw1}" stroke-linecap="round"/>
    <line x1="${f(cx)}" y1="${f(cy+outer-tick)}" x2="${f(cx)}" y2="${f(cy+outer+1)}" stroke="#4fa8b0" stroke-width="${sw1}" stroke-linecap="round"/>
    <line x1="${f(cx-outer-1)}" y1="${f(cy)}" x2="${f(cx-outer+tick)}" y2="${f(cy)}" stroke="#4fa8b0" stroke-width="${sw1}" stroke-linecap="round"/>
    <line x1="${f(cx+outer-tick)}" y1="${f(cy)}" x2="${f(cx+outer+1)}" y2="${f(cy)}" stroke="#4fa8b0" stroke-width="${sw1}" stroke-linecap="round"/>
    <line x1="${f(cx)}" y1="${f(cy-inner*0.55)}" x2="${f(cx)}" y2="${f(cy+inner*0.55)}" stroke="#4fa8b0" stroke-width="${sw3}" opacity="0.4"/>
    <line x1="${f(cx-inner*0.55)}" y1="${f(cy)}" x2="${f(cx+inner*0.55)}" y2="${f(cy)}" stroke="#4fa8b0" stroke-width="${sw3}" opacity="0.4"/>
    <circle cx="${f(cx)}" cy="${f(cy)}" r="${f(dot)}" fill="#0d9488"/>
  </svg>`
}

const BRAND = '#0d9488'  // teal — matches Logo.jsx centre dot / sweep arc

const SEV_COLORS = {
  critical: { bg: '#fee2e2', text: '#991b1b', border: '#fca5a5', label: 'Critical' },
  high:     { bg: '#ffedd5', text: '#9a3412', border: '#fdba74', label: 'High'     },
  medium:   { bg: '#fef3c7', text: '#92400e', border: '#fcd34d', label: 'Medium'   },
  low:      { bg: '#dbeafe', text: '#1e40af', border: '#93c5fd', label: 'Low'      },
  info:     { bg: '#ede9fe', text: '#5b21b6', border: '#c4b5fd', label: 'Info'     },
  clean:    { bg: '#dcfce7', text: '#166534', border: '#86efac', label: 'Clean'    },
  unknown:  { bg: '#f1f5f9', text: '#475569', border: '#cbd5e1', label: 'Unknown'  },
}
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function esc(s) {
  if (s == null) return ''
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

function fmt(iso) {
  if (!iso) return 'Unknown'
  try {
    return new Date(iso).toLocaleString('en-GB', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    })
  } catch { return String(iso) }
}

function sevBadge(sev) {
  const c = SEV_COLORS[sev] || SEV_COLORS.unknown
  return `<span style="display:inline-flex;align-items:center;padding:2px 8px;border-radius:999px;
    font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;
    background:${c.bg};color:${c.text};border:1px solid ${c.border}">${c.label}</span>`
}

function countsBySev(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const f of findings || []) if (f.severity in counts) counts[f.severity]++
  return counts
}

function sevSummaryRow(findings) {
  const counts = countsBySev(findings)
  const active = SEV_ORDER.filter(s => counts[s] > 0)
  if (!active.length) return ''
  const cols = active.length
  const boxes = active.map(s => {
    const c = SEV_COLORS[s]
    return `<div style="background:${c.bg};border:1px solid ${c.border};border-radius:8px;
      padding:10px 14px;text-align:center">
      <div style="font-size:26px;font-weight:900;line-height:1;color:${c.text}">${counts[s]}</div>
      <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.8px;
        color:${c.text};margin-top:4px">${c.label}</div>
    </div>`
  }).join('')
  return `<div style="display:grid;grid-template-columns:repeat(${cols},1fr);gap:10px;margin-bottom:20px">
    ${boxes}
  </div>`
}

// ---------------------------------------------------------------------------
// Finding card — used in device reports
// ---------------------------------------------------------------------------
function renderFindingCard(f) {
  const c = SEV_COLORS[f.severity] || SEV_COLORS.unknown
  const cves = f.cves || []
  const refs = (f.reference || []).filter(Boolean)
  const tags = (f.tags || [])

  const cvssColor = f.cvss == null ? null
    : f.cvss >= 9.0 ? SEV_COLORS.critical
    : f.cvss >= 7.0 ? SEV_COLORS.high
    : f.cvss >= 4.0 ? SEV_COLORS.medium
    : SEV_COLORS.low

  const rows = []
  if (f.matched_at || f.host)
    rows.push(`<div style="display:flex;gap:8px;margin-bottom:5px;align-items:flex-start">
      <span style="font-weight:700;color:#64748b;min-width:80px;font-size:10px;text-transform:uppercase;letter-spacing:0.4px;flex-shrink:0;margin-top:1px">Target</span>
      <span style="font-family:monospace;font-size:11px;word-break:break-all;color:#1e293b">${esc(f.matched_at || f.host)}</span>
    </div>`)
  if (cves.length)
    rows.push(`<div style="display:flex;gap:8px;margin-bottom:5px;align-items:flex-start">
      <span style="font-weight:700;color:#64748b;min-width:80px;font-size:10px;text-transform:uppercase;letter-spacing:0.4px;flex-shrink:0;margin-top:1px">CVE</span>
      <span>${cves.map(c => `<span style="display:inline-flex;background:#f1f5f9;border:1px solid #cbd5e1;border-radius:4px;padding:1px 6px;font-size:10px;margin:0 3px 2px 0;color:#3730a3;font-family:monospace;font-weight:600">${esc(c)}</span>`).join('')}</span>
    </div>`)
  if (cvssColor && f.cvss != null)
    rows.push(`<div style="display:flex;gap:8px;margin-bottom:5px;align-items:flex-start">
      <span style="font-weight:700;color:#64748b;min-width:80px;font-size:10px;text-transform:uppercase;letter-spacing:0.4px;flex-shrink:0;margin-top:1px">CVSS</span>
      <span style="display:inline-flex;align-items:center;gap:3px;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;background:${cvssColor.bg};color:${cvssColor.text};border:1px solid ${cvssColor.border}">${f.cvss.toFixed(1)}</span>
    </div>`)
  if (f.description)
    rows.push(`<div style="display:flex;gap:8px;margin-bottom:5px;align-items:flex-start">
      <span style="font-weight:700;color:#64748b;min-width:80px;font-size:10px;text-transform:uppercase;letter-spacing:0.4px;flex-shrink:0;margin-top:1px">Description</span>
      <span style="color:#1e293b;font-size:11px">${esc(f.description)}</span>
    </div>`)
  if (tags.length)
    rows.push(`<div style="display:flex;gap:8px;margin-bottom:5px;align-items:flex-start">
      <span style="font-weight:700;color:#64748b;min-width:80px;font-size:10px;text-transform:uppercase;letter-spacing:0.4px;flex-shrink:0;margin-top:1px">Tags</span>
      <span>${tags.map(t => `<span style="display:inline-flex;background:#f1f5f9;border:1px solid #cbd5e1;border-radius:4px;padding:1px 5px;font-size:10px;margin:0 3px 2px 0;color:#475569">${esc(t)}</span>`).join('')}</span>
    </div>`)
  if (refs.length)
    rows.push(`<div style="display:flex;gap:8px;margin-bottom:5px;align-items:flex-start">
      <span style="font-weight:700;color:#64748b;min-width:80px;font-size:10px;text-transform:uppercase;letter-spacing:0.4px;flex-shrink:0;margin-top:1px">References</span>
      <span>${refs.map(r => `<a href="${esc(r)}" style="display:block;font-size:10px;color:#0d9488;word-break:break-all">${esc(r)}</a>`).join('')}</span>
    </div>`)

  const body = rows.join('')

  return `<div style="margin-bottom:10px;border-radius:8px;border:1px solid ${c.border};overflow:hidden;page-break-inside:avoid">
    <div style="display:flex;align-items:center;gap:8px;padding:9px 12px;background:${c.bg}">
      ${sevBadge(f.severity)}
      <span style="font-size:12px;font-weight:700;flex:1;color:#0f172a">${esc(f.name || f.template_id || 'Unknown Finding')}</span>
      ${f.template_id ? `<span style="font-size:10px;font-family:monospace;color:#64748b;flex-shrink:0">${esc(f.template_id)}</span>` : ''}
    </div>
    ${body ? `<div style="padding:9px 12px;font-size:11px;border-top:1px solid rgba(0,0,0,0.07);background:rgba(0,0,0,0.015)">${body}</div>` : ''}
  </div>`
}

function renderFindings(findings) {
  if (!findings || findings.length === 0)
    return `<div style="padding:12px 16px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;color:#166534;font-size:12px;font-weight:600">✓ No vulnerabilities found</div>`

  const sorted = [...findings].sort((a, b) => {
    const o = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
    return (o[a.severity] ?? 9) - (o[b.severity] ?? 9)
  })
  return sorted.map(renderFindingCard).join('')
}

// ---------------------------------------------------------------------------
// Container findings — compact table (can have hundreds of rows)
// ---------------------------------------------------------------------------
function renderContainerTable(vulns) {
  const sorted = [...vulns].sort((a, b) => {
    const o = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 }
    return (o[a.severity] ?? 9) - (o[b.severity] ?? 9)
  })
  const shown = sorted.slice(0, 100)
  const rows = shown.map(v => `<tr>
    <td style="width:80px">${sevBadge(v.severity)}</td>
    <td style="font-family:monospace;font-size:10px;color:#3730a3;white-space:nowrap">${esc(v.id)}</td>
    <td style="font-family:monospace;font-size:10px">${esc(v.pkg)}</td>
    <td style="font-family:monospace;font-size:10px">${esc(v.installed)}</td>
    <td style="font-family:monospace;font-size:10px;color:#166534">${esc(v.fixed) || '—'}</td>
    <td style="font-size:11px">${esc(v.title || '')}</td>
  </tr>`).join('')
  return `<table style="width:100%;border-collapse:collapse;font-size:11px">
    <thead><tr>
      <th style="background:#f8fafc;border:1px solid #e2e8f0;padding:5px 8px;text-align:left;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.4px">Severity</th>
      <th style="background:#f8fafc;border:1px solid #e2e8f0;padding:5px 8px;text-align:left;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.4px">CVE ID</th>
      <th style="background:#f8fafc;border:1px solid #e2e8f0;padding:5px 8px;text-align:left;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.4px">Package</th>
      <th style="background:#f8fafc;border:1px solid #e2e8f0;padding:5px 8px;text-align:left;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.4px">Installed</th>
      <th style="background:#f8fafc;border:1px solid #e2e8f0;padding:5px 8px;text-align:left;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.4px">Fixed In</th>
      <th style="background:#f8fafc;border:1px solid #e2e8f0;padding:5px 8px;text-align:left;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.4px">Title</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>
  ${sorted.length > 100 ? `<p style="font-size:10px;color:#64748b;margin-top:4px">… and ${sorted.length - 100} more findings not shown</p>` : ''}`
}

// ---------------------------------------------------------------------------
// Shared layout pieces
// ---------------------------------------------------------------------------
function reportHeader(title, subtitle) {
  return `<div style="display:flex;justify-content:space-between;align-items:flex-start;
    padding-bottom:16px;margin-bottom:24px;border-bottom:2px solid #e2e8f0">
    <div style="display:flex;align-items:center;gap:10px">
      ${logoSvg(40)}
      <div>
        <div style="font-size:22px;font-weight:900;letter-spacing:-0.5px;line-height:1">
          <span style="color:#0d9488">In</span><span style="color:#0f172a">Spectre</span>
        </div>
        <div style="font-size:11px;color:#64748b;margin-top:2px">Network Security Monitor</div>
      </div>
    </div>
    <div style="text-align:right">
      <div style="font-size:13px;font-weight:700;color:#0f172a">${esc(title)}</div>
      <div style="font-size:11px;color:#64748b;margin-top:2px">${esc(subtitle)}</div>
      <div style="font-size:11px;color:#94a3b8;margin-top:2px">Generated ${esc(fmt(new Date().toISOString()))}</div>
    </div>
  </div>`
}

function sectionHeading(text) {
  return `<div style="font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:1.2px;
    color:#64748b;border-bottom:1px solid #e2e8f0;padding-bottom:6px;margin:20px 0 12px">${esc(text)}</div>`
}

function pageFooter(text) {
  return `<div style="text-align:center;font-size:10px;color:#94a3b8;margin-top:32px;
    padding-top:12px;border-top:1px solid #e2e8f0">${esc(text)}</div>`
}

function buildDoc(title, bodyHtml) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${esc(title)}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
      font-size: 12px; color: #0f172a; background: #fff; line-height: 1.6;
      -webkit-print-color-adjust: exact; print-color-adjust: exact;
    }
    a { color: #0d9488; }
    @media print {
      @page { margin: 15mm 18mm; size: A4; }
      .no-print { display: none !important; }
      .page-break { page-break-before: always; }
    }
    .print-bar {
      position: fixed; top: 0; left: 0; right: 0; height: 44px;
      background: #0d9488; color: #fff; display: flex; align-items: center;
      justify-content: space-between; padding: 0 20px; z-index: 999;
      font-size: 13px; font-weight: 600; box-shadow: 0 2px 8px rgba(0,0,0,0.3);
    }
    .print-bar button {
      background: #fff; color: #0d9488; border: none; padding: 6px 16px;
      border-radius: 6px; cursor: pointer; font-weight: 700; font-size: 12px;
    }
    .print-bar button:hover { background: #ccfbf1; }
    .print-spacer { height: 44px; }
    @media print { .print-bar, .print-spacer { display: none; } }
    .page { max-width: 800px; margin: 0 auto; padding: 20px 24px 40px; }
  </style>
</head>
<body>
  <div class="print-bar no-print">
    <span>${esc(title)}</span>
    <button onclick="window.print()">⬇ Save as PDF</button>
  </div>
  <div class="print-spacer no-print"></div>
  <div class="page">${bodyHtml}</div>
</body>
</html>`
}

function openWindow(html) {
  const win = window.open('', '_blank', 'width=960,height=860')
  if (!win) {
    alert('Popup blocked — please allow popups for this page to export PDFs.')
    return
  }
  win.document.write(html)
  win.document.close()
}

// ---------------------------------------------------------------------------
// Public: Device vulnerability report (from VulnPanel)
// ---------------------------------------------------------------------------
export function exportDeviceVulnPDF(device, reports) {
  const name   = device.custom_name || device.hostname || device.ip_address || device.mac_address
  const latest = reports?.[0]
  const findings = latest?.findings || []

  const kvRow = (label, val, mono = false) => val
    ? `<div style="display:flex;gap:6px;font-size:11px;align-items:baseline">
        <span style="color:#64748b;font-weight:600;min-width:68px;flex-shrink:0">${esc(label)}</span>
        <span style="color:#0f172a;font-weight:500${mono ? ';font-family:monospace' : ''}">${esc(val)}</span>
      </div>`
    : ''

  const deviceBox = `<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;
    padding:14px 18px;margin-bottom:20px">
    <div style="font-size:16px;font-weight:800;color:#0f172a;margin-bottom:8px">${esc(name)}</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:5px 20px">
      ${kvRow('IP Address', device.ip_address, true)}
      ${kvRow('MAC Address', device.mac_address, true)}
      ${kvRow('Vendor', device.vendor_override || device.vendor || device.vendor_inferred)}
      ${latest ? kvRow('Last Scanned', fmt(latest.scanned_at)) : ''}
      ${latest?.duration_s != null ? kvRow('Scan Duration',
          latest.duration_s < 60
            ? `${latest.duration_s.toFixed(1)}s`
            : `${(latest.duration_s / 60).toFixed(1)} min`) : ''}
      ${latest ? kvRow('Severity', SEV_COLORS[latest.severity]?.label || latest.severity) : ''}
    </div>
  </div>`

  const findingsSection = latest
    ? `${sectionHeading(`Vulnerability Findings — ${findings.length > 0 ? findings.length + ' finding' + (findings.length !== 1 ? 's' : '') : 'Clean'}`)}
       ${sevSummaryRow(findings)}
       ${renderFindings(findings)}`
    : `<div style="padding:12px 16px;background:#fef3c7;border:1px solid #fcd34d;
        border-radius:8px;color:#92400e;font-size:12px">
        No vulnerability scan has been run for this device yet.
      </div>`

  let historySection = ''
  if (reports && reports.length > 1) {
    const rows = reports.map((r, i) => `<tr>
      <td style="border:1px solid #e2e8f0;padding:6px 10px;${i % 2 ? 'background:#fafafa' : ''}">
        ${i === 0 ? '<strong>' : ''}${esc(fmt(r.scanned_at))}${i === 0 ? ' <span style="font-size:10px;color:#0d9488">(latest)</span></strong>' : ''}
      </td>
      <td style="border:1px solid #e2e8f0;padding:6px 10px;${i % 2 ? 'background:#fafafa' : ''}">${sevBadge(r.severity)}</td>
      <td style="border:1px solid #e2e8f0;padding:6px 10px;text-align:right;font-family:monospace;${i % 2 ? 'background:#fafafa' : ''}">${r.vuln_count}</td>
      <td style="border:1px solid #e2e8f0;padding:6px 10px;text-align:right;font-family:monospace;color:#64748b;${i % 2 ? 'background:#fafafa' : ''}">
        ${r.duration_s != null ? (r.duration_s < 60 ? r.duration_s.toFixed(1) + 's' : (r.duration_s / 60).toFixed(1) + 'm') : '—'}
      </td>
    </tr>`).join('')

    historySection = `${sectionHeading(`Scan History — ${reports.length} scans`)}
    <table style="width:100%;border-collapse:collapse;font-size:11px">
      <thead><tr>
        ${['Date', 'Severity', 'Findings', 'Duration'].map(h =>
          `<th style="background:#f8fafc;border:1px solid #e2e8f0;padding:6px 10px;text-align:left;
            font-weight:700;font-size:10px;text-transform:uppercase;letter-spacing:0.4px">${h}</th>`
        ).join('')}
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`
  }

  const html = buildDoc(
    `InSpectre — ${name} Security Report`,
    reportHeader('Device Security Report', name) +
    deviceBox +
    findingsSection +
    historySection +
    pageFooter(`InSpectre · ${name} · ${fmt(new Date().toISOString())}`)
  )
  openWindow(html)
}

// ---------------------------------------------------------------------------
// Public: Network-wide security report (from SecurityDashboard)
// deviceFindings = { [mac]: findings[] } — pre-fetched by the caller
// ---------------------------------------------------------------------------
export function exportDashboardVulnPDF(summaryData, containerVulns, deviceFindings) {
  const {
    severity_counts = {},
    total_scanned   = 0,
    total_devices   = 0,
    top_vulnerable  = [],
  } = summaryData

  const atRisk       = (severity_counts.critical || 0) + (severity_counts.high || 0) + (severity_counts.medium || 0)
  const coveragePct  = total_devices > 0 ? Math.round((total_scanned / total_devices) * 100) : 0

  // ── Summary stat boxes ──────────────────────────────────────────────────
  const statBoxes = `<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:24px">
    <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:14px;text-align:center">
      <div style="font-size:28px;font-weight:900;color:${atRisk > 0 ? '#991b1b' : '#166534'}">${atRisk}</div>
      <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.8px;color:#991b1b;margin-top:4px">At Risk</div>
      <div style="font-size:10px;color:#64748b;margin-top:2px">Critical + High + Medium</div>
    </div>
    <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:14px;text-align:center">
      <div style="font-size:28px;font-weight:900;color:#166534">${severity_counts.clean || 0}</div>
      <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.8px;color:#166534;margin-top:4px">Clean</div>
      <div style="font-size:10px;color:#64748b;margin-top:2px">No findings</div>
    </div>
    <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px;text-align:center">
      <div style="font-size:28px;font-weight:900;color:#0f172a">${coveragePct}%</div>
      <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.8px;color:#64748b;margin-top:4px">Coverage</div>
      <div style="font-size:10px;color:#64748b;margin-top:2px">${total_scanned} / ${total_devices} devices scanned</div>
    </div>
  </div>`

  // ── Severity distribution ────────────────────────────────────────────────
  const activeSevs = SEV_ORDER.filter(s => severity_counts[s] > 0)
  const sevDist = activeSevs.length > 0
    ? sectionHeading('Severity Distribution') + sevSummaryRow(
        activeSevs.flatMap(s => Array(severity_counts[s]).fill({ severity: s }))
      )
    : ''

  // ── Per-device sections ──────────────────────────────────────────────────
  let deviceSections = ''
  if (top_vulnerable.length > 0) {
    deviceSections = sectionHeading(`Vulnerable Devices (${top_vulnerable.length})`)
    deviceSections += top_vulnerable.map((d, idx) => {
      const findings = deviceFindings[d.mac_address] || []
      const c = SEV_COLORS[d.severity] || SEV_COLORS.unknown
      return `<div style="margin-bottom:24px${idx > 0 ? ';page-break-inside:avoid' : ''}">
        <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;
          padding:10px 14px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center">
          <div>
            <div style="font-size:13px;font-weight:800;color:#0f172a">${esc(d.display_name)}</div>
            <div style="font-size:10px;color:#64748b;margin-top:2px">
              ${d.ip_address ? `IP: ${esc(d.ip_address)} · ` : ''}MAC: ${esc(d.mac_address)} · Scanned: ${esc(fmt(d.scanned_at))}
            </div>
          </div>
          <div style="text-align:right">
            ${sevBadge(d.severity)}
            <div style="font-size:10px;color:#64748b;margin-top:3px">${d.vuln_count} finding${d.vuln_count !== 1 ? 's' : ''}</div>
          </div>
        </div>
        ${sevSummaryRow(findings)}
        ${renderFindings(findings)}
      </div>`
    }).join('')
  }

  // ── Container sections ───────────────────────────────────────────────────
  let containerSection = ''
  const scanned = (containerVulns || []).filter(c => c.scanned_at)
  if (scanned.length > 0) {
    const withFindings = scanned.filter(c => c.severity && c.severity !== 'clean')
    containerSection = sectionHeading(
      `Container Images — ${scanned.length} scanned, ${withFindings.length} with findings`
    )
    containerSection += scanned.map(c => {
      const vulns = (c.vulns || []).filter(v => v.severity !== 'unknown')
      const cv = SEV_COLORS[c.severity] || SEV_COLORS.clean
      return `<div style="background:#f0fdfa;border:1px solid #99f6e4;border-radius:8px;
        padding:12px 16px;margin-bottom:14px;page-break-inside:avoid">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:${vulns.length ? '12px' : '0'}">
          <div>
            <div style="font-size:13px;font-weight:800;color:#0f172a">${esc(c.name)}</div>
            <div style="font-size:10px;font-family:monospace;color:#0d9488;margin-top:2px">${esc(c.image)}</div>
          </div>
          <div style="text-align:right">
            ${c.severity ? sevBadge(c.severity) : ''}
            <div style="font-size:10px;color:#64748b;margin-top:3px">
              ${vulns.length} CVE${vulns.length !== 1 ? 's' : ''} · Scanned ${esc(fmt(c.scanned_at))}
            </div>
          </div>
        </div>
        ${vulns.length > 0
          ? renderContainerTable(vulns)
          : `<div style="font-size:11px;color:#166534;font-weight:600">✓ No vulnerabilities found</div>`}
      </div>`
    }).join('')
  }

  const subtitle = `${total_scanned} device${total_scanned !== 1 ? 's' : ''} scanned · ${top_vulnerable.length} with findings`

  const html = buildDoc(
    'InSpectre — Network Security Report',
    reportHeader('Network Security Report', subtitle) +
    statBoxes +
    sevDist +
    deviceSections +
    containerSection +
    pageFooter(`InSpectre Network Security Report · ${fmt(new Date().toISOString())}`)
  )
  openWindow(html)
}

// ---------------------------------------------------------------------------
// Public: Container image vulnerability report (from ContainerDrawer VulnTab)
// ---------------------------------------------------------------------------
export function exportContainerVulnPDF(container, vulns, scannedAt) {
  const name = container.name || container.id
  const hasVulns = Array.isArray(vulns) && vulns.length > 0

  const SEV_ORDER_TRIVY = ['critical', 'high', 'medium', 'low', 'unknown']
  const counts = Object.fromEntries(SEV_ORDER_TRIVY.map(s => [s, 0]))
  if (hasVulns) for (const v of vulns) { const s = counts[v.severity] !== undefined ? v.severity : 'unknown'; counts[s]++ }
  const activeSevs = SEV_ORDER_TRIVY.filter(s => counts[s] > 0)

  const infoBox = `<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;
    padding:14px 18px;margin-bottom:20px">
    <div style="font-size:16px;font-weight:800;color:#0f172a;margin-bottom:8px">${esc(name)}</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:5px 20px;font-size:11px">
      <div style="display:flex;gap:6px">
        <span style="color:#64748b;font-weight:600;min-width:68px">Image</span>
        <span style="font-family:monospace;color:#0f172a">${esc(container.image || '—')}</span>
      </div>
      ${scannedAt ? `<div style="display:flex;gap:6px">
        <span style="color:#64748b;font-weight:600;min-width:68px">Scanned</span>
        <span style="color:#0f172a">${esc(fmt(scannedAt))}</span>
      </div>` : ''}
    </div>
  </div>`

  const summaryBoxes = activeSevs.length > 0
    ? `<div style="display:grid;grid-template-columns:repeat(${activeSevs.length},1fr);gap:10px;margin-bottom:20px">
        ${activeSevs.map(s => {
          const c = SEV_COLORS[s] || SEV_COLORS.unknown
          return `<div style="background:${c.bg};border:1px solid ${c.border};border-radius:8px;
            padding:10px 14px;text-align:center">
            <div style="font-size:26px;font-weight:900;line-height:1;color:${c.text}">${counts[s]}</div>
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.8px;
              color:${c.text};margin-top:4px">${c.label}</div>
          </div>`
        }).join('')}
      </div>`
    : ''

  const resultsSection = hasVulns
    ? sectionHeading(`CVE Findings — ${vulns.length} vulnerabilit${vulns.length !== 1 ? 'ies' : 'y'}`) +
      summaryBoxes +
      renderContainerTable(vulns)
    : `<div style="padding:12px 16px;background:#f0fdf4;border:1px solid #bbf7d0;
        border-radius:8px;color:#166534;font-size:12px;font-weight:600">
        ✓ No vulnerabilities found in this image
      </div>`

  const html = buildDoc(
    `InSpectre — ${name} Container Report`,
    reportHeader('Container Security Report', name) +
    infoBox +
    resultsSection +
    pageFooter(`InSpectre · ${name} · ${fmt(new Date().toISOString())}`)
  )
  openWindow(html)
}
