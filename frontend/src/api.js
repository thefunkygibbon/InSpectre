const BASE = import.meta.env.VITE_API_URL || '/api'

async function request(method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) throw new Error(`${method} ${path} \u2192 ${res.status}`)
  return res.json()
}

async function streamSSE(path, onLine, signal) {
  const res = await fetch(`${BASE}${path}`, { signal })
  if (!res.ok) throw new Error(`GET ${path} \u2192 ${res.status}`)
  const reader  = res.body.getReader()
  const decoder = new TextDecoder()
  let buf = ''
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buf += decoder.decode(value, { stream: true })
    const parts = buf.split('\n')
    buf = parts.pop()
    for (const part of parts) {
      const line = part.trim()
      if (line.startsWith('data:')) {
        const text = line.slice(5).trim()
        if (text) onLine(text)
      }
    }
  }
}

export const api = {
  // Devices
  getDevices:      (params = {}) => {
    const p = new URLSearchParams()
    Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') p.set(k, v) })
    const qs = p.toString()
    return request('GET', `/devices${qs ? '?' + qs : ''}`)
  },
  getDevice:       (mac)        => request('GET',   `/devices/${mac}`),
  updateDevice:    (mac, body)  => request('PATCH', `/devices/${mac}`, body),
  updateIdentity:  (mac, body)  => request('PATCH', `/devices/${mac}/identity`, body),
  updateMetadata:  (mac, body)  => request('PATCH', `/devices/${mac}/metadata`, body),
  resolveName:     (mac)        => request('POST',  `/devices/${mac}/resolve-name`),
  rescanDevice:    (mac)        => request('POST',  `/devices/${mac}/rescan`),
  getScanResults:  (mac)        => request('GET',   `/devices/${mac}/scan`),
  getIpHistory:    (mac)        => request('GET',   `/devices/${mac}/ip-history`),
  getDeviceEvents: (mac, limit, type) => {
    const p = new URLSearchParams()
    if (limit) p.set('limit', limit)
    if (type)  p.set('type', type)
    return request('GET', `/devices/${mac}/events${p.toString() ? '?' + p : ''}`)
  },
  getDeviceServices: (mac)      => request('GET',  `/devices/${mac}/services`),
  refreshMdns:       (mac)      => request('POST', `/devices/${mac}/mdns-refresh`),
  getDeviceZones:    ()         => request('GET',  '/devices/meta/zones'),
  getStats:          ()         => request('GET',  '/stats'),

  // Global events feed
  getAllEvents:    (limit, type) => {
    const p = new URLSearchParams()
    if (limit) p.set('limit', limit)
    if (type)  p.set('event_type', type)
    return request('GET', `/events${p.toString() ? '?' + p : ''}`)
  },

  // Vendor list for autocomplete
  getVendors:      ()           => request('GET',   '/vendors'),

  // Fingerprint DB
  getFingerprints:     (params) => request('GET',    '/fingerprints' + (params ? `?${new URLSearchParams(params)}` : '')),
  getFingerprintStats: ()       => request('GET',    '/fingerprints/stats'),
  deleteFingerprint:   (id)     => request('DELETE', `/fingerprints/${id}`),

  // Settings
  getSettings:     ()           => request('GET',  '/settings'),
  updateSetting:   (key, value) => request('PUT',  `/settings/${key}`, { value: String(value) }),
  resetSettings:   ()           => request('POST', '/settings/reset'),
  applySettings:   ()           => request('POST', '/settings/apply'),

  // Export
  exportDevicesCsv:       ()     => fetch(`${BASE}/export/devices`),
  exportFingerprintsJson: ()     => fetch(`${BASE}/export/fingerprints`),

  // Import
  importFingerprintsJson: (file) => {
    const form = new FormData()
    form.append('file', file)
    return fetch(`${BASE}/import/fingerprints`, { method: 'POST', body: form })
      .then(r => { if (!r.ok) throw new Error(`Import failed: ${r.status}`); return r.json() })
  },

  // Notifications
  sendPushbullet: (title, body) => request('POST', '/notify/pushbullet', { title, body }),
  testPushbullet: (apiKey)      => request('POST', '/notify/test', { api_key: apiKey || '' }),

  // Streaming
  streamPing:       (mac, signal) => streamSSE(`/devices/${mac}/ping`,       (l) => l, signal),
  streamTraceroute: (mac, signal) => streamSSE(`/devices/${mac}/traceroute`, (l) => l, signal),

  // Phase 4 — ARP block
  blockDevice:   (mac) => request('POST', `/devices/${mac}/block`),
  unblockDevice: (mac) => request('POST', `/devices/${mac}/unblock`),

  // Phase 3 — Vuln scanning
  getVulnReports:       (mac, limit) => request('GET',    `/devices/${mac}/vuln-reports${limit ? `?limit=${limit}` : ''}`),
  getVulnReportDetail:  (mac, id)    => request('GET',    `/devices/${mac}/vuln-reports/${id}`),
  deleteVulnReport:     (mac, id)    => request('DELETE', `/devices/${mac}/vuln-reports/${id}`),
  getAllVulnReports:     (severity)   => request('GET',    `/vuln-reports${severity ? `?severity=${severity}` : ''}`),
  getVulnSummary:       ()           => request('GET',    '/vulns/summary'),
  scanAllVulns:         ()           => request('POST',   '/vulns/scan-all'),
  getVulnTrend:         (days)       => request('GET',    `/vulns/trend${days ? `?days=${days}` : ''}`),
  getTopVulnDevices:    (limit)      => request('GET',    `/vulns/top-devices${limit ? `?limit=${limit}` : ''}`),

  // Network Tools (one-shot)
  toolsDns:           (host, type)  => request('GET', `/tools/dns?host=${encodeURIComponent(host)}&type=${encodeURIComponent(type)}`),
  toolsRdns:          (ip)          => request('GET', `/tools/rdns?ip=${encodeURIComponent(ip)}`),
  toolsDnsPropagation:(host, type)  => request('GET', `/tools/dns-propagation?host=${encodeURIComponent(host)}&type=${encodeURIComponent(type)}`),
  toolsHttpHeaders:   (url)         => request('GET', `/tools/http-headers?url=${encodeURIComponent(url)}`),
  toolsSsl:           (host, port)  => request('GET', `/tools/ssl?host=${encodeURIComponent(host)}&port=${port || 443}`),
  toolsGeo:           (ip)          => request('GET', `/tools/geo?ip=${encodeURIComponent(ip)}`),
  toolsWhois:         (host)        => request('GET', `/tools/whois?host=${encodeURIComponent(host)}`),
  toolsEmail:         (domain)      => request('GET', `/tools/email?domain=${encodeURIComponent(domain)}`),

  // Block schedules
  getBlockSchedules:    ()          => request('GET',    '/block-schedules'),
  createBlockSchedule:  (body)      => request('POST',   '/block-schedules', body),
  updateBlockSchedule:  (id, body)  => request('PATCH',  `/block-schedules/${id}`, body),
  deleteBlockSchedule:  (id)        => request('DELETE', `/block-schedules/${id}`),

  // Network pause / resume
  getNetworkStatus: ()  => request('GET',  '/network/status'),
  networkPause:     ()  => request('POST', '/network/pause'),
  networkResume:    ()  => request('POST', '/network/resume'),

  // Timeline
  getTimeline: (days) => request('GET', `/timeline${days ? `?days=${days}` : ''}`),

  // Zones
  getZones:     ()     => request('GET',  '/zones'),
  assignZone:   (body) => request('POST', '/zones/assign', body),
  renameZone:   (body) => request('POST', '/zones/rename', body),

  // Saved views (server-side)
  getSavedViews:    ()          => request('GET',    '/saved-views'),
  createSavedView:  (body)      => request('POST',   '/saved-views', body),
  updateSavedView:  (id, body)  => request('PUT',    `/saved-views/${id}`, body),
  deleteSavedView:  (id)        => request('DELETE', `/saved-views/${id}`),

  // Alert suppressions
  getSuppressions:    (mac)  => request('GET',    `/suppressions${mac ? `?mac=${mac}` : ''}`),
  createSuppression:  (body) => request('POST',   '/suppressions', body),
  deleteSuppression:  (id)   => request('DELETE', `/suppressions/${id}`),

  // Traffic monitoring
  trafficStart:       (mac)        => request('POST',   `/traffic/start/${mac}`),
  trafficStop:        (mac)        => request('DELETE', `/traffic/stop/${mac}`),
  trafficActive:      ()           => request('GET',    '/traffic/active'),
  trafficLive:        (mac)        => request('GET',    `/traffic/live/${mac}`),
  trafficHistory:     (mac, days)  => request('GET',    `/traffic/history/${mac}${days ? `?days=${days}` : ''}`),
  trafficTopDomains:  (mac, days)  => request('GET',    `/traffic/top-domains/${mac}${days ? `?days=${days}` : ''}`),
  trafficSummary:     ()           => request('GET',    '/traffic/summary'),
  trafficStream:      (mac, onLine, signal) => streamSSE(`/traffic/stream/${mac}`, onLine, signal),
}

export { streamSSE }
