const BASE = import.meta.env.VITE_API_URL || '/api'

// ---------------------------------------------------------------------------
// Token storage
// ---------------------------------------------------------------------------
export function getToken() { return localStorage.getItem('inspectre_token') }
export function setToken(t) { if (t) localStorage.setItem('inspectre_token', t); else localStorage.removeItem('inspectre_token') }
export function clearToken() { localStorage.removeItem('inspectre_token') }

async function request(method, path, body) {
  const token = getToken()
  const headers = {}
  if (body) headers['Content-Type'] = 'application/json'
  if (token) headers['Authorization'] = `Bearer ${token}`
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  })
  if (res.status === 401) {
    clearToken()
    window.location.reload()
    throw new Error('Session expired')
  }
  if (!res.ok) throw new Error(`${method} ${path} \u2192 ${res.status}`)
  return res.json()
}

async function streamSSE(path, onLine, signal) {
  const token   = getToken()
  const headers = token ? { Authorization: `Bearer ${token}` } : {}
  const res = await fetch(`${BASE}${path}`, { signal, headers })
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
  // Health / status
  getHealth: () => {
    const token = getToken()
    return fetch(`${BASE}/health`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    }).then(r => r.json()).catch(() => ({
      backend: { ok: false, message: 'Unreachable' },
      database: { ok: false, message: 'Unknown' },
      probe:    { ok: false, message: 'Unknown' },
      all_ok: false,
      active_scans: { port: [], vuln: [] },
    }))
  },

  // Auth
  login:          (username, password) => request('POST', '/auth/login', { username, password }),
  authMe:         ()                   => request('GET',  '/auth/me'),
  changePassword: (current, next)      => request('POST', '/auth/change-password', { current_password: current, new_password: next }),

  // Setup wizard
  setupStatus:      ()       => request('GET',  '/setup/status'),
  setupCreateUser:  (u, p)   => request('POST', '/setup/create-user', { username: u, password: p }),
  setupNetworkInfo: ()       => request('GET',  '/setup/network-info'),
  setupApplyNetwork:(body)   => request('POST', '/setup/apply-network', body),
  setupComplete:    (body)   => request('POST', '/setup/complete', body),

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
  resolveName:      (mac) => request('POST', `/devices/${mac}/resolve-name`),
  rescanDevice:     (mac) => request('POST', `/devices/${mac}/rescan`),
  resetBaseline:    (mac) => request('POST', `/devices/${mac}/reset-baseline`),
  fingerbankLookup: (mac) => request('POST', `/devices/${mac}/fingerbank/lookup`),
  getScanResults:  (mac)        => request('GET',   `/devices/${mac}/scan`),
  getIpHistory:    (mac)        => request('GET',   `/devices/${mac}/ip-history`),
  setPrimaryIp:    (mac, ip)    => request('POST',  `/devices/${mac}/set-primary-ip`, { ip_address: ip }),
  unpinPrimaryIp:  (mac)        => request('POST',  `/devices/${mac}/unpin-ip`),
  getDeviceEvents: (mac, limit, type) => {
    const p = new URLSearchParams()
    if (limit) p.set('limit', limit)
    if (type)  p.set('type', type)
    return request('GET', `/devices/${mac}/events${p.toString() ? '?' + p : ''}`)
  },
  getDeviceServices:  (mac)           => request('GET',  `/devices/${mac}/services`),
  getDeviceGroup:     (mac)           => request('GET',  `/devices/${mac}/group`),
  addToGroup:         (mac, targetMac)=> request('POST', `/devices/${mac}/group/add`, { target_mac: targetMac }),
  removeFromGroup:    (mac)           => request('POST', `/devices/${mac}/group/remove`),
  setGroupPrimary:    (mac)           => request('PUT',  `/devices/${mac}/group/primary`),
  refreshMdns:       (mac)      => request('POST', `/devices/${mac}/mdns-refresh`),
  networkMdnsScan:   ()         => request('POST', '/network/mdns-scan'),
  networkSsdpScan:   ()         => request('POST', '/network/ssdp-scan'),
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
  restartProbe:    ()           => request('POST', '/settings/restart-probe'),
  restartBackend:  ()           => request('POST', '/settings/restart-backend'),

  // Home Assistant MQTT (legacy — kept for backward compat)
  haMqttStatus:     ()         => request('GET',  '/ha-mqtt/status'),
  haMqttReconnect:  ()         => request('POST', '/ha-mqtt/reconnect'),
  haMqttDisconnect: ()         => request('POST', '/ha-mqtt/disconnect'),

  // Plugins
  listPlugins:      ()              => request('GET',    '/plugins'),
  getPlugin:        (id)            => request('GET',    `/plugins/${id}`),
  savePluginConfig: (id, config)    => request('PUT',    `/plugins/${id}/config`, { config }),
  enablePlugin:     (id)            => request('PATCH',  `/plugins/${id}/enable`),
  disablePlugin:    (id)            => request('PATCH',  `/plugins/${id}/disable`),
  deletePlugin:     (id)            => request('DELETE', `/plugins/${id}`),
  testPlugin:       (id)            => request('POST',   `/plugins/${id}/test`),
  pollPlugin:       (id)            => request('POST',   `/plugins/${id}/poll`),
  getPluginData:    (id)            => request('GET',    `/plugins/${id}/data`),
  uploadPlugin: (file) => {
    const form = new FormData()
    form.append('file', file)
    const token = getToken()
    const headers = token ? { Authorization: `Bearer ${token}` } : {}
    return fetch(`${BASE}/plugins/upload`, { method: 'POST', body: form, headers })
      .then(async r => {
        if (!r.ok) {
          const e = await r.json().catch(() => ({}))
          throw new Error(e.detail || `Upload failed: ${r.status}`)
        }
        return r.json()
      })
  },

  // Export (include auth header so the global middleware allows through)
  exportDevicesCsv: () => {
    const token = getToken()
    return fetch(`${BASE}/export/devices`, { headers: token ? { Authorization: `Bearer ${token}` } : {} })
  },
  exportFingerprintsJson: () => {
    const token = getToken()
    return fetch(`${BASE}/export/fingerprints`, { headers: token ? { Authorization: `Bearer ${token}` } : {} })
  },

  // Import
  importFingerprintsJson: (file) => {
    const form = new FormData()
    form.append('file', file)
    const token = getToken()
    const headers = token ? { Authorization: `Bearer ${token}` } : {}
    return fetch(`${BASE}/import/fingerprints`, { method: 'POST', body: form, headers })
      .then(r => { if (!r.ok) throw new Error(`Import failed: ${r.status}`); return r.json() })
  },

  // Streaming
  streamPing:       (mac, signal) => streamSSE(`/devices/${mac}/ping`,       (l) => l, signal),
  streamTraceroute: (mac, signal) => streamSSE(`/devices/${mac}/traceroute`, (l) => l, signal),

  // Phase 4 — ARP block
  blockDevice:   (mac) => request('POST', `/devices/${mac}/block`),
  unblockDevice: (mac) => request('POST', `/devices/${mac}/unblock`),

  // Phase 3 — Vuln scanning
  getVulnReports:       (mac, limit) => request('GET',    `/devices/${mac}/vuln-reports${limit ? `?limit=${limit}` : ''}`),
  getVulnReportDetail:  (mac, id)    => request('GET',    `/devices/${mac}/vuln-reports/${id}`),
  getVulnScanStatus:    (mac)        => request('GET',    `/devices/${mac}/vuln-scan-status`),
  acknowledgeDevice:    (mac)        => request('POST',   `/devices/${mac}/acknowledge`),
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
  toolsArpLookup:     (query)       => request('GET', `/tools/arp-lookup?query=${encodeURIComponent(query)}`),
  toolsWakeOnLan:     (mac, bcast)  => request('POST', '/tools/wake-on-lan', { mac, broadcast: bcast || '255.255.255.255' }),
  toolsDoh:           (host, type)  => request('GET', `/tools/doh?host=${encodeURIComponent(host)}&type=${encodeURIComponent(type)}`),
  toolsDnssec:        (host)        => request('GET', `/tools/dnssec?host=${encodeURIComponent(host)}`),
  toolsRdnsBulk:      (cidr)        => request('GET', `/tools/rdns-bulk?cidr=${encodeURIComponent(cidr)}`),
  toolsRedirectChain: (url)         => request('GET', `/tools/redirect-chain?url=${encodeURIComponent(url)}`),
  toolsHttpTiming:    (url)         => request('GET', `/tools/http-timing?url=${encodeURIComponent(url)}`),
  toolsTlsVersions:   (host, port)  => request('GET', `/tools/tls-versions?host=${encodeURIComponent(host)}&port=${port || 443}`),
  toolsBgp:           (query)       => request('GET', `/tools/bgp?query=${encodeURIComponent(query)}`),
  toolsSmtpBanner:    (host, port)  => request('GET', `/tools/smtp-banner?host=${encodeURIComponent(host)}&port=${port || 25}`),
  toolsBimi:          (domain)      => request('GET', `/tools/bimi?domain=${encodeURIComponent(domain)}`),
  toolsDnsbl:         (ip)          => request('GET', `/tools/dnsbl?ip=${encodeURIComponent(ip)}`),

  // Speed test
  speedtestResults:   ()                => request('GET',    '/speedtest/results'),
  deleteSpeedtest:    (id)              => request('DELETE', `/speedtest/results/${id}`),
  speedtestServers:   ()                => request('GET',    '/tools/speedtest-servers'),

  // Delete device
  deleteDevice:       (mac)             => request('DELETE', `/devices/${mac}`),

  // Backup / restore
  exportBackup: (password = '') => {
    const form = new FormData()
    form.append('password', password)
    const token = getToken()
    const headers = token ? { Authorization: `Bearer ${token}` } : {}
    return fetch(`${BASE}/export/backup`, { method: 'POST', body: form, headers })
  },
  importRestore: (file, password = '') => {
    const form = new FormData()
    form.append('file', file)
    form.append('password', password)
    const token = getToken()
    const headers = token ? { Authorization: `Bearer ${token}` } : {}
    return fetch(`${BASE}/import/restore`, { method: 'POST', body: form, headers })
      .then(async r => {
        if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || `Restore failed: ${r.status}`) }
        return r.json()
      })
  },
  setupRestoreFromBackup: (file, password = '') => {
    const form = new FormData()
    form.append('file', file)
    form.append('password', password)
    return fetch(`${BASE}/setup/restore-from-backup`, { method: 'POST', body: form })
      .then(r => { if (!r.ok) throw new Error(`Restore failed: ${r.status}`); return r.json() })
  },

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
  getTimeline:       (days)      => request('GET', `/timeline${days ? `?days=${days}` : ''}`),
  getDeviceTimeline: (mac, days) => request('GET', `/devices/${mac}/timeline${days ? `?days=${days}` : ''}`),

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

  // Docker container monitoring
  dockerStats:            ()              => request('GET',  '/docker/stats'),
  dockerContainers:       ()              => request('GET',  '/docker/containers'),
  dockerContainer:        (id)            => request('GET',  `/docker/containers/${id}`),
  dockerStart:            (id)            => request('POST', `/docker/containers/${id}/start`),
  dockerStop:             (id)            => request('POST', `/docker/containers/${id}/stop`),
  dockerRestart:          (id)            => request('POST', `/docker/containers/${id}/restart`),
  dockerLogs:             (id, tail, onLine, signal) => streamSSE(`/docker/containers/${id}/logs${tail ? `?tail=${tail}` : ''}`, onLine, signal),
  dockerTrivyScan:        (id, onLine, signal)       => streamSSE(`/docker/containers/${id}/trivy-scan`, onLine, signal),
  dockerAutoScanResult:   (name)      => request('GET',  `/docker/auto-scan/${encodeURIComponent(name)}`),
  dockerVulnSummary:      ()          => request('GET',  '/docker/vuln-summary'),
  dockerScanAll:          ()          => request('POST', '/docker/scan-all'),
  getContainerTimeline:   (days)      => request('GET',  `/docker/timeline?days=${days}`),

  // Container host management (multi-host: Docker + Proxmox)
  listContainerHosts:     ()          => request('GET',    '/container-hosts'),
  createContainerHost:    (body)      => request('POST',   '/container-hosts', body),
  updateContainerHost:    (id, body)  => request('PUT',    `/container-hosts/${id}`, body),
  deleteContainerHost:    (id)        => request('DELETE', `/container-hosts/${id}`),
  testContainerHost:      (id)        => request('POST',   `/container-hosts/${id}/test`),

  // Device acknowledgement
  acknowledgeDevice:  (mac)        => request('POST',   `/devices/${mac}/acknowledge`),

  // Traffic monitoring
  trafficStart:       (mac)        => request('POST',   `/traffic/start/${mac}`),
  trafficStop:        (mac)        => request('DELETE', `/traffic/stop/${mac}`),
  trafficActive:      ()           => request('GET',    '/traffic/active'),
  trafficLive:        (mac)        => request('GET',    `/traffic/live/${mac}`),
  trafficHistory:     (mac, days)  => request('GET',    `/traffic/history/${mac}${days ? `?days=${days}` : ''}`),
  trafficTopDomains:  (mac, days)  => request('GET',    `/traffic/top-domains/${mac}${days ? `?days=${days}` : ''}`),
  trafficSummary:     ()           => request('GET',    '/traffic/summary'),
  trafficStream:      (mac, onLine, signal) => streamSSE(`/traffic/stream/${mac}`, onLine, signal),

  // Notification channels
  notifChannels:        ()          => request('GET',    '/notifications/channels'),
  createNotifChannel:   (body)      => request('POST',   '/notifications/channels', body),
  updateNotifChannel:   (id, body)  => request('PUT',    `/notifications/channels/${id}`, body),
  deleteNotifChannel:   (id)        => request('DELETE', `/notifications/channels/${id}`),
  testNotifChannel:     (id)        => request('POST',   `/notifications/channels/${id}/test`),

  // Notification profiles
  notifProfiles:        ()          => request('GET',    '/notifications/profiles'),
  createNotifProfile:   (body)      => request('POST',   '/notifications/profiles', body),
  updateNotifProfile:   (id, body)  => request('PUT',    `/notifications/profiles/${id}`, body),
  deleteNotifProfile:   (id)        => request('DELETE', `/notifications/profiles/${id}`),

  // Notification event definitions and pending browser queue
  notifEvents:          ()          => request('GET',    '/notifications/events'),
  notifPending:         ()          => request('GET',    '/notifications/pending'),
}

export { streamSSE }
