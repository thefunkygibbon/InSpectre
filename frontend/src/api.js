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

/**
 * Stream an SSE endpoint, calling onLine(text) for each data line.
 * Pass an AbortSignal to cancel mid-stream.
 */
async function streamSSE(path, onLine, signal) {
  const res = await fetch(`${BASE}${path}`, { signal })
  if (!res.ok) throw new Error(`GET ${path} \u2192 ${res.status}`)

  const reader  = res.body.getReader()
  const decoder = new TextDecoder()
  let buf = ''

  // eslint-disable-next-line no-constant-condition
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
  getDevices:      ()           => request('GET',   '/devices'),
  getDevice:       (mac)        => request('GET',   `/devices/${mac}`),
  updateDevice:    (mac, body)  => request('PATCH', `/devices/${mac}`, body),
  updateIdentity:  (mac, body)  => request('PATCH', `/devices/${mac}/identity`, body),
  resolveName:     (mac)        => request('POST',  `/devices/${mac}/resolve-name`),
  rescanDevice:    (mac)        => request('POST',  `/devices/${mac}/rescan`),
  getScanResults:  (mac)        => request('GET',   `/devices/${mac}/scan`),
  getIpHistory:    (mac)        => request('GET',   `/devices/${mac}/ip-history`),
  getStats:        ()           => request('GET',   '/stats'),

  // Fingerprint DB
  getFingerprints:     (params) => request('GET',    '/fingerprints' + (params ? `?${new URLSearchParams(params)}` : '')),
  getFingerprintStats: ()       => request('GET',    '/fingerprints/stats'),
  deleteFingerprint:   (id)     => request('DELETE', `/fingerprints/${id}`),

  // Settings
  getSettings:     ()           => request('GET',  '/settings'),
  updateSetting:   (key, value) => request('PUT',  `/settings/${key}`, { value: String(value) }),
  resetSettings:   ()           => request('POST', '/settings/reset'),

  // Export — returns a Response so the caller can trigger a file download
  exportDevicesCsv:       ()     => fetch(`${BASE}/export/devices`),
  exportFingerprintsJson: ()     => fetch(`${BASE}/export/fingerprints`),

  // Import — multipart file upload
  importFingerprintsJson: (file) => {
    const form = new FormData()
    form.append('file', file)
    return fetch(`${BASE}/import/fingerprints`, { method: 'POST', body: form })
      .then(r => { if (!r.ok) throw new Error(`Import failed: ${r.status}`); return r.json() })
  },

  // Streaming
  streamPing:       (mac, signal) => streamSSE(`/devices/${mac}/ping`,       (l) => l, signal),
  streamTraceroute: (mac, signal) => streamSSE(`/devices/${mac}/traceroute`, (l) => l, signal),
}

export { streamSSE }
