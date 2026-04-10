const BASE = import.meta.env.VITE_API_URL || '/api'

async function request(method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) throw new Error(`${method} ${path} → ${res.status}`)
  return res.json()
}

export const api = {
  // Devices
  getDevices:    ()           => request('GET',   '/devices'),
  getDevice:     (mac)        => request('GET',   `/devices/${mac}`),
  updateDevice:  (mac, body)  => request('PATCH', `/devices/${mac}`, body),
  resolveName:   (mac)        => request('POST',  `/devices/${mac}/resolve-name`),
  rescanDevice:  (mac)        => request('POST',  `/devices/${mac}/rescan`),
  getScanResults:(mac)        => request('GET',   `/devices/${mac}/scan`),
  getIpHistory:  (mac)        => request('GET',   `/devices/${mac}/ip-history`),
  getStats:      ()           => request('GET',   '/stats'),

  // Settings
  getSettings:   ()           => request('GET',  '/settings'),
  updateSetting: (key, value) => request('PUT',  `/settings/${key}`, { value: String(value) }),
  resetSettings: ()           => request('POST', '/settings/reset'),
}
