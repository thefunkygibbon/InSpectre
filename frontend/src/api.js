const BASE = '/api'

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) throw new Error(`API ${path} failed: ${res.status}`)
  return res.json()
}

export const api = {
  getDevices:    (onlineOnly = false) => request(`/devices${onlineOnly ? '?online_only=true' : ''}`),
  getDevice:     (mac)               => request(`/devices/${mac}`),
  updateDevice:  (mac, data)         => request(`/devices/${mac}`, { method: 'PATCH', body: JSON.stringify(data) }),
  getScanResult: (mac)               => request(`/devices/${mac}/scan`),
  getStats:      ()                  => request('/stats'),
  getSettings:   ()                  => request('/settings'),
  updateSetting: (key, value)        => request(`/settings/${key}`, { method: 'PATCH', body: JSON.stringify({ value: String(value) }) }),
  resetSettings: ()                  => request('/settings/reset', { method: 'POST' }),
}
