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
  getDevices:    ()           => request('GET',   '/devices'),
  getDevice:     (mac)        => request('GET',   `/devices/${mac}`),
  updateDevice:  (mac, body)  => request('PATCH', `/devices/${mac}`, body),
  resolveName:   (mac)        => request('POST',  `/devices/${mac}/resolve-name`),
  getScanResults:(mac)        => request('GET',   `/devices/${mac}/scan`),
  getStats:      ()           => request('GET',   '/stats'),
}
