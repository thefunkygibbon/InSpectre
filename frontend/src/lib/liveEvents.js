// ---------------------------------------------------------------------------
// liveEvents — single shared Server-Sent Events connection for live UI updates.
//
// The backend pushes named events ('devices', 'persons', 'schedules') whenever
// the underlying data changes.  Components subscribe to the channels they care
// about and re-fetch on demand, instead of polling on a timer.
//
// One EventSource is shared across the whole app (browsers cap concurrent
// connections per origin, so we must not open one per component).  The browser
// reconnects automatically; pages also keep a slow fallback poll as a safety
// net in case the stream drops.
// ---------------------------------------------------------------------------
import { getToken } from '../api'

const BASE = import.meta.env.VITE_API_URL || '/api'

// Known channels we addEventListener for. 'ready' fires on (re)connect.
const CHANNELS = ['ready', 'devices', 'persons', 'schedules', 'message']

let source = null
let connectedToken = null
// channel -> Set<callback>
const listeners = new Map()
// callbacks subscribed to every channel
const wildcard = new Set()

function emit(channel, data) {
  const set = listeners.get(channel)
  if (set) for (const cb of [...set]) { try { cb(channel, data) } catch { /* ignore */ } }
  for (const cb of [...wildcard]) { try { cb(channel, data) } catch { /* ignore */ } }
}

function handle(channel) {
  return (ev) => {
    let data = {}
    try { data = ev.data ? JSON.parse(ev.data) : {} } catch { /* ignore */ }
    emit(channel, data)
  }
}

function connect() {
  const token = getToken()
  if (!token) return                       // not logged in yet
  if (source && connectedToken === token) return
  disconnect()
  connectedToken = token
  const url = `${BASE}/events/stream?token=${encodeURIComponent(token)}`
  try {
    source = new EventSource(url)
  } catch {
    source = null
    return
  }
  for (const ch of CHANNELS) source.addEventListener(ch, handle(ch))
  // EventSource auto-reconnects on error; nothing else to do here.
}

function disconnect() {
  if (source) { try { source.close() } catch { /* ignore */ } }
  source = null
  connectedToken = null
}

function ensureConnected() {
  // (Re)connect if needed — e.g. after login when a token first appears, or if
  // the token changed.
  const token = getToken()
  if (!token) { disconnect(); return }
  if (!source || connectedToken !== token) connect()
}

/**
 * Subscribe to one or more SSE channels.
 * @param {string|string[]} channels  channel name(s), or '*' for all.
 * @param {(channel: string, data: object) => void} callback
 * @returns {() => void} unsubscribe
 */
export function subscribeLive(channels, callback) {
  ensureConnected()
  const list = channels === '*' ? null : (Array.isArray(channels) ? channels : [channels])
  if (list === null) {
    wildcard.add(callback)
  } else {
    for (const ch of list) {
      if (!listeners.has(ch)) listeners.set(ch, new Set())
      listeners.get(ch).add(callback)
    }
  }
  return () => {
    if (list === null) {
      wildcard.delete(callback)
    } else {
      for (const ch of list) listeners.get(ch)?.delete(callback)
    }
    // Close the stream once nothing is listening.
    const anyLeft = wildcard.size > 0 || [...listeners.values()].some(s => s.size > 0)
    if (!anyLeft) disconnect()
  }
}

// Reconnect when the tab becomes visible again (mobile/laptop sleep can drop the
// connection without a clean error).
if (typeof document !== 'undefined') {
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') ensureConnected()
  })
}
