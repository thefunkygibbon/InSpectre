// ---------------------------------------------------------------------------
// liveEvents — single shared Server-Sent Events connection for live UI updates.
//
// The backend pushes named events ('devices', 'persons', 'schedules') whenever
// the underlying data changes.  Components subscribe to the channels they care
// about and re-fetch on demand, instead of polling on a timer.
//
// One stream is shared across the whole app.  We use fetch() (not EventSource)
// so the auth token travels in the Authorization header rather than the URL —
// URLs leak into server/proxy logs and browser history.  fetch() does not
// auto-reconnect, so we implement a small reconnect loop ourselves.
// ---------------------------------------------------------------------------
import { getToken } from '../api'

const BASE = import.meta.env.VITE_API_URL || '/api'

// Known channels we dispatch. 'ready' fires on (re)connect.
const CHANNELS = new Set(['ready', 'devices', 'persons', 'schedules', 'message'])

let controller = null          // AbortController for the active fetch stream
let connectedToken = null
let reconnectTimer = null
let generation = 0             // bumped on every (re)connect to invalidate stale loops

// channel -> Set<callback>
const listeners = new Map()
// callbacks subscribed to every channel
const wildcard = new Set()

function emit(channel, data) {
  const set = listeners.get(channel)
  if (set) for (const cb of [...set]) { try { cb(channel, data) } catch { /* ignore */ } }
  for (const cb of [...wildcard]) { try { cb(channel, data) } catch { /* ignore */ } }
}

function dispatchEvent(eventName, dataStr) {
  const channel = CHANNELS.has(eventName) ? eventName : 'message'
  let data = {}
  try { data = dataStr ? JSON.parse(dataStr) : {} } catch { /* ignore */ }
  emit(channel, data)
}

async function runStream(token, myGen) {
  let res
  try {
    res = await fetch(`${BASE}/events/stream`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: controller.signal,
    })
  } catch {
    scheduleReconnect(myGen)
    return
  }
  if (!res.ok || !res.body) {
    scheduleReconnect(myGen)
    return
  }

  const reader  = res.body.getReader()
  const decoder = new TextDecoder()
  let buf = ''
  let eventName = 'message'
  let dataLines = []

  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      buf += decoder.decode(value, { stream: true })
      let idx
      while ((idx = buf.indexOf('\n')) !== -1) {
        let line = buf.slice(0, idx)
        buf = buf.slice(idx + 1)
        if (line.endsWith('\r')) line = line.slice(0, -1)
        if (line === '') {
          // End of an SSE event block — dispatch it.
          if (dataLines.length) dispatchEvent(eventName, dataLines.join('\n'))
          eventName = 'message'
          dataLines = []
        } else if (line.startsWith('event:')) {
          eventName = line.slice(6).trim()
        } else if (line.startsWith('data:')) {
          dataLines.push(line.slice(5).replace(/^ /, ''))
        }
        // ':' comment lines and other fields are ignored.
      }
    }
  } catch {
    // network error / aborted — fall through to reconnect logic
  }
  // Stream ended: reconnect unless this generation was superseded/aborted.
  scheduleReconnect(myGen)
}

function scheduleReconnect(myGen) {
  if (myGen !== generation) return            // superseded by a newer connect/disconnect
  if (reconnectTimer) return
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null
    if (myGen !== generation) return
    ensureConnected()
  }, 3000)
}

function connect() {
  const token = getToken()
  if (!token) return                          // not logged in yet
  if (controller && connectedToken === token) return
  disconnect()
  connectedToken = token
  const myGen = ++generation
  controller = new AbortController()
  runStream(token, myGen)
}

function disconnect() {
  generation++                                // invalidate any in-flight reconnect loops
  if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null }
  if (controller) { try { controller.abort() } catch { /* ignore */ } }
  controller = null
  connectedToken = null
}

function ensureConnected() {
  // (Re)connect if needed — e.g. after login when a token first appears, or if
  // the token changed.
  const token = getToken()
  if (!token) { disconnect(); return }
  if (!controller || connectedToken !== token) connect()
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
