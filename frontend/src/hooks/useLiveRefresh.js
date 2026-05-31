// ---------------------------------------------------------------------------
// useLiveRefresh — run a callback when matching SSE channels fire.
//
// Wraps subscribeLive() with a short debounce so a burst of events triggers a
// single refresh.  Components pass the channels they care about and their
// existing load() function; the page updates live on real changes instead of
// polling on a fixed timer.
// ---------------------------------------------------------------------------
import { useEffect, useRef } from 'react'
import { subscribeLive } from '../lib/liveEvents'

export function useLiveRefresh(channels, callback, { debounceMs = 300, enabled = true } = {}) {
  const cbRef = useRef(callback)
  cbRef.current = callback

  // Channels can be an array literal recreated each render; key by content so
  // the effect doesn't resubscribe every render.
  const channelKey = Array.isArray(channels) ? channels.join(',') : String(channels)

  useEffect(() => {
    if (!enabled) return undefined
    let timer = null
    const run = (channel, data) => {
      if (timer) clearTimeout(timer)
      timer = setTimeout(() => {
        timer = null
        try { cbRef.current?.(channel, data) } catch { /* ignore */ }
      }, debounceMs)
    }
    const unsub = subscribeLive(channels, run)
    return () => {
      if (timer) clearTimeout(timer)
      unsub()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [channelKey, debounceMs, enabled])
}
