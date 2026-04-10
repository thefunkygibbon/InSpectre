import { useState, useRef, useCallback, useEffect } from 'react'
import { streamSSE } from '../api'

/**
 * useStreamAction
 *
 * Manages an SSE stream with proper AbortController lifecycle.
 *
 * Usage:
 *   const stream = useStreamAction()
 *   stream.start('/devices/xx:xx/ping')
 *   stream.stop()
 *
 * Returns: { lines, running, start, stop }
 */
export function useStreamAction() {
  const [lines,   setLines]   = useState([])
  const [running, setRunning] = useState(false)
  const abortRef = useRef(null)

  const stop = useCallback(() => {
    if (abortRef.current) {
      abortRef.current.abort()
      abortRef.current = null
    }
    setRunning(false)
  }, [])

  const start = useCallback((path) => {
    // Cancel any in-flight stream first
    if (abortRef.current) {
      abortRef.current.abort()
    }

    const controller = new AbortController()
    abortRef.current = controller
    setLines([])
    setRunning(true)

    const BASE = import.meta.env.VITE_API_URL || '/api'

    // Use fetch directly for maximum control over the SSE stream
    fetch(`${BASE}${path}`, { signal: controller.signal })
      .then(async (res) => {
        if (!res.ok) {
          setLines([`ERROR: server returned ${res.status}`])
          setRunning(false)
          return
        }

        const reader = res.body.getReader()
        const decoder = new TextDecoder()
        let buf = ''

        // eslint-disable-next-line no-constant-condition
        while (true) {
          let result
          try {
            result = await reader.read()
          } catch (e) {
            // AbortError is expected when stop() is called -- swallow silently
            if (e.name !== 'AbortError') {
              setLines(prev => [...prev, `ERROR: ${e.message}`])
            }
            break
          }

          if (result.done) break

          buf += decoder.decode(result.value, { stream: true })
          const parts = buf.split('\n')
          buf = parts.pop() // keep the incomplete trailing chunk

          for (const part of parts) {
            const line = part.trim()
            if (line.startsWith('data:')) {
              const text = line.slice(5).trim()
              if (text && text !== '{}') {
                setLines(prev => [...prev, text])
              }
            }
          }
        }

        // Mark done only if not externally aborted
        if (!controller.signal.aborted) {
          setRunning(false)
        }
      })
      .catch((e) => {
        if (e.name !== 'AbortError') {
          setLines(prev => [...prev, `ERROR: ${e.message}`])
          setRunning(false)
        }
      })
  }, [])

  // Clean up on unmount
  useEffect(() => () => stop(), [stop])

  return { lines, running, start, stop }
}
