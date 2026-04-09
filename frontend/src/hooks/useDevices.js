import { useState, useEffect, useCallback } from 'react'
import { api } from '../api'

export function useDevices(intervalMs = 10000) {
  const [devices, setDevices]   = useState([])
  const [stats, setStats]       = useState(null)
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [lastRefresh, setLastRefresh] = useState(null)

  const refresh = useCallback(async () => {
    try {
      const [devs, st] = await Promise.all([api.getDevices(), api.getStats()])
      setDevices(devs)
      setStats(st)
      setError(null)
      setLastRefresh(new Date())
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
    const id = setInterval(refresh, intervalMs)
    return () => clearInterval(id)
  }, [refresh, intervalMs])

  return { devices, stats, loading, error, refresh, lastRefresh }
}
