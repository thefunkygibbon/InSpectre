import { useState, useEffect, useRef, useCallback } from 'react'
import { api } from '../api'

/**
 * useDevices
 *
 * Polls /devices and /stats on an interval.
 * Detects new MACs and devices dropping offline between polls,
 * exposing alert state for the UI to render toasts.
 * New-device alerts auto-dismiss after 8 seconds.
 */
export function useDevices(intervalMs = 10000) {
  const [devices,     setDevices]     = useState([])
  const [stats,       setStats]       = useState(null)
  const [loading,     setLoading]     = useState(true)
  const [error,       setError]       = useState(null)
  const [lastRefresh, setLastRefresh] = useState(null)

  // Alert state
  const [newDeviceAlerts, setNewDeviceAlerts] = useState([]) // [{ id, mac, ip, vendor, hostname }]
  const [offlineAlerts,   setOfflineAlerts]   = useState([]) // [{ id, mac, ip, name }]

  const knownMacsRef  = useRef(null)        // Set<string> -- null = first load
  const prevOnlineRef = useRef(new Map())   // mac -> was_online

  const fetchData = useCallback(async () => {
    try {
      const [devList, st] = await Promise.all([api.getDevices(), api.getStats()])

      // ---- New device detection ----
      if (knownMacsRef.current === null) {
        // First load -- seed known MACs, no alerts
        knownMacsRef.current = new Set(devList.map(d => d.mac_address))
      } else {
        const newOnes = devList.filter(d => !knownMacsRef.current.has(d.mac_address))
        if (newOnes.length) {
          const alerts = newOnes.map(d => ({
            id:       d.mac_address,
            mac:      d.mac_address,
            ip:       d.ip_address,
            vendor:   d.vendor   || 'Unknown vendor',
            hostname: d.hostname || null,
          }))
          setNewDeviceAlerts(prev => [...prev, ...alerts])
          newOnes.forEach(d => knownMacsRef.current.add(d.mac_address))
          // Auto-dismiss after 8 seconds
          setTimeout(() => {
            const ids = new Set(alerts.map(a => a.id))
            setNewDeviceAlerts(prev => prev.filter(a => !ids.has(a.id)))
          }, 8000)
        }
      }

      // ---- Offline drop detection ----
      const prevOnline = prevOnlineRef.current
      const droppedOff = devList.filter(d => {
        const wasOnline = prevOnline.get(d.mac_address)
        return wasOnline === true && d.is_online === false
      })
      if (droppedOff.length) {
        setOfflineAlerts(prev => [
          ...prev,
          ...droppedOff.map(d => ({
            id:   d.mac_address,
            mac:  d.mac_address,
            ip:   d.ip_address,
            name: d.display_name || d.ip_address,
          })),
        ])
      }
      // Update previous online map
      prevOnlineRef.current = new Map(devList.map(d => [d.mac_address, d.is_online]))

      setDevices(devList)
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
    fetchData()
    const id = setInterval(fetchData, intervalMs)
    return () => clearInterval(id)
  }, [fetchData, intervalMs])

  function dismissNewDevice(id) {
    setNewDeviceAlerts(prev => prev.filter(a => a.id !== id))
  }

  function dismissOffline(id) {
    setOfflineAlerts(prev => prev.filter(a => a.id !== id))
  }

  function dismissAllNew()     { setNewDeviceAlerts([]) }
  function dismissAllOffline() { setOfflineAlerts([]) }

  return {
    devices,
    stats,
    loading,
    error,
    lastRefresh,
    refresh: fetchData,
    newDeviceAlerts,
    offlineAlerts,
    dismissNewDevice,
    dismissOffline,
    dismissAllNew,
    dismissAllOffline,
  }
}
