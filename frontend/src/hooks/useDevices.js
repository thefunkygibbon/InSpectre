import { useState, useEffect, useRef, useCallback } from 'react'
import { api } from '../api'

function enrich(d) {
  return {
    ...d,
    display_name: d.custom_name || d.hostname || d.ip_address || d.mac_address,
    tags_array: d.tags ? d.tags.split(',').map(t => t.trim()).filter(Boolean) : [],
  }
}

export function useDevices(intervalMs = 10000, { onAlert } = {}) {
  const [devices,     setDevices]     = useState([])
  const [stats,       setStats]       = useState(null)
  const [loading,     setLoading]     = useState(true)
  const [error,       setError]       = useState(null)
  const [lastRefresh, setLastRefresh] = useState(null)

  // Alert state
  const [newDeviceAlerts, setNewDeviceAlerts] = useState([])
  const [offlineAlerts,   setOfflineAlerts]   = useState([])

  const knownMacsRef  = useRef(null)
  const prevOnlineRef = useRef(new Map())
  const onAlertRef    = useRef(onAlert)
  useEffect(() => { onAlertRef.current = onAlert }, [onAlert])

  const fetchData = useCallback(async () => {
    try {
      const [rawList, st] = await Promise.all([api.getDevices(), api.getStats()])
      const devList = rawList.map(enrich)

      // New device detection
      const pageVisible = typeof document !== 'undefined' ? !document.hidden : true
      if (knownMacsRef.current === null) {
        knownMacsRef.current = new Set(devList.map(d => d.mac_address))
      } else {
        const newOnes = devList.filter(d => !knownMacsRef.current.has(d.mac_address))
        if (newOnes.length) {
          const alerts = newOnes.map(d => ({
            id:        d.mac_address,
            mac:       d.mac_address,
            ip:        d.ip_address,
            vendor:    d.vendor || 'Unknown vendor',
            hostname:  d.hostname || null,
            toastable: pageVisible,
          }))
          setNewDeviceAlerts(prev => [...prev, ...alerts])
          newOnes.forEach(d => knownMacsRef.current.add(d.mac_address))
          alerts.forEach(a => onAlertRef.current?.({ kind: 'new_device', ...a }))
        }
      }

      // Offline drop detection
      const prevOnline = prevOnlineRef.current
      const droppedOff = devList.filter(d => {
        const wasOnline = prevOnline.get(d.mac_address)
        return wasOnline === true && d.is_online === false
      })
      if (droppedOff.length) {
        const offAlerts = droppedOff.map(d => ({
          id:           d.mac_address,
          mac:          d.mac_address,
          ip:           d.ip_address,
          name:         d.display_name || d.ip_address,
          is_important: d.is_important,
          toastable:    pageVisible,
        }))
        setOfflineAlerts(prev => [...prev, ...offAlerts])
        offAlerts.forEach(a => onAlertRef.current?.({ kind: 'offline', ...a }))
      }
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

  function optimisticUpdate(mac, patch) {
    setDevices(prev =>
      prev.map(d => d.mac_address === mac ? enrich({ ...d, ...patch }) : d)
    )
  }

  function dismissNewDevice(id)    { setNewDeviceAlerts(prev => prev.filter(a => a.id !== id)) }
  function dismissOffline(id)      { setOfflineAlerts(prev => prev.filter(a => a.id !== id)) }
  function dismissAllNew()         { setNewDeviceAlerts([]) }
  function dismissAllOffline()     { setOfflineAlerts([]) }

  return {
    devices,
    stats,
    loading,
    error,
    lastRefresh,
    refresh: fetchData,
    optimisticUpdate,
    newDeviceAlerts,
    offlineAlerts,
    dismissNewDevice,
    dismissOffline,
    dismissAllNew,
    dismissAllOffline,
  }
}
