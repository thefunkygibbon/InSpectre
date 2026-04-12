/**
 * useSmartFilters
 *
 * Manages a set of active smart-filter IDs and exposes a function to apply
 * them to a device list.  Filters are additive (AND logic).
 */
import { useState, useCallback } from 'react'

export const SMART_FILTERS = [
  {
    id:          'important',
    label:       'Watched',
    icon:        'Star',
    description: 'Devices you have starred as important',
    fn:          d => Boolean(d.is_important),
  },
  {
    id:          'unknown',
    label:       'Unknown type',
    icon:        'HelpCircle',
    description: 'Devices with no device type set',
    fn:          d => !d.device_type_override,
  },
  {
    id:          'unnamed',
    label:       'Unnamed',
    icon:        'Tag',
    description: 'Devices with no custom name or hostname',
    fn:          d => !d.custom_name && !d.hostname,
  },
  {
    id:          'open_ports',
    label:       'Open ports',
    icon:        'Unlock',
    description: 'Devices with at least one open port detected',
    fn:          d => {
      const ports = d.scan_results?.open_ports
      return Array.isArray(ports) && ports.length > 0
    },
  },
  {
    id:          'unscanned',
    label:       'Not scanned',
    icon:        'ScanLine',
    description: 'Devices that have not yet been deep-scanned',
    fn:          d => !d.deep_scanned,
  },
  {
    id:          'tagged',
    label:       'Tagged',
    icon:        'Tags',
    description: 'Devices with at least one tag',
    fn:          d => Array.isArray(d.tags_array) && d.tags_array.length > 0,
  },
  {
    id:          'located',
    label:       'Located',
    icon:        'MapPin',
    description: 'Devices with a room/location set',
    fn:          d => Boolean(d.location),
  },
]

export function useSmartFilters() {
  const [activeFilters, setActiveFilters] = useState([])

  const toggleFilter = useCallback(id => {
    setActiveFilters(prev =>
      prev.includes(id) ? prev.filter(f => f !== id) : [...prev, id]
    )
  }, [])

  const clearFilters = useCallback(() => setActiveFilters([]), [])

  const applyFilters = useCallback((devices) => {
    if (!activeFilters.length) return devices
    const activeFns = SMART_FILTERS
      .filter(f => activeFilters.includes(f.id))
      .map(f => f.fn)
    return devices.filter(d => activeFns.every(fn => fn(d)))
  }, [activeFilters])

  return { activeFilters, toggleFilter, clearFilters, applyFilters }
}
