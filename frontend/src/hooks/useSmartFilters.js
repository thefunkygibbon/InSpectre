/**
 * useSmartFilters
 *
 * Manages a set of active smart-filter IDs and exposes a function to apply
 * them to a device list.  Filters are additive (AND logic).
 * Saved views are persisted to localStorage.
 */
import { useState, useCallback, useEffect } from 'react'

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
    fn:          d => !d.device_type_override && !d.device_type,
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
    id:          'has_vuln',
    label:       'Vulnerable',
    icon:        'ShieldAlert',
    description: 'Devices with active vulnerability findings',
    fn:          d => d.vuln_severity && !['clean', 'info'].includes(d.vuln_severity),
  },
  {
    id:          'vuln_scanned',
    label:       'Vuln scanned',
    icon:        'ShieldCheck',
    description: 'Devices that have had a vulnerability scan completed',
    fn:          d => Boolean(d.vuln_last_scanned),
  },
  {
    id:          'not_vuln_scanned',
    label:       'Not vuln scanned',
    icon:        'ShieldOff',
    description: 'Devices that have never had a vulnerability scan run',
    fn:          d => !d.vuln_last_scanned,
  },
  {
    id:          'blocked',
    label:       'Blocked',
    icon:        'Ban',
    description: 'Devices currently blocked from internet access',
    fn:          d => Boolean(d.is_blocked),
  },
  {
    id:          'has_notes',
    label:       'Has notes',
    icon:        'FileText',
    description: 'Devices with notes or tags recorded',
    fn:          d => Boolean(d.notes || d.tags),
  },
  {
    id:          'tagged',
    label:       'Tagged',
    icon:        'Tags',
    description: 'Devices with at least one tag',
    fn:          d => Boolean(d.tags),
  },
  {
    id:          'ignored',
    label:       'Ignored',
    icon:        'EyeOff',
    description: 'Devices marked as ignored (hidden from main list)',
    fn:          d => Boolean(d.is_ignored),
  },
]

const SAVED_VIEWS_KEY = 'inspectre_saved_views'

function loadSavedViews() {
  try {
    const raw = localStorage.getItem(SAVED_VIEWS_KEY)
    return raw ? JSON.parse(raw) : []
  } catch {
    return []
  }
}

function persistSavedViews(views) {
  try {
    localStorage.setItem(SAVED_VIEWS_KEY, JSON.stringify(views))
  } catch {}
}

export function useSmartFilters() {
  const [activeFilters, setActiveFilters] = useState([])
  const [savedViews,    setSavedViews]    = useState(() => loadSavedViews())

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

  const saveView = useCallback((name) => {
    if (!name.trim() || !activeFilters.length) return
    setSavedViews(prev => {
      const next = [...prev, { id: Date.now().toString(), name: name.trim(), filters: [...activeFilters] }]
      persistSavedViews(next)
      return next
    })
  }, [activeFilters])

  const loadView = useCallback((viewId) => {
    const view = savedViews.find(v => v.id === viewId)
    if (view) setActiveFilters([...view.filters])
  }, [savedViews])

  const deleteView = useCallback((viewId) => {
    setSavedViews(prev => {
      const next = prev.filter(v => v.id !== viewId)
      persistSavedViews(next)
      return next
    })
  }, [])

  return { activeFilters, toggleFilter, clearFilters, applyFilters, savedViews, saveView, loadView, deleteView }
}
