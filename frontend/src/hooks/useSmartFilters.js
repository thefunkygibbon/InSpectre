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
  } catch { return [] }
}

function persistSavedViews(views) {
  try { localStorage.setItem(SAVED_VIEWS_KEY, JSON.stringify(views)) } catch {}
}

export function useSmartFilters() {
  // activeFilters: { [id]: 'include' | 'exclude' }
  const [activeFilters, setActiveFilters] = useState({})
  const [savedViews,    setSavedViews]    = useState(() => loadSavedViews())

  // Cycle: off → include → exclude → off
  const toggleFilter = useCallback(id => {
    setActiveFilters(prev => {
      const current = prev[id]
      if (!current)             return { ...prev, [id]: 'include' }
      if (current === 'include') return { ...prev, [id]: 'exclude' }
      // exclude → remove key entirely
      const next = { ...prev }
      delete next[id]
      return next
    })
  }, [])

  const clearFilters = useCallback(() => setActiveFilters({}), [])

  const applyFilters = useCallback((devices) => {
    const entries = Object.entries(activeFilters)
    if (!entries.length) return devices

    return devices.filter(d => {
      for (const [id, mode] of entries) {
        const filter = SMART_FILTERS.find(f => f.id === id)
        if (!filter) continue
        const match = filter.fn(d)
        if (mode === 'include' && !match) return false
        if (mode === 'exclude' &&  match) return false
      }
      return true
    })
  }, [activeFilters])

  // Saved views store the full activeFilters object now
  const saveView = useCallback((name) => {
    if (!name.trim() || !Object.keys(activeFilters).length) return
    setSavedViews(prev => {
      const next = [...prev, { id: Date.now().toString(), name: name.trim(), filters: { ...activeFilters } }]
      persistSavedViews(next)
      return next
    })
  }, [activeFilters])

  const loadView = useCallback((viewId) => {
    const view = savedViews.find(v => v.id === viewId)
    if (view) setActiveFilters({ ...view.filters })
  }, [savedViews])

  const deleteView = useCallback((viewId) => {
    setSavedViews(prev => {
      const next = prev.filter(v => v.id !== viewId)
      persistSavedViews(next)
      return next
    })
  }, [])

  // Helpers for components
  const getFilterState = useCallback((id) => activeFilters[id] || null, [activeFilters])
  const hasActiveFilters = Object.keys(activeFilters).length > 0

  return {
    activeFilters, toggleFilter, clearFilters, applyFilters,
    savedViews, saveView, loadView, deleteView,
    getFilterState, hasActiveFilters,
  }
}
