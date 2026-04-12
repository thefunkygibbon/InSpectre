/**
 * Phase 1: Smart filter definitions and filtering logic.
 * Each filter has: id, label, icon (string), description, fn(device) -> bool
 */

export const SMART_FILTERS = [
  {
    id:          'important',
    label:       'Important',
    icon:        'Star',
    description: 'Devices marked as important / watched',
    fn: d => Boolean(d.is_important),
  },
  {
    id:          'unknown',
    label:       'Unknown type',
    icon:        'HelpCircle',
    description: 'No device type has been identified',
    fn: d => !d.device_type_override && !d.vendor,
  },
  {
    id:          'unnamed',
    label:       'Unnamed',
    icon:        'Tag',
    description: 'No custom name or hostname set',
    fn: d => !d.custom_name && !d.hostname,
  },
  {
    id:          'open_ports',
    label:       'Open ports',
    icon:        'Unlock',
    description: 'Device has one or more open ports',
    fn: d => Array.isArray(d.scan_results?.open_ports) && d.scan_results.open_ports.length > 0,
  },
  {
    id:          'unscanned',
    label:       'Not yet scanned',
    icon:        'ScanLine',
    description: 'Deep scan has not completed',
    fn: d => !d.deep_scanned,
  },
  {
    id:          'offline',
    label:       'Offline',
    icon:        'WifiOff',
    description: 'Currently offline',
    fn: d => !d.is_online,
  },
  {
    id:          'tagged',
    label:       'Tagged',
    icon:        'Tags',
    description: 'Has one or more tags',
    fn: d => Array.isArray(d.tags_array) && d.tags_array.length > 0,
  },
  {
    id:          'located',
    label:       'Has location',
    icon:        'MapPin',
    description: 'Location/room has been set',
    fn: d => Boolean(d.location),
  },
]

/**
 * Apply an array of active filter ids to a device list.
 * Multiple active filters are ANDed together.
 */
export function applySmartFilters(devices, activeIds) {
  if (!activeIds || activeIds.length === 0) return devices
  const active = SMART_FILTERS.filter(f => activeIds.includes(f.id))
  return devices.filter(d => active.every(f => f.fn(d)))
}
