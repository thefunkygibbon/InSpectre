import {
  Star, HelpCircle, Tag, Unlock, ScanLine,
  WifiOff, Tags, MapPin
} from 'lucide-react'
import { SMART_FILTERS } from '../hooks/useSmartFilters'

const ICON_MAP = {
  Star, HelpCircle, Tag, Unlock, ScanLine, WifiOff, Tags, MapPin,
}

export function SmartFilterBar({ devices, activeFilters, onToggle, onClear }) {
  // Count matches per filter
  function countFor(filter) {
    return devices.filter(filter.fn).length
  }

  return (
    <div className="flex flex-wrap gap-2 items-center">
      {SMART_FILTERS.map(f => {
        const active  = activeFilters.includes(f.id)
        const count   = countFor(f)
        const Icon    = ICON_MAP[f.icon] || HelpCircle
        return (
          <button
            key={f.id}
            title={f.description}
            onClick={() => onToggle(f.id)}
            className={[
              'flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium border transition-all',
              active
                ? 'border-transparent text-white'
                : 'border-transparent hover:border-current',
            ].join(' ')}
            style={active
              ? { background: 'var(--color-primary)', color: '#fff' }
              : { background: 'var(--color-surface-offset)', color: 'var(--color-text-muted)' }
            }
          >
            <Icon size={12} />
            {f.label}
            {count > 0 && (
              <span
                className="ml-0.5 px-1.5 py-0.5 rounded-full text-[10px] font-semibold"
                style={active
                  ? { background: 'rgba(255,255,255,0.25)', color: '#fff' }
                  : { background: 'var(--color-surface-dynamic)', color: 'var(--color-text-muted)' }
                }
              >
                {count}
              </span>
            )}
          </button>
        )
      })}

      {activeFilters.length > 0 && (
        <button
          onClick={onClear}
          className="text-xs px-2 py-1 rounded-full"
          style={{ color: 'var(--color-text-faint)' }}
        >
          Clear filters
        </button>
      )}
    </div>
  )
}
