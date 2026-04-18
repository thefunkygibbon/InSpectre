import { useState } from 'react'
import {
  Star, HelpCircle, Tag, Unlock, ScanLine,
  WifiOff, Tags, MapPin, ShieldAlert, Ban, FileText,
  Bookmark, BookmarkCheck, X,
} from 'lucide-react'
import { SMART_FILTERS } from '../hooks/useSmartFilters'

const ICON_MAP = {
  Star, HelpCircle, Tag, Unlock, ScanLine, WifiOff, Tags, MapPin,
  ShieldAlert, Ban, FileText,
}

export function SmartFilterBar({ devices, activeFilters, onToggle, onClear, savedViews, onSaveView, onLoadView, onDeleteView }) {
  const [saveMode,   setSaveMode]   = useState(false)
  const [viewName,   setViewName]   = useState('')

  function countFor(filter) {
    return devices.filter(filter.fn).length
  }

  function handleSave(e) {
    e.preventDefault()
    if (!viewName.trim()) return
    onSaveView(viewName)
    setViewName('')
    setSaveMode(false)
  }

  return (
    <div className="space-y-2">
      {/* Saved views row */}
      {savedViews?.length > 0 && (
        <div className="flex flex-wrap gap-1.5 items-center">
          <span className="text-[10px] uppercase tracking-wider font-semibold mr-1" style={{ color: 'var(--color-text-faint)' }}>
            Saved views
          </span>
          {savedViews.map(view => (
            <div key={view.id} className="flex items-center gap-0 rounded-full overflow-hidden"
              style={{ border: '1px solid var(--color-border)', background: 'var(--color-surface-offset)' }}>
              <button
                onClick={() => onLoadView(view.id)}
                className="flex items-center gap-1 pl-2.5 pr-2 py-1 text-xs hover:opacity-80 transition-opacity"
                style={{ color: 'var(--color-text-muted)' }}
              >
                <BookmarkCheck size={10} />
                {view.name}
              </button>
              <button
                onClick={() => onDeleteView(view.id)}
                className="px-1.5 py-1 opacity-40 hover:opacity-100 transition-opacity"
                style={{ color: 'var(--color-text-muted)', borderLeft: '1px solid var(--color-border)' }}
                aria-label={`Delete view "${view.name}"`}
              >
                <X size={10} />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Filter chips row */}
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

        {/* Save view button */}
        {activeFilters.length > 0 && onSaveView && !saveMode && (
          <button
            onClick={() => setSaveMode(true)}
            className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-full border transition-all"
            style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}
          >
            <Bookmark size={10} />
            Save view
          </button>
        )}

        {saveMode && (
          <form onSubmit={handleSave} className="flex items-center gap-1.5">
            <input
              autoFocus
              value={viewName}
              onChange={e => setViewName(e.target.value)}
              placeholder="View name…"
              className="input py-1 px-2 text-xs h-7 w-32"
            />
            <button type="submit" disabled={!viewName.trim()}
              className="text-xs px-2.5 py-1 rounded-full"
              style={{ background: 'var(--color-brand)', color: '#fff', opacity: viewName.trim() ? 1 : 0.4 }}>
              Save
            </button>
            <button type="button" onClick={() => { setSaveMode(false); setViewName('') }}
              className="text-xs px-2 py-1 rounded-full opacity-60 hover:opacity-100"
              style={{ color: 'var(--color-text-faint)' }}>
              Cancel
            </button>
          </form>
        )}
      </div>
    </div>
  )
}
