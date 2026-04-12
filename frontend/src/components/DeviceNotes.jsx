import { useState, useEffect } from 'react'
import { Save, MapPin, Tag, X, Plus } from 'lucide-react'
import { api } from '../api'

/**
 * DeviceNotes — Phase 1
 * Editable notes, tags, and location for a device.
 * Calls onSaved(updatedDevice) when the backend confirms.
 */
export function DeviceNotes({ device, onSaved }) {
  const [notes,    setNotes]    = useState(device.notes    || '')
  const [location, setLocation] = useState(device.location || '')
  const [tagInput, setTagInput] = useState('')
  const [tags,     setTags]     = useState(
    device.tags ? device.tags.split(',').map(t => t.trim()).filter(Boolean) : []
  )
  const [saving,   setSaving]   = useState(false)
  const [saved,    setSaved]    = useState(false)
  const [error,    setError]    = useState(null)

  // Sync if device prop changes (e.g. refresh)
  useEffect(() => {
    setNotes(device.notes || '')
    setLocation(device.location || '')
    setTags(device.tags ? device.tags.split(',').map(t => t.trim()).filter(Boolean) : [])
  }, [device.mac_address])

  function addTag(e) {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault()
      const t = tagInput.trim().replace(/,/g, '')
      if (t && !tags.includes(t)) setTags(prev => [...prev, t])
      setTagInput('')
    }
  }

  function removeTag(tag) {
    setTags(prev => prev.filter(t => t !== tag))
  }

  async function handleSave(e) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    setSaved(false)
    try {
      const updated = await api.updateMetadata(device.mac_address, {
        notes:    notes.trim() || null,
        tags:     tags.join(',') || null,
        location: location.trim() || null,
      })
      setSaved(true)
      setTimeout(() => setSaved(false), 2500)
      if (onSaved) onSaved(updated)
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <form onSubmit={handleSave} className="space-y-4">

      {/* Notes */}
      <div>
        <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--color-text-muted)' }}>
          Notes
        </label>
        <textarea
          className="input w-full resize-none"
          rows={3}
          value={notes}
          onChange={e => setNotes(e.target.value)}
          placeholder="Add notes about this device\u2026"
          style={{ fontFamily: 'inherit', fontSize: 'var(--text-sm)' }}
        />
      </div>

      {/* Location */}
      <div>
        <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--color-text-muted)' }}>
          <span className="flex items-center gap-1.5">
            <MapPin size={11} />
            Location / Room
          </span>
        </label>
        <input
          className="input w-full"
          value={location}
          onChange={e => setLocation(e.target.value)}
          placeholder="e.g. Living room, Server rack, Office"
        />
      </div>

      {/* Tags */}
      <div>
        <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--color-text-muted)' }}>
          <span className="flex items-center gap-1.5">
            <Tag size={11} />
            Tags
          </span>
        </label>
        <div
          className="flex flex-wrap gap-1.5 p-2 rounded-lg border min-h-[38px]"
          style={{ borderColor: 'var(--color-border)', background: 'var(--color-surface-offset)' }}
        >
          {tags.map(tag => (
            <span
              key={tag}
              className="flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium"
              style={{ background: 'var(--color-brand)', color: '#fff' }}
            >
              {tag}
              <button
                type="button"
                onClick={() => removeTag(tag)}
                aria-label={`Remove tag ${tag}`}
                className="hover:opacity-70 transition-opacity"
              >
                <X size={10} />
              </button>
            </span>
          ))}
          <input
            className="flex-1 min-w-[80px] text-xs bg-transparent outline-none"
            value={tagInput}
            onChange={e => setTagInput(e.target.value)}
            onKeyDown={addTag}
            placeholder={tags.length === 0 ? 'Type a tag, press Enter\u2026' : 'Add another\u2026'}
            style={{ color: 'var(--color-text)' }}
          />
        </div>
        <p className="text-[10px] mt-1" style={{ color: 'var(--color-text-faint)' }}>Press Enter or comma to add a tag</p>
      </div>

      {error && <p className="text-xs text-red-400">{error}</p>}

      <button
        type="submit"
        disabled={saving}
        className="btn-primary flex items-center gap-1.5"
      >
        {saved ? (
          <><span>\u2713</span> Saved!</>
        ) : saving ? (
          'Saving\u2026'
        ) : (
          <><Save size={13} /> Save notes</>  
        )}
      </button>
    </form>
  )
}
