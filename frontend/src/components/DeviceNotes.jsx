import { useState, useEffect } from 'react'
import { Save, Tag, MapPin, FileText } from 'lucide-react'
import { api } from '../api'

export function DeviceNotes({ device, onSaved }) {
  const [notes,    setNotes]    = useState(device.notes    || '')
  const [tags,     setTags]     = useState(device.tags     || '')
  const [location, setLocation] = useState(device.location || '')
  const [saving,   setSaving]   = useState(false)
  const [saved,    setSaved]    = useState(false)

  // Sync if device prop changes (e.g. after another tab saves)
  useEffect(() => {
    setNotes(device.notes    || '')
    setTags(device.tags      || '')
    setLocation(device.location || '')
  }, [device.mac_address])

  async function handleSave() {
    setSaving(true)
    setSaved(false)
    try {
      const updated = await api.updateMetadata(device.mac_address, {
        notes:    notes.trim()    || null,
        tags:     tags.trim()     || null,
        location: location.trim() || null,
      })
      onSaved?.(updated)
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (e) {
      console.error('Save failed', e)
    } finally {
      setSaving(false)
    }
  }

  const dirty =
    notes    !== (device.notes    || '') ||
    tags     !== (device.tags     || '') ||
    location !== (device.location || '')

  return (
    <div className="space-y-4">
      {/* Location */}
      <div className="space-y-1">
        <label className="flex items-center gap-1.5 text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>
          <MapPin size={12} /> Location / Room
        </label>
        <input
          type="text"
          value={location}
          onChange={e => setLocation(e.target.value)}
          placeholder="e.g. Living room, Loft, Rack"
          className="w-full px-3 py-2 rounded-lg text-sm border"
          style={{
            background: 'var(--color-surface-offset)',
            border: '1px solid var(--color-border)',
            color: 'var(--color-text)',
          }}
        />
      </div>

      {/* Tags */}
      <div className="space-y-1">
        <label className="flex items-center gap-1.5 text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>
          <Tag size={12} /> Tags
          <span className="font-normal" style={{ color: 'var(--color-text-faint)' }}>(comma-separated)</span>
        </label>
        <input
          type="text"
          value={tags}
          onChange={e => setTags(e.target.value)}
          placeholder="e.g. iot, trusted, media"
          className="w-full px-3 py-2 rounded-lg text-sm border"
          style={{
            background: 'var(--color-surface-offset)',
            border: '1px solid var(--color-border)',
            color: 'var(--color-text)',
          }}
        />
        {/* Tag chips preview */}
        {tags.trim() && (
          <div className="flex flex-wrap gap-1 pt-1">
            {tags.split(',').map(t => t.trim()).filter(Boolean).map(t => (
              <span
                key={t}
                className="px-2 py-0.5 rounded-full text-[11px]"
                style={{ background: 'var(--color-primary-highlight)', color: 'var(--color-primary)' }}
              >
                {t}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Notes */}
      <div className="space-y-1">
        <label className="flex items-center gap-1.5 text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>
          <FileText size={12} /> Notes
        </label>
        <textarea
          value={notes}
          onChange={e => setNotes(e.target.value)}
          placeholder="Free-form notes about this device…"
          rows={4}
          className="w-full px-3 py-2 rounded-lg text-sm border resize-none"
          style={{
            background: 'var(--color-surface-offset)',
            border: '1px solid var(--color-border)',
            color: 'var(--color-text)',
          }}
        />
      </div>

      <button
        onClick={handleSave}
        disabled={saving || !dirty}
        className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all"
        style={{
          background: (saving || !dirty) ? 'var(--color-surface-dynamic)' : 'var(--color-primary)',
          color:      (saving || !dirty) ? 'var(--color-text-faint)' : '#fff',
          cursor:     (saving || !dirty) ? 'default' : 'pointer',
        }}
      >
        <Save size={14} />
        {saving ? 'Saving…' : saved ? 'Saved!' : 'Save changes'}
      </button>
    </div>
  )
}
