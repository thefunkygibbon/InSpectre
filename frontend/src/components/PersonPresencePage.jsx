import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import {
  UserPlus, User, Edit2, Trash2, X, Check,
  Smartphone, Plus, Shield, Camera, ShieldOff, ShieldCheck, ChevronDown,
  AlertTriangle, Star, Loader, ToggleRight, ToggleLeft, Home, MapPin,
} from 'lucide-react'
import { api } from '../api'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PERIODS = [
  { label: '7 days',  days: 7   },
  { label: '1 month', days: 30  },
  { label: '1 year',  days: 365 },
]

const SCHED_DAYS = [
  { key: 'mon', label: 'Mo' },
  { key: 'tue', label: 'Tu' },
  { key: 'wed', label: 'We' },
  { key: 'thu', label: 'Th' },
  { key: 'fri', label: 'Fr' },
  { key: 'sat', label: 'Sa' },
  { key: 'sun', label: 'Su' },
]

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function initials(name) {
  if (!name) return '?'
  return name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2)
}

function fmtDate(iso) {
  if (!iso) return ''
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

function fmtDateTime(iso) {
  if (!iso) return ''
  return new Date(iso).toLocaleString()
}

// ---------------------------------------------------------------------------
// Shared UI atoms
// ---------------------------------------------------------------------------

function Avatar({ photo, name, size = 48, className = '' }) {
  if (photo) {
    return (
      <img src={photo} alt={name}
        style={{ width: size, height: size }}
        className={`rounded-full object-cover flex-shrink-0 ${className}`} />
    )
  }
  return (
    <div style={{
      width: size, height: size,
      background: 'linear-gradient(135deg, var(--color-brand) 0%, var(--color-brand-light) 100%)',
      fontSize: size * 0.38,
    }}
      className={`rounded-full flex items-center justify-center font-bold text-black flex-shrink-0 select-none ${className}`}>
      {initials(name)}
    </div>
  )
}

function OnlineBadge({ online }) {
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold tracking-wide ${
      online
        ? 'bg-green-500/20 text-green-400 border border-green-500/40'
        : 'bg-slate-500/10 text-slate-400 border border-slate-500/25'
    }`}>
      {online
        ? <Home size={11} className="shrink-0" />
        : <MapPin size={11} className="shrink-0" />}
      {online ? 'At Home' : 'Away'}
    </span>
  )
}

function DeviceChip({ device, onRemove, isPrimary, onSetPrimary }) {
  return (
    <div className="flex items-center gap-1.5 px-2 py-1 rounded-lg border text-xs"
      style={{
        borderColor: device.is_online ? 'rgba(74,200,100,0.3)' : 'var(--color-border)',
        background: device.is_online ? 'rgba(74,200,100,0.06)' : 'var(--color-surface-offset)',
        color: 'var(--color-text)',
      }}>
      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${device.is_online ? 'bg-green-400' : 'bg-text-faint'}`} />
      <span className="truncate max-w-[120px]">{device.display_name}</span>
      {isPrimary && (
        <span className="text-[9px] font-bold text-brand uppercase tracking-wider ml-0.5">Primary</span>
      )}
      {onSetPrimary && !isPrimary && (
        <button onClick={() => onSetPrimary(device.mac_address)}
          title="Set as primary presence device"
          className="ml-0.5 opacity-50 hover:opacity-100 transition-opacity">
          <Star size={10} />
        </button>
      )}
      {onRemove && (
        <button onClick={() => onRemove(device.mac_address)}
          className="ml-0.5 opacity-50 hover:opacity-100 transition-opacity">
          <X size={10} />
        </button>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Device autocomplete
// ---------------------------------------------------------------------------

function DeviceAutocomplete({ allDevices, onSelect, placeholder = 'Search devices…', exclude = [] }) {
  const [query, setQuery] = useState('')
  const [open, setOpen]   = useState(false)
  const ref               = useRef(null)

  const filtered = allDevices.filter(d =>
    !exclude.includes(d.mac_address) &&
    (d.display_name || d.hostname || d.ip_address || '')
      .toLowerCase().includes(query.toLowerCase())
  ).slice(0, 8)

  useEffect(() => {
    function handle(e) { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handle)
    return () => document.removeEventListener('mousedown', handle)
  }, [])

  return (
    <div ref={ref} className="relative">
      <input type="text" value={query} placeholder={placeholder}
        onChange={e => { setQuery(e.target.value); setOpen(true) }}
        onFocus={() => setOpen(true)}
        className="w-full px-3 py-1.5 rounded-lg border text-xs"
        style={{ background: 'var(--color-surface-offset)', borderColor: 'var(--color-border)', color: 'var(--color-text)', outline: 'none' }} />
      {open && filtered.length > 0 && (
        <div className="absolute z-50 mt-1 w-full rounded-lg border shadow-xl overflow-hidden"
          style={{ background: 'var(--color-surface)', borderColor: 'var(--color-border)' }}>
          {filtered.map(d => (
            <button key={d.mac_address}
              className="w-full flex items-center gap-2 px-3 py-2 text-xs hover:bg-surface-hover transition-colors text-left"
              style={{ color: 'var(--color-text)' }}
              onMouseDown={() => { onSelect(d); setQuery(''); setOpen(false) }}>
              <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${d.is_online ? 'bg-green-400' : 'bg-text-faint'}`} />
              <span className="truncate font-medium">{d.display_name || d.hostname || d.ip_address}</span>
              <span className="ml-auto text-text-faint truncate">{d.ip_address}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Person autocomplete (exported for use in DeviceDrawer)
// ---------------------------------------------------------------------------

export function PersonAutocomplete({ persons, onSelect, placeholder = 'Search people…', currentPersonId }) {
  const [query, setQuery] = useState('')
  const [open, setOpen]   = useState(false)
  const ref               = useRef(null)

  const filtered = persons.filter(p =>
    p.id !== currentPersonId &&
    p.name.toLowerCase().includes(query.toLowerCase())
  ).slice(0, 6)

  useEffect(() => {
    function handle(e) { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handle)
    return () => document.removeEventListener('mousedown', handle)
  }, [])

  return (
    <div ref={ref} className="relative flex-1">
      <input type="text" value={query} placeholder={placeholder}
        onChange={e => { setQuery(e.target.value); setOpen(true) }}
        onFocus={() => setOpen(true)}
        className="w-full px-2 py-1 rounded border text-xs"
        style={{ background: 'var(--color-surface-offset)', borderColor: 'var(--color-border)', color: 'var(--color-text)', outline: 'none' }} />
      {open && filtered.length > 0 && (
        <div className="absolute z-50 mt-1 w-full rounded-lg border shadow-xl overflow-hidden"
          style={{ background: 'var(--color-surface)', borderColor: 'var(--color-border)' }}>
          {filtered.map(p => (
            <button key={p.id}
              className="w-full flex items-center gap-2 px-3 py-2 text-xs hover:bg-surface-hover transition-colors text-left"
              style={{ color: 'var(--color-text)' }}
              onMouseDown={() => { onSelect(p); setQuery(''); setOpen(false) }}>
              <Avatar name={p.name} photo={p.photo} size={20} />
              <span>{p.name}</span>
              <OnlineBadge online={p.is_home} />
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Timeline rendering (same approach as NetworkTimeline)
// ---------------------------------------------------------------------------

const HOME_COLORS = { online: '#10b981', offline: '#ef4444', unknown: '#374151' }

function XAxisLabels({ windowStart, windowEnd, days }) {
  const ticks = useMemo(() => {
    const start   = new Date(windowStart)
    const end     = new Date(windowEnd)
    const totalMs = end - start
    const count   = days <= 7 ? 7 : days <= 30 ? 6 : 12
    return Array.from({ length: count + 1 }, (_, i) => {
      const t = new Date(start.getTime() + (totalMs * i) / count)
      return { pct: (i / count) * 100, label: fmtDate(t.toISOString()) }
    })
  }, [windowStart, windowEnd, days])

  return (
    <div className="relative h-5 ml-[160px] mr-[70px] sm:ml-[200px]">
      {ticks.map((t, i) => (
        <span key={i}
          className="absolute text-[9px] transform -translate-x-1/2"
          style={{ left: `${t.pct}%`, color: 'var(--color-text-faint)' }}>
          {t.label}
        </span>
      ))}
    </div>
  )
}

function TimelineBar({ segments, label }) {
  if (!segments?.length) {
    return <div className="flex-1 h-6 rounded overflow-hidden" style={{ background: 'var(--color-surface-offset)' }} />
  }
  return (
    <div className="flex-1 h-6 rounded overflow-hidden relative" style={{ background: 'var(--color-surface-offset)' }}>
      {segments.map((seg, i) => (
        <div key={i}
          title={`${label}: ${seg.status === 'online' ? 'At Home' : seg.status === 'offline' ? 'Away' : 'Unknown'} · ${fmtDateTime(seg.from)} → ${fmtDateTime(seg.to)}`}
          className="absolute top-0 bottom-0 transition-opacity hover:opacity-80 cursor-default"
          style={{
            left: `${seg.leftPct}%`, width: `${seg.widthPct}%`, minWidth: '2px',
            background: HOME_COLORS[seg.status] || HOME_COLORS.unknown,
            opacity: seg.status === 'unknown' ? 0.3 : 0.85,
          }} />
      ))}
    </div>
  )
}

function PersonTimelineRow({ person }) {
  const { renderSegments, at_home_pct } = person
  const pct = at_home_pct ?? 0
  return (
    <div className="flex items-center gap-3 py-1.5">
      <div className="w-[160px] sm:w-[200px] flex items-center gap-2 shrink-0 min-w-0">
        <Avatar name={person.name} photo={person.photo} size={20} />
        <span className="text-xs truncate" style={{ color: 'var(--color-text)' }} title={person.name}>
          {person.name}
        </span>
      </div>
      <TimelineBar segments={renderSegments} label={person.name} />
      <div className="w-[60px] text-right shrink-0">
        <span className="text-[10px] font-mono tabular-nums"
          style={{ color: pct >= 75 ? '#10b981' : pct >= 40 ? '#f59e0b' : '#ef4444' }}>
          {pct}% home
        </span>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Person block schedule manager (inline per card)
// ---------------------------------------------------------------------------

function DaysToggle({ value, onChange }) {
  const selected = value.split(',').map(d => d.trim().toLowerCase()).filter(Boolean)
  function toggle(day) {
    const next = selected.includes(day)
      ? selected.filter(d => d !== day)
      : [...selected, day]
    onChange(SCHED_DAYS.map(d => d.key).filter(k => next.includes(k)).join(','))
  }
  return (
    <div className="flex gap-0.5 flex-wrap">
      {SCHED_DAYS.map(d => (
        <button key={d.key} type="button" onClick={() => toggle(d.key)}
          className="px-1.5 py-0.5 rounded text-[10px] font-medium transition-colors"
          style={selected.includes(d.key)
            ? { background: 'var(--color-brand)', color: 'black' }
            : { background: 'var(--color-surface-offset)', color: 'var(--color-text-muted)', border: '1px solid var(--color-border)' }}>
          {d.label}
        </button>
      ))}
    </div>
  )
}

function PersonScheduleManager({ person, onScheduleChanged }) {
  const [showForm, setShowForm] = useState(false)
  const [label,    setLabel]    = useState('')
  const [days,     setDays]     = useState('mon,tue,wed,thu,fri,sat,sun')
  const [start,    setStart]    = useState('22:00')
  const [end,      setEnd]      = useState('07:00')
  const [saving,   setSaving]   = useState(false)
  const [error,    setError]    = useState(null)
  const [deleting, setDeleting] = useState(null)

  async function handleAdd(e) {
    e.preventDefault()
    if (!days) { setError('Select at least one day'); return }
    setSaving(true); setError(null)
    try {
      await api.createBlockSchedule({
        person_id:    person.id,
        label:        label.trim() || null,
        days_of_week: days,
        start_time:   start,
        end_time:     end,
        mac_addresses: [],
        tags: '',
      })
      setShowForm(false); setLabel(''); setDays('mon,tue,wed,thu,fri,sat,sun'); setStart('22:00'); setEnd('07:00')
      onScheduleChanged()
    } catch (e) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  async function handleToggle(sched) {
    try {
      await api.updateBlockSchedule(sched.id, { enabled: !sched.enabled })
      onScheduleChanged()
    } catch {}
  }

  async function handleDelete(id) {
    setDeleting(id)
    try { await api.deleteBlockSchedule(id); onScheduleChanged() }
    catch {} finally { setDeleting(null) }
  }

  return (
    <div className="mt-3 pt-3 border-t" style={{ borderColor: 'var(--color-border)' }}>
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider"
          style={{ color: 'var(--color-text-faint)' }}>
          <Shield size={9} /> Block Schedules
        </div>
        {!showForm && (
          <button onClick={() => setShowForm(true)}
            className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded border transition-colors hover:bg-surface-hover"
            style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}>
            <Plus size={9} /> Add
          </button>
        )}
      </div>

      {/* Existing schedules */}
      {person.schedules.length > 0 && (
        <div className="space-y-1 mb-2">
          {person.schedules.map(s => {
            const dList = (s.days_of_week || '').split(',').map(d => d.trim())
            const allD  = dList.length === 7
            return (
              <div key={s.id}
                className="flex items-center gap-2 px-2 py-1 rounded-lg text-[10px]"
                style={{ background: 'var(--color-surface-offset)', border: '1px solid var(--color-border)' }}>
                <button onClick={() => handleToggle(s)} className="shrink-0 transition-colors"
                  title={s.enabled ? 'Disable' : 'Enable'}>
                  {s.enabled
                    ? <ToggleRight size={16} style={{ color: 'var(--color-brand)' }} />
                    : <ToggleLeft  size={16} style={{ color: 'var(--color-text-faint)' }} />}
                </button>
                <span className="flex-1 truncate" style={{ color: s.enabled ? 'var(--color-text)' : 'var(--color-text-faint)' }}>
                  {s.label || `${s.start_time}–${s.end_time}`}
                </span>
                <span style={{ color: 'var(--color-text-muted)' }}>
                  {allD ? 'Every day' : dList.map(d => d.slice(0, 2)).join(' ')}
                </span>
                <span className="font-mono" style={{ color: 'var(--color-text-muted)' }}>
                  {s.start_time}–{s.end_time}
                </span>
                <button onClick={() => handleDelete(s.id)} disabled={deleting === s.id}
                  className="opacity-50 hover:opacity-100 hover:text-red-400 transition-opacity">
                  {deleting === s.id ? <Loader size={10} className="animate-spin" /> : <X size={10} />}
                </button>
              </div>
            )
          })}
        </div>
      )}

      {/* Add form */}
      {showForm && (
        <form onSubmit={handleAdd} className="space-y-2 p-2 rounded-lg border"
          style={{ background: 'var(--color-surface-offset)', borderColor: 'var(--color-border)' }}>
          <input type="text" value={label} onChange={e => setLabel(e.target.value)}
            placeholder="Label (optional)"
            className="w-full px-2 py-1 rounded border text-xs"
            style={{ background: 'var(--color-surface)', borderColor: 'var(--color-border)', color: 'var(--color-text)', outline: 'none' }} />
          <DaysToggle value={days} onChange={setDays} />
          <div className="flex gap-2">
            <div className="flex-1">
              <label className="text-[10px] block mb-0.5" style={{ color: 'var(--color-text-muted)' }}>From</label>
              <input type="time" value={start} onChange={e => setStart(e.target.value)}
                className="w-full px-2 py-1 rounded border text-xs font-mono"
                style={{ background: 'var(--color-surface)', borderColor: 'var(--color-border)', color: 'var(--color-text)', outline: 'none' }} />
            </div>
            <div className="flex-1">
              <label className="text-[10px] block mb-0.5" style={{ color: 'var(--color-text-muted)' }}>Until</label>
              <input type="time" value={end} onChange={e => setEnd(e.target.value)}
                className="w-full px-2 py-1 rounded border text-xs font-mono"
                style={{ background: 'var(--color-surface)', borderColor: 'var(--color-border)', color: 'var(--color-text)', outline: 'none' }} />
            </div>
          </div>
          {error && <p className="text-[10px] text-red-400">{error}</p>}
          <div className="flex gap-1.5">
            <button type="submit" disabled={saving}
              className="flex items-center gap-1 px-3 py-1 rounded text-[10px] font-semibold disabled:opacity-50"
              style={{ background: 'var(--color-brand)', color: 'black' }}>
              {saving && <Loader size={9} className="animate-spin" />}
              Save
            </button>
            <button type="button" onClick={() => { setShowForm(false); setError(null) }}
              className="px-3 py-1 rounded text-[10px] border"
              style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}>
              Cancel
            </button>
          </div>
        </form>
      )}

      {person.schedules.length === 0 && !showForm && (
        <p className="text-[10px] italic" style={{ color: 'var(--color-text-faint)' }}>
          No block schedules. Click Add to create one.
        </p>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Person form (add / edit)
// ---------------------------------------------------------------------------

function PersonForm({ person, allDevices, onSave, onCancel, onDelete }) {
  const isNew = !person
  const [name,       setName]       = useState(person?.name       || '')
  const [notes,      setNotes]      = useState(person?.notes      || '')
  const [photo,      setPhoto]      = useState(person?.photo      || null)
  const [primaryMac, setPrimaryMac] = useState(person?.primary_mac || null)
  const [devices,    setDevices]    = useState(person?.devices     || [])
  const [saving,     setSaving]     = useState(false)
  const [error,      setError]      = useState(null)
  const [confirmDel, setConfirmDel] = useState(false)
  const fileRef = useRef(null)

  function handlePhotoChange(e) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = ev => setPhoto(ev.target.result)
    reader.readAsDataURL(file)
  }

  function handleAddDevice(device) {
    if (devices.find(d => d.mac_address === device.mac_address)) return
    setDevices(prev => [...prev, device])
    if (!primaryMac) setPrimaryMac(device.mac_address)
  }

  function handleRemoveDevice(mac) {
    setDevices(prev => prev.filter(d => d.mac_address !== mac))
    if (primaryMac === mac) setPrimaryMac(devices.find(d => d.mac_address !== mac)?.mac_address || null)
  }

  async function handleSave() {
    if (!name.trim()) { setError('Name is required'); return }
    setSaving(true); setError(null)
    try {
      await onSave({ name, notes, photo, primary_mac: primaryMac, devices, existingPerson: person })
    } catch (e) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="rounded-xl border p-5 space-y-4"
      style={{ borderColor: 'var(--color-border)', background: 'var(--color-surface)' }}>
      <div className="flex items-center justify-between">
        <span className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>
          {isNew ? 'Add Person' : 'Edit Person'}
        </span>
        <button onClick={onCancel} className="p-1 rounded hover:bg-surface-hover transition-colors">
          <X size={14} style={{ color: 'var(--color-text-muted)' }} />
        </button>
      </div>

      {/* Photo + Name */}
      <div className="flex items-center gap-4">
        <div className="relative flex-shrink-0">
          <Avatar name={name || '?'} photo={photo} size={64} />
          <button onClick={() => fileRef.current?.click()}
            className="absolute -bottom-1 -right-1 w-6 h-6 rounded-full flex items-center justify-center"
            style={{ background: 'var(--color-brand)', color: 'black' }}
            title="Upload photo">
            <Camera size={10} />
          </button>
          <input ref={fileRef} type="file" accept="image/*" className="hidden" onChange={handlePhotoChange} />
        </div>
        <div className="flex-1 space-y-2">
          <input type="text" value={name} onChange={e => setName(e.target.value)}
            placeholder="Person's name"
            className="w-full px-3 py-1.5 rounded-lg border text-sm font-medium"
            style={{ background: 'var(--color-surface-offset)', borderColor: 'var(--color-border)', color: 'var(--color-text)', outline: 'none' }} />
          {photo && (
            <button onClick={() => setPhoto(null)}
              className="text-[10px] text-text-muted hover:text-text transition-colors">
              Remove photo
            </button>
          )}
        </div>
      </div>

      {/* Devices */}
      <div className="space-y-2">
        <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--color-text-muted)' }}>
          Devices
        </label>
        {devices.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {devices.map(d => (
              <DeviceChip key={d.mac_address} device={d}
                isPrimary={d.mac_address === primaryMac}
                onSetPrimary={mac => setPrimaryMac(mac)}
                onRemove={handleRemoveDevice} />
            ))}
          </div>
        )}
        <DeviceAutocomplete allDevices={allDevices} onSelect={handleAddDevice}
          exclude={devices.map(d => d.mac_address)} placeholder="Add device…" />
        {primaryMac && (
          <p className="text-[10px]" style={{ color: 'var(--color-text-faint)' }}>
            ★ = primary presence device. Click the star on any device to set it.
          </p>
        )}
      </div>

      {/* Notes */}
      <div className="space-y-1">
        <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--color-text-muted)' }}>
          Notes
        </label>
        <textarea value={notes} onChange={e => setNotes(e.target.value)}
          rows={2} placeholder="Optional notes…"
          className="w-full px-3 py-1.5 rounded-lg border text-xs resize-none"
          style={{ background: 'var(--color-surface-offset)', borderColor: 'var(--color-border)', color: 'var(--color-text)', outline: 'none' }} />
      </div>

      {error && (
        <div className="flex items-center gap-2 text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
          <AlertTriangle size={12} /> {error}
        </div>
      )}

      <div className="flex items-center gap-2">
        <button onClick={handleSave} disabled={saving}
          className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-medium transition-colors"
          style={{ background: 'var(--color-brand)', color: 'black', opacity: saving ? 0.6 : 1 }}>
          <Check size={12} />
          {saving ? 'Saving…' : 'Save'}
        </button>
        <button onClick={onCancel}
          className="px-4 py-1.5 rounded-lg border text-xs font-medium transition-colors hover:bg-surface-hover"
          style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}>
          Cancel
        </button>
        {!isNew && onDelete && (
          <div className="ml-auto">
            {confirmDel
              ? (
                <span className="flex items-center gap-1">
                  <span className="text-xs text-red-400 mr-1">Confirm?</span>
                  <button onClick={() => onDelete(person.id)}
                    className="px-2 py-1 rounded text-xs bg-red-500/20 text-red-400 border border-red-500/30">
                    Yes
                  </button>
                  <button onClick={() => setConfirmDel(false)}
                    className="px-2 py-1 rounded text-xs border text-text-muted"
                    style={{ borderColor: 'var(--color-border)' }}>
                    No
                  </button>
                </span>
              )
              : (
                <button onClick={() => setConfirmDel(true)}
                  className="flex items-center gap-1 px-3 py-1.5 rounded-lg border text-xs text-red-400 border-red-500/30 hover:bg-red-500/10 transition-colors">
                  <Trash2 size={11} /> Delete
                </button>
              )
            }
          </div>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Person card
// ---------------------------------------------------------------------------

const BLOCK_DURATIONS = [
  { label: 'Until unblocked', value: null },
  { label: '30 minutes',      value: 30  },
  { label: '1 hour',          value: 60  },
  { label: '6 hours',         value: 360 },
  { label: '24 hours',        value: 1440 },
]

function BlockButton({ person, onUpdated }) {
  const [open,     setOpen]     = useState(false)
  const [working,  setWorking]  = useState(false)
  const ref = useRef(null)

  const isBlocked = person.is_blocked
  const hasTimer  = person.has_timed_block

  useEffect(() => {
    function handle(e) { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handle)
    return () => document.removeEventListener('mousedown', handle)
  }, [])

  async function doUnblock() {
    setWorking(true)
    try { await api.unblockPerson(person.id); onUpdated() }
    catch {} finally { setWorking(false) }
  }

  async function doBlock(duration_minutes) {
    setOpen(false); setWorking(true)
    try { await api.blockPerson(person.id, { duration_minutes }); onUpdated() }
    catch {} finally { setWorking(false) }
  }

  if (isBlocked) {
    return (
      <button onClick={doUnblock} disabled={working}
        title="Unblock all this person's devices"
        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border border-red-500/40 bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors disabled:opacity-50">
        {working ? <Loader size={11} className="animate-spin" /> : <ShieldCheck size={11} />}
        {hasTimer ? 'Timed block' : 'Blocked'}
        {!working && ' · Unblock'}
      </button>
    )
  }

  return (
    <div ref={ref} className="relative">
      <button onClick={() => setOpen(v => !v)} disabled={working || person.devices.length === 0}
        title={person.devices.length === 0 ? 'No devices assigned' : 'Block all this person\'s devices'}
        className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors disabled:opacity-40"
        style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}>
        {working ? <Loader size={11} className="animate-spin" /> : <ShieldOff size={11} />}
        Block
        <ChevronDown size={9} />
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-1 z-50 rounded-lg border shadow-xl overflow-hidden w-40"
          style={{ background: 'var(--color-surface)', borderColor: 'var(--color-border)' }}>
          {BLOCK_DURATIONS.map(opt => (
            <button key={String(opt.value)} onMouseDown={() => doBlock(opt.value)}
              className="w-full px-3 py-2 text-xs text-left hover:bg-surface-hover transition-colors"
              style={{ color: 'var(--color-text)' }}>
              {opt.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

function PersonCard({ person, allDevices, onUpdated, onDeleted }) {
  const [editing, setEditing] = useState(false)

  async function handleSave({ name, notes, photo, primary_mac, devices, existingPerson }) {
    await api.updatePerson(existingPerson.id, { name, notes, photo, primary_mac })
    const currentMacs = existingPerson.devices.map(d => d.mac_address)
    const newMacs     = devices.map(d => d.mac_address)
    for (const mac of currentMacs) {
      if (!newMacs.includes(mac)) await api.removePersonDevice(existingPerson.id, mac)
    }
    for (const mac of newMacs) {
      if (!currentMacs.includes(mac)) {
        await api.addPersonDevice(existingPerson.id, { mac_address: mac, set_primary: mac === primary_mac })
      }
    }
    if (primary_mac && primary_mac !== existingPerson.primary_mac) {
      await api.updatePerson(existingPerson.id, { primary_mac })
    }
    setEditing(false)
    onUpdated()
  }

  if (editing) {
    return (
      <PersonForm person={person} allDevices={allDevices}
        onSave={handleSave}
        onCancel={() => setEditing(false)}
        onDelete={async id => { await api.deletePerson(id); onDeleted() }} />
    )
  }

  return (
    <div className="rounded-xl border overflow-hidden"
      style={{
        borderColor: person.is_blocked
          ? 'rgba(239,68,68,0.4)'
          : person.is_home
            ? 'rgba(74,222,128,0.35)'
            : 'var(--color-border)',
        background: person.is_blocked
          ? 'rgba(239,68,68,0.04)'
          : person.is_home
            ? 'rgba(74,222,128,0.04)'
            : 'var(--color-surface)',
      }}>
      {/* Colour accent bar at top of card */}
      <div className="h-1.5 w-full" style={{
        background: person.is_blocked
          ? 'linear-gradient(90deg, rgba(239,68,68,0.8), rgba(239,68,68,0.3))'
          : person.is_home
            ? 'linear-gradient(90deg, rgba(74,222,128,0.8), rgba(74,222,128,0.3))'
            : 'linear-gradient(90deg, rgba(148,163,184,0.35), rgba(148,163,184,0.1))',
      }} />
      <div className="p-4">
        {/* Header row — avatar + name/notes only; edit button pinned top-right */}
        <div className="flex items-start gap-3">
          <div className="relative flex-shrink-0">
            <Avatar name={person.name} photo={person.photo} size={52} />
            <span className={`absolute -bottom-0.5 -right-0.5 w-3.5 h-3.5 rounded-full border-2 border-surface ${person.is_home ? 'bg-green-400' : 'bg-text-faint'}`} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-semibold text-sm" style={{ color: 'var(--color-text)' }}>{person.name}</span>
              <OnlineBadge online={person.is_home} />
            </div>
            {person.notes && (
              <p className="text-xs mt-0.5 truncate" style={{ color: 'var(--color-text-muted)' }}>{person.notes}</p>
            )}
            {person.primary_mac && (() => {
              const pDev = person.devices.find(d => d.mac_address === person.primary_mac)
              return pDev ? (
                <div className="flex items-center gap-1 mt-1">
                  <Smartphone size={10} style={{ color: 'var(--color-text-faint)' }} />
                  <span className="text-[10px]" style={{ color: 'var(--color-text-faint)' }}>{pDev.display_name}</span>
                </div>
              ) : null
            })()}
          </div>
          <button onClick={() => setEditing(true)}
            className="p-1.5 rounded-lg hover:bg-surface-hover transition-colors flex-shrink-0"
            title="Edit person">
            <Edit2 size={13} style={{ color: 'var(--color-text-muted)' }} />
          </button>
        </div>

        {/* Devices */}
        {person.devices.length > 0 && (
          <div className="mt-3 flex flex-wrap gap-1.5">
            {person.devices.map(d => (
              <DeviceChip key={d.mac_address} device={d} isPrimary={d.mac_address === person.primary_mac} />
            ))}
          </div>
        )}

        {person.devices.length === 0 && (
          <p className="mt-3 text-xs italic" style={{ color: 'var(--color-text-faint)' }}>
            No devices assigned. Click edit to add devices.
          </p>
        )}

        {/* Block button — own row to prevent overlap with name/info */}
        <div className="mt-2 flex justify-end">
          <BlockButton person={person} onUpdated={onUpdated} />
        </div>

        {/* Block schedule manager */}
        <PersonScheduleManager person={person} onScheduleChanged={onUpdated} />
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export function PersonPresencePage({ devices }) {
  const [persons,         setPersons]         = useState([])
  const [loading,         setLoading]         = useState(true)
  const [error,           setError]           = useState(null)
  const [showForm,        setShowForm]        = useState(false)
  const [days,            setDays]            = useState(7)
  const [timelineData,    setTimelineData]    = useState(null)
  const [timelineLoading, setTimelineLoading] = useState(false)

  const allDevices = (devices || []).map(d => ({
    ...d,
    display_name: d.custom_name || d.hostname || d.ip_address,
  }))

  const loadTimeline = useCallback(async (d) => {
    setTimelineLoading(true)
    try {
      const data = await api.getPersonsTimeline(d)
      setTimelineData(data)
    } catch {}
    finally { setTimelineLoading(false) }
  }, [])

  const load = useCallback(async () => {
    try {
      const data = await api.getPersons()
      setPersons(data)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])
  useEffect(() => { if (!loading) loadTimeline(days) }, [days, loading, loadTimeline])

  // Smart refresh: poll every 30s but skip if the user has an input focused
  useEffect(() => {
    function doRefresh() {
      const el = document.activeElement
      const busy = el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT')
      if (!busy) { load(); loadTimeline(days) }
    }
    // Also refresh when the tab regains focus
    function onVisible() { if (document.visibilityState === 'visible') doRefresh() }
    document.addEventListener('visibilitychange', onVisible)
    const id = setInterval(doRefresh, 30000)
    return () => { clearInterval(id); document.removeEventListener('visibilitychange', onVisible) }
  }, [load, loadTimeline, days])

  async function handleCreate({ name, notes, photo, primary_mac, devices: devs }) {
    const person = await api.createPerson({ name, notes, photo, primary_mac })
    for (const d of devs) {
      await api.addPersonDevice(person.id, { mac_address: d.mac_address, set_primary: d.mac_address === primary_mac })
    }
    setShowForm(false)
    load()
    loadTimeline(days)
  }

  // Prepare timeline render segments
  const preparedTimeline = useMemo(() => {
    if (!timelineData?.persons?.length) return []
    const winStart = new Date(timelineData.window_start).getTime()
    const winEnd   = new Date(timelineData.window_end).getTime()
    const totalMs  = winEnd - winStart
    if (totalMs <= 0) return timelineData.persons.map(p => ({ ...p, renderSegments: [], at_home_pct: 0 }))
    return timelineData.persons.map(p => {
      const renderSegments = (p.segments || []).map(seg => {
        const s = Math.max(new Date(seg.from).getTime(), winStart)
        const e = Math.min(new Date(seg.to).getTime(), winEnd)
        if (e <= s) return null
        return {
          status: seg.status,
          from:   seg.from,
          to:     seg.to,
          leftPct:  ((s - winStart) / totalMs) * 100,
          widthPct: ((e - s)        / totalMs) * 100,
        }
      }).filter(Boolean)
      return { ...p, renderSegments }
    })
  }, [timelineData])

  const homeCount = persons.filter(p => p.is_home).length

  return (
    <div className="p-6 max-w-5xl mx-auto">

      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold" style={{ color: 'var(--color-text)' }}>Person Presence</h1>
          <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-muted)' }}>
            Track who is home based on their devices
            {!loading && persons.length > 0 && (
              <span className="ml-2">
                — <span style={{ color: 'var(--color-brand)' }}>{homeCount}</span>
                <span> / {persons.length} at home</span>
              </span>
            )}
          </p>
        </div>
        <button onClick={() => setShowForm(v => !v)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors"
          style={{ background: 'var(--color-brand)', color: 'black' }}>
          <UserPlus size={15} />
          Add Person
        </button>
      </div>

      {/* Add form */}
      {showForm && (
        <div className="mb-6">
          <PersonForm allDevices={allDevices} onSave={handleCreate} onCancel={() => setShowForm(false)} />
        </div>
      )}

      {/* Loading / error */}
      {loading && (
        <div className="flex items-center justify-center py-12">
          <Loader size={24} className="animate-spin" style={{ color: 'var(--color-text-faint)' }} />
        </div>
      )}
      {error && (
        <div className="flex items-center gap-2 text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-xl px-4 py-3 mb-6">
          <AlertTriangle size={14} /> {error}
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && persons.length === 0 && !showForm && (
        <div className="text-center py-16 space-y-3">
          <User size={40} style={{ color: 'var(--color-text-faint)', margin: '0 auto' }} />
          <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>No people configured yet</p>
          <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
            Add a person and assign their devices to track who is home.
          </p>
        </div>
      )}

      {/* People cards */}
      {!loading && persons.length > 0 && (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3 mb-8">
          {persons.map(person => (
            <PersonCard key={person.id} person={person} allDevices={allDevices}
              onUpdated={() => { load(); loadTimeline(days) }}
              onDeleted={() => { load(); loadTimeline(days) }} />
          ))}
        </div>
      )}

      {/* Presence Timeline section */}
      {!loading && persons.length > 0 && (
        <div className="rounded-xl border overflow-hidden"
          style={{ borderColor: 'var(--color-border)', background: 'var(--color-surface)' }}>
          <div className="px-5 py-3 border-b flex items-center justify-between"
            style={{ borderColor: 'var(--color-border)', background: 'var(--color-surface-offset)' }}>
            <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--color-text-muted)' }}>
              Presence History
            </span>
            {/* Period picker */}
            <div className="flex items-center gap-1 rounded-lg p-0.5"
              style={{ background: 'var(--color-surface)' }}>
              {PERIODS.map(p => (
                <button key={p.days} onClick={() => setDays(p.days)}
                  className="px-2.5 py-1 rounded text-xs font-medium transition-all"
                  style={days === p.days
                    ? { background: 'var(--color-brand)', color: 'black' }
                    : { color: 'var(--color-text-muted)' }}>
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          {/* Legend */}
          <div className="flex items-center gap-4 px-5 pt-3 pb-1 text-xs" style={{ color: 'var(--color-text-muted)' }}>
            <span className="flex items-center gap-1.5">
              <span className="w-3 h-3 rounded-sm inline-block" style={{ background: '#10b981', opacity: 0.85 }} />
              At Home
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-3 h-3 rounded-sm inline-block" style={{ background: '#ef4444', opacity: 0.85 }} />
              Away
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-3 h-3 rounded-sm inline-block" style={{ background: '#374151', opacity: 0.3 }} />
              Unknown
            </span>
          </div>

          {timelineLoading ? (
            <div className="flex items-center justify-center py-10">
              <Loader size={20} className="animate-spin" style={{ color: 'var(--color-text-faint)' }} />
            </div>
          ) : preparedTimeline.length === 0 ? (
            <p className="text-xs italic px-5 py-6" style={{ color: 'var(--color-text-faint)' }}>
              No timeline data yet. Events will appear once devices have been active.
            </p>
          ) : (
            <div className="px-5 pb-4">
              <div className="pt-1 pb-2">
                <XAxisLabels
                  windowStart={timelineData.window_start}
                  windowEnd={timelineData.window_end}
                  days={days} />
              </div>
              <div className="divide-y" style={{ borderColor: 'var(--color-border)' }}>
                {preparedTimeline.map(p => (
                  <PersonTimelineRow key={p.id} person={p} />
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
