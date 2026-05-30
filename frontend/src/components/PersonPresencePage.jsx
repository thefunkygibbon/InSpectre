import { useState, useEffect, useRef, useCallback } from 'react'
import {
  UserPlus, User, Home, MapPin, Edit2, Trash2, X, Check,
  Smartphone, Wifi, WifiOff, Plus, Shield, Clock, Camera,
  ChevronDown, ChevronUp, AlertTriangle, Star,
} from 'lucide-react'
import { api } from '../api'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function initials(name) {
  if (!name) return '?'
  return name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2)
}

function Avatar({ photo, name, size = 48, className = '' }) {
  if (photo) {
    return (
      <img
        src={photo}
        alt={name}
        style={{ width: size, height: size }}
        className={`rounded-full object-cover flex-shrink-0 ${className}`}
      />
    )
  }
  return (
    <div
      style={{
        width: size, height: size,
        background: 'linear-gradient(135deg, var(--color-brand) 0%, var(--color-brand-light) 100%)',
        fontSize: size * 0.38,
      }}
      className={`rounded-full flex items-center justify-center font-bold text-black flex-shrink-0 select-none ${className}`}
    >
      {initials(name)}
    </div>
  )
}

function OnlineBadge({ online }) {
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold ${
        online
          ? 'bg-green-500/15 text-green-400 border border-green-500/30'
          : 'bg-surface-offset text-text-muted border border-border'
      }`}
    >
      <span className={`inline-block w-1.5 h-1.5 rounded-full ${online ? 'bg-green-400 animate-pulse' : 'bg-text-muted'}`} />
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
        <button
          onClick={() => onSetPrimary(device.mac_address)}
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
      <input
        type="text"
        value={query}
        placeholder={placeholder}
        onChange={e => { setQuery(e.target.value); setOpen(true) }}
        onFocus={() => setOpen(true)}
        className="w-full px-3 py-1.5 rounded-lg border text-xs"
        style={{
          background: 'var(--color-surface-offset)',
          borderColor: 'var(--color-border)',
          color: 'var(--color-text)',
          outline: 'none',
        }}
      />
      {open && filtered.length > 0 && (
        <div className="absolute z-50 mt-1 w-full rounded-lg border shadow-xl overflow-hidden"
          style={{ background: 'var(--color-surface)', borderColor: 'var(--color-border)' }}>
          {filtered.map(d => (
            <button
              key={d.mac_address}
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

// Person autocomplete (for DeviceDrawer usage, exported)
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
      <input
        type="text"
        value={query}
        placeholder={placeholder}
        onChange={e => { setQuery(e.target.value); setOpen(true) }}
        onFocus={() => setOpen(true)}
        className="w-full px-2 py-1 rounded border text-xs"
        style={{
          background: 'var(--color-surface-offset)',
          borderColor: 'var(--color-border)',
          color: 'var(--color-text)',
          outline: 'none',
        }}
      />
      {open && filtered.length > 0 && (
        <div className="absolute z-50 mt-1 w-full rounded-lg border shadow-xl overflow-hidden"
          style={{ background: 'var(--color-surface)', borderColor: 'var(--color-border)' }}>
          {filtered.map(p => (
            <button
              key={p.id}
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
// Schedule chips
// ---------------------------------------------------------------------------

function ScheduleChip({ schedule }) {
  const days = (schedule.days_of_week || '').split(',').map(d => d.trim().slice(0, 2)).join(' ')
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[10px]"
      style={{
        borderColor: schedule.enabled ? 'var(--color-brand)' : 'var(--color-border)',
        color: schedule.enabled ? 'var(--color-brand)' : 'var(--color-text-muted)',
        background: schedule.enabled ? 'rgba(var(--color-brand-rgb,0,255,65),0.07)' : 'var(--color-surface-offset)',
      }}>
      <Clock size={9} />
      {schedule.label || `${schedule.start_time}–${schedule.end_time}`}
      {days && <span className="opacity-70">{days}</span>}
    </span>
  )
}

// ---------------------------------------------------------------------------
// Add/Edit person panel
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

  const existingMacs = (person?.devices || []).map(d => d.mac_address)
  const allExclude   = devices.map(d => d.mac_address)

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

      {/* Photo + Name row */}
      <div className="flex items-center gap-4">
        <div className="relative flex-shrink-0">
          <Avatar name={name || '?'} photo={photo} size={64} />
          <button
            onClick={() => fileRef.current?.click()}
            className="absolute -bottom-1 -right-1 w-6 h-6 rounded-full flex items-center justify-center"
            style={{ background: 'var(--color-brand)', color: 'black' }}
            title="Upload photo">
            <Camera size={10} />
          </button>
          <input ref={fileRef} type="file" accept="image/*" className="hidden" onChange={handlePhotoChange} />
        </div>
        <div className="flex-1 space-y-2">
          <input
            type="text"
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="Person's name"
            className="w-full px-3 py-1.5 rounded-lg border text-sm font-medium"
            style={{
              background: 'var(--color-surface-offset)',
              borderColor: 'var(--color-border)',
              color: 'var(--color-text)',
              outline: 'none',
            }}
          />
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
              <DeviceChip
                key={d.mac_address}
                device={d}
                isPrimary={d.mac_address === primaryMac}
                onSetPrimary={mac => setPrimaryMac(mac)}
                onRemove={handleRemoveDevice}
              />
            ))}
          </div>
        )}
        <DeviceAutocomplete
          allDevices={allDevices}
          onSelect={handleAddDevice}
          exclude={allExclude}
          placeholder="Add device…"
        />
        {primaryMac && (
          <p className="text-[10px]" style={{ color: 'var(--color-text-faint)' }}>
            ★ = primary presence device (used to determine "At Home" status). Click the star on any device to set it.
          </p>
        )}
      </div>

      {/* Notes */}
      <div className="space-y-1">
        <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--color-text-muted)' }}>
          Notes
        </label>
        <textarea
          value={notes}
          onChange={e => setNotes(e.target.value)}
          rows={2}
          placeholder="Optional notes…"
          className="w-full px-3 py-1.5 rounded-lg border text-xs resize-none"
          style={{
            background: 'var(--color-surface-offset)',
            borderColor: 'var(--color-border)',
            color: 'var(--color-text)',
            outline: 'none',
          }}
        />
      </div>

      {error && (
        <div className="flex items-center gap-2 text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
          <AlertTriangle size={12} /> {error}
        </div>
      )}

      <div className="flex items-center gap-2">
        <button
          onClick={handleSave}
          disabled={saving}
          className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-medium transition-colors"
          style={{ background: 'var(--color-brand)', color: 'black', opacity: saving ? 0.6 : 1 }}>
          <Check size={12} />
          {saving ? 'Saving…' : 'Save'}
        </button>
        <button
          onClick={onCancel}
          className="px-4 py-1.5 rounded-lg border text-xs font-medium transition-colors hover:bg-surface-hover"
          style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}>
          Cancel
        </button>
        {!isNew && onDelete && (
          <div className="ml-auto">
            {confirmDel
              ? (
                <span className="flex items-center gap-1">
                  <span className="text-xs text-red-400 mr-1">Confirm delete?</span>
                  <button onClick={() => onDelete(person.id)}
                    className="px-2 py-1 rounded text-xs bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30 transition-colors">
                    Yes, delete
                  </button>
                  <button onClick={() => setConfirmDel(false)}
                    className="px-2 py-1 rounded text-xs border text-text-muted hover:bg-surface-hover transition-colors"
                    style={{ borderColor: 'var(--color-border)' }}>
                    Cancel
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

function PersonCard({ person, allDevices, onUpdated, onDeleted }) {
  const [editing,   setEditing]   = useState(false)
  const [expanded,  setExpanded]  = useState(false)

  async function handleSave({ name, notes, photo, primary_mac, devices, existingPerson }) {
    // Update fields
    await api.updatePerson(existingPerson.id, { name, notes, photo, primary_mac })

    // Sync devices: remove ones no longer in the list, add new ones
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
    // Ensure primary_mac is set correctly
    if (primary_mac && primary_mac !== existingPerson.primary_mac) {
      await api.updatePerson(existingPerson.id, { primary_mac })
    }
    setEditing(false)
    onUpdated()
  }

  if (editing) {
    return (
      <PersonForm
        person={person}
        allDevices={allDevices}
        onSave={handleSave}
        onCancel={() => setEditing(false)}
        onDelete={async id => { await api.deletePerson(id); onDeleted() }}
      />
    )
  }

  return (
    <div className="rounded-xl border overflow-hidden"
      style={{ borderColor: 'var(--color-border)', background: 'var(--color-surface)' }}>
      <div className="p-4">
        <div className="flex items-start gap-3">
          <div className="relative">
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
            {/* Primary device */}
            {person.primary_mac && (() => {
              const pDev = person.devices.find(d => d.mac_address === person.primary_mac)
              return pDev ? (
                <div className="flex items-center gap-1 mt-1">
                  <Smartphone size={10} style={{ color: 'var(--color-text-faint)' }} />
                  <span className="text-[10px]" style={{ color: 'var(--color-text-faint)' }}>
                    {pDev.display_name}
                  </span>
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

        {/* Device list */}
        {person.devices.length > 0 && (
          <div className="mt-3 flex flex-wrap gap-1.5">
            {person.devices.map(d => (
              <DeviceChip key={d.mac_address} device={d} isPrimary={d.mac_address === person.primary_mac} />
            ))}
          </div>
        )}

        {/* Schedules */}
        {person.schedules.length > 0 && (
          <div className="mt-3 space-y-1">
            <div className="flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider"
              style={{ color: 'var(--color-text-faint)' }}>
              <Shield size={9} /> Block schedules
            </div>
            <div className="flex flex-wrap gap-1">
              {person.schedules.map(s => <ScheduleChip key={s.id} schedule={s} />)}
            </div>
          </div>
        )}

        {/* Expand toggle for empty state messaging */}
        {person.devices.length === 0 && (
          <p className="mt-3 text-xs italic" style={{ color: 'var(--color-text-faint)' }}>
            No devices assigned. Click edit to add devices.
          </p>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export function PersonPresencePage({ devices }) {
  const [persons,    setPersons]   = useState([])
  const [loading,    setLoading]   = useState(true)
  const [error,      setError]     = useState(null)
  const [showForm,   setShowForm]  = useState(false)

  const allDevices = (devices || []).map(d => ({
    ...d,
    display_name: d.custom_name || d.hostname || d.ip_address,
  }))

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

  async function handleCreate({ name, notes, photo, primary_mac, devices: devs }) {
    const person = await api.createPerson({ name, notes, photo, primary_mac })
    for (const d of devs) {
      await api.addPersonDevice(person.id, { mac_address: d.mac_address, set_primary: d.mac_address === primary_mac })
    }
    setShowForm(false)
    load()
  }

  const homeCount = persons.filter(p => p.is_home).length

  return (
    <div className="p-6 max-w-4xl mx-auto">
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
        <button
          onClick={() => setShowForm(v => !v)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors"
          style={{ background: 'var(--color-brand)', color: 'black' }}>
          <UserPlus size={15} />
          Add Person
        </button>
      </div>

      {/* Add form */}
      {showForm && (
        <div className="mb-6">
          <PersonForm
            allDevices={allDevices}
            onSave={handleCreate}
            onCancel={() => setShowForm(false)}
          />
        </div>
      )}

      {/* Loading / error */}
      {loading && (
        <div className="text-center py-12 text-text-muted text-sm">Loading…</div>
      )}
      {error && (
        <div className="flex items-center gap-2 text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-xl px-4 py-3 mb-6">
          <AlertTriangle size={14} /> {error}
        </div>
      )}

      {/* People grid */}
      {!loading && !error && persons.length === 0 && !showForm && (
        <div className="text-center py-16 space-y-3">
          <User size={40} style={{ color: 'var(--color-text-faint)', margin: '0 auto' }} />
          <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>No people configured yet</p>
          <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
            Add a person and assign their devices to track who is home.
          </p>
        </div>
      )}

      {!loading && persons.length > 0 && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-2 xl:grid-cols-3">
          {persons.map(person => (
            <PersonCard
              key={person.id}
              person={person}
              allDevices={allDevices}
              onUpdated={load}
              onDeleted={load}
            />
          ))}
        </div>
      )}
    </div>
  )
}
