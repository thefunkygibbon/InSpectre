import { useState, useEffect, useCallback, useMemo } from 'react'
import {
  ShieldOff, ShieldCheck, Plus, Trash2, ToggleLeft, ToggleRight,
  Loader, AlertTriangle, Clock, Wifi, WifiOff, Calendar, Pencil, Tag,
} from 'lucide-react'
import { api } from '../api'

const DAYS = [
  { key: 'mon', label: 'Mon' },
  { key: 'tue', label: 'Tue' },
  { key: 'wed', label: 'Wed' },
  { key: 'thu', label: 'Thu' },
  { key: 'fri', label: 'Fri' },
  { key: 'sat', label: 'Sat' },
  { key: 'sun', label: 'Sun' },
]

function PageSection({ title, children }) {
  return (
    <div className="rounded-xl border border-[var(--color-border)] overflow-hidden mb-6">
      <div className="px-5 py-3 border-b border-[var(--color-border)]"
        style={{ background: 'var(--color-surface-offset)' }}>
        <span className="text-xs font-semibold uppercase tracking-wider"
          style={{ color: 'var(--color-text-muted)' }}>{title}</span>
      </div>
      <div className="p-5">{children}</div>
    </div>
  )
}

function DaysSelector({ value, onChange }) {
  const selected = value.split(',').map(d => d.trim().toLowerCase()).filter(Boolean)
  function toggle(day) {
    const next = selected.includes(day)
      ? selected.filter(d => d !== day)
      : [...selected, day]
    onChange(DAYS.map(d => d.key).filter(k => next.includes(k)).join(','))
  }
  return (
    <div className="flex gap-1 flex-wrap">
      {DAYS.map(d => (
        <button key={d.key} type="button"
          onClick={() => toggle(d.key)}
          className="px-2 py-1 rounded text-xs font-medium transition-colors"
          style={selected.includes(d.key)
            ? { background: 'var(--color-brand)', color: 'white' }
            : { background: 'var(--color-surface-offset)', color: 'var(--color-text-muted)', border: '1px solid var(--color-border)' }}>
          {d.label}
        </button>
      ))}
    </div>
  )
}

function DeviceChecklist({ devices, selected, onChange }) {
  function toggle(mac) {
    onChange(selected.includes(mac)
      ? selected.filter(m => m !== mac)
      : [...selected, mac])
  }
  if (!devices.length) {
    return <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>No devices found.</p>
  }
  return (
    <div className="max-h-48 overflow-y-auto rounded-lg border divide-y"
      style={{ borderColor: 'var(--color-border)', divideColor: 'var(--color-border)' }}>
      {devices.map(d => (
        <label key={d.mac_address}
          className="flex items-center gap-2.5 px-3 py-2 cursor-pointer hover:bg-[var(--color-surface-offset)] transition-colors">
          <input type="checkbox" checked={selected.includes(d.mac_address)}
            onChange={() => toggle(d.mac_address)}
            className="rounded border-[var(--color-border)]" />
          <span className="w-2 h-2 rounded-full shrink-0"
            style={{ background: d.is_online ? '#10b981' : '#6b7280' }} />
          <span className="text-xs font-medium flex-1 truncate" style={{ color: 'var(--color-text)' }}>
            {d.display_name}
          </span>
          <span className="text-[10px] font-mono shrink-0" style={{ color: 'var(--color-text-faint)' }}>
            {d.ip_address}
          </span>
        </label>
      ))}
    </div>
  )
}

function ScheduleForm({ devices, allTags, initial, onSave, onCancel, saveLabel = 'Save schedule' }) {
  const [targetMode, setTargetMode] = useState(
    initial?.mac_addresses?.length ? 'devices'
    : initial?.tags ? 'tags'
    : 'whole'
  )
  const [selectedMacs, setSelectedMacs] = useState(initial?.mac_addresses || [])
  const [tagInput,     setTagInput]     = useState(initial?.tags || '')
  const [label,        setLabel]        = useState(initial?.label || '')
  const [days,         setDays]         = useState(initial?.days_of_week || 'mon,tue,wed,thu,fri,sat,sun')
  const [start,        setStart]        = useState(initial?.start_time || '22:00')
  const [end,          setEnd]          = useState(initial?.end_time || '07:00')
  const [saving,       setSaving]       = useState(false)
  const [error,        setError]        = useState(null)

  async function handleSubmit(e) {
    e.preventDefault()
    if (!days) { setError('Select at least one day'); return }
    if (targetMode === 'devices' && !selectedMacs.length) {
      setError('Select at least one device'); return
    }
    setSaving(true)
    setError(null)
    try {
      await onSave({
        mac_addresses: targetMode === 'devices' ? selectedMacs : [],
        tags:          targetMode === 'tags'    ? tagInput.trim() : '',
        label:         label || null,
        days_of_week:  days,
        start_time:    start,
        end_time:      end,
      })
    } catch (e) {
      setError(e.message)
      setSaving(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4 p-4 rounded-xl border"
      style={{ background: 'var(--color-surface-offset)', borderColor: 'var(--color-border)' }}>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <label className="block text-xs mb-1.5" style={{ color: 'var(--color-text-muted)' }}>Target</label>
          <div className="flex rounded-lg overflow-hidden border text-xs" style={{ borderColor: 'var(--color-border)' }}>
            {[
              { key: 'whole',   label: 'Whole network' },
              { key: 'devices', label: 'Devices' },
              { key: 'tags',    label: 'By tags' },
            ].map(opt => (
              <button key={opt.key} type="button"
                onClick={() => setTargetMode(opt.key)}
                className="flex-1 py-1.5 font-medium transition-colors"
                style={targetMode === opt.key
                  ? { background: 'var(--color-brand)', color: 'white' }
                  : { background: 'var(--color-surface)', color: 'var(--color-text-muted)' }}>
                {opt.label}
              </button>
            ))}
          </div>
        </div>
        <div>
          <label className="block text-xs mb-1" style={{ color: 'var(--color-text-muted)' }}>Label (optional)</label>
          <input className="input w-full text-xs" placeholder="e.g. Kids' bedtime"
            value={label} onChange={e => setLabel(e.target.value)} />
        </div>
      </div>

      {targetMode === 'devices' && (
        <div>
          <label className="block text-xs mb-1.5" style={{ color: 'var(--color-text-muted)' }}>
            Select devices ({selectedMacs.length} selected)
          </label>
          <DeviceChecklist devices={devices} selected={selectedMacs} onChange={setSelectedMacs} />
        </div>
      )}

      {targetMode === 'tags' && (
        <div>
          <label className="block text-xs mb-1" style={{ color: 'var(--color-text-muted)' }}>Tags (comma-separated)</label>
          <input className="input w-full text-xs" placeholder="e.g. kids, iot, guest"
            value={tagInput} onChange={e => setTagInput(e.target.value)} />
          {allTags.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-1.5">
              {allTags.map(t => (
                <button key={t} type="button"
                  onClick={() => {
                    const current = tagInput.split(',').map(s => s.trim()).filter(Boolean)
                    if (!current.includes(t)) setTagInput([...current, t].join(', '))
                  }}
                  className="px-1.5 py-0.5 rounded-full text-[10px] font-medium transition-opacity"
                  style={{ background: 'var(--color-brand)', color: '#fff', opacity: 0.75 }}>
                  {t}
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      <div>
        <label className="block text-xs mb-2" style={{ color: 'var(--color-text-muted)' }}>Days</label>
        <DaysSelector value={days} onChange={setDays} />
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs mb-1" style={{ color: 'var(--color-text-muted)' }}>Block from</label>
          <input type="time" className="input w-full text-xs font-mono"
            value={start} onChange={e => setStart(e.target.value)} />
        </div>
        <div>
          <label className="block text-xs mb-1" style={{ color: 'var(--color-text-muted)' }}>Until</label>
          <input type="time" className="input w-full text-xs font-mono"
            value={end} onChange={e => setEnd(e.target.value)} />
        </div>
      </div>

      {error && (
        <p className="text-xs px-3 py-2 rounded-lg" style={{ background: 'rgba(239,68,68,0.1)', color: '#f87171' }}>{error}</p>
      )}

      <div className="flex gap-2">
        <button type="submit" disabled={saving}
          className="px-4 py-1.5 rounded-lg text-xs font-semibold text-white disabled:opacity-50 flex items-center gap-1.5"
          style={{ background: 'var(--color-brand)' }}>
          {saving && <Loader size={11} className="animate-spin" />}
          {saveLabel}
        </button>
        <button type="button" onClick={onCancel}
          className="px-4 py-1.5 rounded-lg text-xs border"
          style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}>
          Cancel
        </button>
      </div>
    </form>
  )
}

function ScheduleRow({ schedule, devices, allTags, onToggle, onDelete, onSave }) {
  const [deleting, setDeleting] = useState(false)
  const [editing,  setEditing]  = useState(false)

  const targetLabel = useMemo(() => {
    if (schedule.mac_addresses?.length) {
      const names = schedule.mac_addresses.map(mac => {
        const d = devices.find(x => x.mac_address === mac)
        return d ? d.display_name : mac
      })
      if (names.length === 1) return names[0]
      if (names.length <= 3) return names.join(', ')
      return `${names.slice(0, 2).join(', ')} +${names.length - 2} more`
    }
    if (schedule.tags) return null  // rendered as tag badges
    if (schedule.mac_address) {
      return devices.find(d => d.mac_address === schedule.mac_address)?.display_name || schedule.mac_address
    }
    return 'Whole network'
  }, [schedule, devices])

  async function handleDelete() {
    if (!confirm('Delete this schedule?')) return
    setDeleting(true)
    try { await onDelete(schedule.id) } finally { setDeleting(false) }
  }

  async function handleSave(data) {
    await onSave(schedule.id, data)
    setEditing(false)
  }

  const days = schedule.days_of_week.split(',').map(d => d.trim())
  const allDays = days.length === 7

  if (editing) {
    return (
      <div className="p-3 border-b last:border-0" style={{ borderColor: 'var(--color-border)' }}>
        <ScheduleForm
          devices={devices}
          allTags={allTags}
          initial={schedule}
          onSave={handleSave}
          onCancel={() => setEditing(false)}
          saveLabel="Update schedule"
        />
      </div>
    )
  }

  return (
    <div className="flex items-center gap-3 px-4 py-3 border-b last:border-0"
      style={{ borderColor: 'var(--color-border)' }}>
      <button onClick={() => onToggle(schedule)}
        className="shrink-0 transition-colors"
        title={schedule.enabled ? 'Disable schedule' : 'Enable schedule'}>
        {schedule.enabled
          ? <ToggleRight size={20} style={{ color: 'var(--color-brand)' }} />
          : <ToggleLeft  size={20} style={{ color: 'var(--color-text-faint)' }} />}
      </button>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          {schedule.label && (
            <span className="text-sm font-medium" style={{ color: schedule.enabled ? 'var(--color-text)' : 'var(--color-text-faint)' }}>
              {schedule.label}
            </span>
          )}
          {schedule.tags ? (
            <span className="flex items-center gap-1">
              <Tag size={10} style={{ color: 'var(--color-brand)' }} />
              {schedule.tags.split(',').map(t => t.trim()).filter(Boolean).map(t => (
                <span key={t} className="text-[10px] px-1.5 py-0.5 rounded-full font-medium"
                  style={{ background: 'color-mix(in srgb, var(--color-brand) 15%, transparent)', color: 'var(--color-brand)', border: '1px solid color-mix(in srgb, var(--color-brand) 30%, transparent)' }}>
                  {t}
                </span>
              ))}
            </span>
          ) : (
            <span className="text-xs font-mono" style={{ color: schedule.label ? 'var(--color-text-faint)' : (schedule.enabled ? 'var(--color-text)' : 'var(--color-text-faint)') }}>
              {targetLabel}
            </span>
          )}
        </div>
        <div className="flex items-center gap-3 mt-0.5 flex-wrap">
          <span className="text-xs font-mono flex items-center gap-1" style={{ color: 'var(--color-text-muted)' }}>
            <Clock size={10} />
            {schedule.start_time} – {schedule.end_time}
          </span>
          <span className="text-xs flex items-center gap-1" style={{ color: 'var(--color-text-muted)' }}>
            <Calendar size={10} />
            {allDays ? 'Every day' : days.map(d => d.charAt(0).toUpperCase() + d.slice(1, 3)).join(', ')}
          </span>
        </div>
      </div>

      <button onClick={() => setEditing(true)}
        className="p-1.5 rounded-lg transition-colors hover:opacity-80 shrink-0"
        style={{ color: 'var(--color-text-faint)' }}
        title="Edit schedule">
        <Pencil size={13} />
      </button>

      <button onClick={handleDelete} disabled={deleting}
        className="p-1.5 rounded-lg transition-colors hover:text-red-400 shrink-0"
        style={{ color: 'var(--color-text-faint)' }}
        title="Delete schedule">
        {deleting ? <Loader size={14} className="animate-spin" /> : <Trash2 size={14} />}
      </button>
    </div>
  )
}

export function DeviceBlocking({ devices, onDeviceClick }) {
  const [networkStatus, setNetworkStatus] = useState(null)
  const [schedules,     setSchedules]     = useState([])
  const [loading,       setLoading]       = useState(true)
  const [pausing,       setPausing]       = useState(false)
  const [showAddForm,   setShowAddForm]   = useState(false)
  const [error,         setError]         = useState(null)
  const [autoBlockNew,  setAutoBlockNew]  = useState(false)
  const [autoBlockSev,  setAutoBlockSev]  = useState('none')

  const blockedDevices = devices.filter(d => d.is_blocked)

  const allTags = useMemo(() => {
    const tagSet = new Set()
    for (const d of devices) {
      if (d.tags_array) d.tags_array.forEach(t => tagSet.add(t))
    }
    return Array.from(tagSet).sort()
  }, [devices])

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [status, scheds, settings] = await Promise.all([
        api.getNetworkStatus(),
        api.getBlockSchedules(),
        api.getSettings(),
      ])
      setNetworkStatus(status)
      setSchedules(scheds)
      const autoNew = settings.find(s => s.key === 'auto_block_new_devices')
      const autoSev = settings.find(s => s.key === 'auto_block_vuln_severity')
      if (autoNew) setAutoBlockNew(autoNew.value === 'true')
      if (autoSev) setAutoBlockSev(autoSev.value || 'none')
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function handleNetworkToggle() {
    if (!networkStatus) return
    const isPaused = networkStatus.paused
    if (!confirm(isPaused
      ? 'Resume internet access for all devices?'
      : 'Pause internet for the entire network? This will block all devices.'))
      return

    setPausing(true)
    try {
      const result = isPaused ? await api.networkResume() : await api.networkPause()
      setNetworkStatus({ paused: result.paused, blocked_count: result.blocked ?? result.unblocked ?? 0 })
    } catch (e) {
      setError(e.message)
    } finally {
      setPausing(false)
    }
  }

  async function handleToggleSchedule(sched) {
    try {
      const updated = await api.updateBlockSchedule(sched.id, { enabled: !sched.enabled })
      setSchedules(prev => prev.map(s => s.id === sched.id ? updated : s))
    } catch (e) {
      setError(e.message)
    }
  }

  async function handleDeleteSchedule(id) {
    await api.deleteBlockSchedule(id)
    setSchedules(prev => prev.filter(s => s.id !== id))
  }

  async function handleSaveSchedule(id, data) {
    const updated = await api.updateBlockSchedule(id, data)
    setSchedules(prev => prev.map(s => s.id === id ? updated : s))
  }

  async function handleBlockDevice(mac) {
    try {
      await api.blockDevice(mac)
      await load()
    } catch (e) {
      setError(e.message)
    }
  }

  async function handleUnblockDevice(mac) {
    try {
      await api.unblockDevice(mac)
      await load()
    } catch (e) {
      setError(e.message)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader size={24} className="animate-spin" style={{ color: 'var(--color-text-faint)' }} />
      </div>
    )
  }

  const isPaused = networkStatus?.paused

  return (
    <div className="max-w-3xl mx-auto">

      {error && (
        <div className="mb-5 flex items-center gap-3 px-4 py-3 rounded-xl text-sm"
          style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.2)', color: '#ef4444' }}>
          <AlertTriangle size={15} className="shrink-0" />
          {error}
          <button onClick={() => setError(null)} className="ml-auto opacity-60 hover:opacity-100 text-xs">Dismiss</button>
        </div>
      )}

      {/* Auto-block rules */}
      <PageSection title="Automatic Blocking Rules">
        <div className="space-y-4">
          <div className="flex items-start gap-3">
            <button onClick={async () => {
              const next = !autoBlockNew
              setAutoBlockNew(next)
              await api.updateSetting('auto_block_new_devices', next ? 'true' : 'false').catch(() => {})
            }}
              className="shrink-0 mt-0.5 transition-colors"
              title={autoBlockNew ? 'Disable auto-block for new devices' : 'Enable auto-block for new devices'}>
              {autoBlockNew
                ? <ToggleRight size={20} style={{ color: 'var(--color-brand)' }} />
                : <ToggleLeft  size={20} style={{ color: 'var(--color-text-faint)' }} />}
            </button>
            <div>
              <p className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>Block new devices on discovery</p>
              <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-muted)' }}>
                Automatically ARP-block any device the moment it is first discovered. Useful for a whitelist-style approach — manually unblock trusted devices.
              </p>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <div className="flex-1">
              <p className="text-sm font-medium mb-1" style={{ color: 'var(--color-text)' }}>Auto-block on vulnerability severity</p>
              <p className="text-xs mb-2" style={{ color: 'var(--color-text-muted)' }}>
                Block a device automatically when a vuln scan finds issues at or above the selected severity.
              </p>
              <select className="input text-xs w-48"
                value={autoBlockSev}
                onChange={async e => {
                  const v = e.target.value
                  setAutoBlockSev(v)
                  await api.updateSetting('auto_block_vuln_severity', v).catch(() => {})
                }}>
                <option value="none">Disabled</option>
                <option value="medium">Medium and above</option>
                <option value="high">High and above</option>
                <option value="critical">Critical only</option>
              </select>
            </div>
          </div>
        </div>
      </PageSection>

      {/* Network-wide pause */}
      <PageSection title="Network Internet Pause">
        <div className="flex items-start gap-4">
          <div className={`w-12 h-12 rounded-xl flex items-center justify-center shrink-0 ${isPaused ? 'bg-red-500/15' : 'bg-emerald-500/15'}`}>
            {isPaused
              ? <ShieldOff size={22} style={{ color: '#ef4444' }} />
              : <ShieldCheck size={22} style={{ color: '#10b981' }} />}
          </div>
          <div className="flex-1">
            <p className="font-medium text-sm" style={{ color: 'var(--color-text)' }}>
              {isPaused ? 'Internet is paused' : 'Internet is active'}
            </p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-muted)' }}>
              {isPaused
                ? `${networkStatus?.blocked_count ?? 0} device(s) currently blocked. All traffic is being intercepted via ARP.`
                : 'All devices have normal internet access. Use this toggle to cut access for the entire network instantly.'}
            </p>
            <button onClick={handleNetworkToggle} disabled={pausing}
              className="mt-3 px-4 py-1.5 rounded-lg text-xs font-semibold text-white disabled:opacity-50 flex items-center gap-1.5"
              style={{ background: isPaused ? '#10b981' : '#ef4444' }}>
              {pausing && <Loader size={11} className="animate-spin" />}
              {isPaused ? 'Resume internet' : 'Pause internet for whole network'}
            </button>
          </div>
        </div>
      </PageSection>

      {/* Schedules */}
      <PageSection title="Block Schedules">
        {schedules.length === 0 && !showAddForm ? (
          <div className="text-center py-6">
            <Clock size={28} className="mx-auto mb-2" style={{ color: 'var(--color-text-faint)' }} />
            <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>No schedules configured</p>
            <p className="text-xs mt-1" style={{ color: 'var(--color-text-faint)' }}>
              Create time-based rules to automatically block devices during set hours.
            </p>
          </div>
        ) : (
          <div className="rounded-lg border overflow-hidden mb-4" style={{ borderColor: 'var(--color-border)' }}>
            {schedules.map(s => (
              <ScheduleRow key={s.id} schedule={s} devices={devices} allTags={allTags}
                onToggle={handleToggleSchedule}
                onDelete={handleDeleteSchedule}
                onSave={handleSaveSchedule} />
            ))}
          </div>
        )}

        {showAddForm ? (
          <ScheduleForm
            devices={devices}
            allTags={allTags}
            onSave={async data => {
              const created = await api.createBlockSchedule(data)
              setSchedules(prev => [created, ...prev])
              setShowAddForm(false)
            }}
            onCancel={() => setShowAddForm(false)}
          />
        ) : (
          <button onClick={() => setShowAddForm(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold border transition-colors"
            style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}>
            <Plus size={13} /> Add schedule
          </button>
        )}
      </PageSection>

      {/* Per-device blocking */}
      <PageSection title="Device Blocking">
        {devices.length === 0 ? (
          <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>No devices discovered yet.</p>
        ) : (
          <div className="space-y-1">
            {devices
              .filter(d => !d.is_ignored)
              .sort((a, b) => (b.is_blocked ? 1 : 0) - (a.is_blocked ? 1 : 0) || (a.display_name || '').localeCompare(b.display_name || ''))
              .map(d => (
                <div key={d.mac_address}
                  className="flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors"
                  style={{ background: d.is_blocked ? 'rgba(239,68,68,0.06)' : 'var(--color-surface-offset)' }}>
                  <span className="w-2 h-2 rounded-full shrink-0"
                    style={{ background: d.is_online ? '#10b981' : '#ef4444' }} />
                  <div className="flex-1 min-w-0"
                    onClick={() => onDeviceClick && onDeviceClick(d)}
                    style={{ cursor: onDeviceClick ? 'pointer' : 'default' }}>
                    <p className="text-sm font-medium truncate hover:underline"
                      style={{ color: onDeviceClick ? 'var(--color-brand)' : 'var(--color-text)' }}>
                      {d.display_name}
                    </p>
                    <p className="text-xs font-mono" style={{ color: 'var(--color-text-faint)' }}>
                      {d.ip_address} · {d.mac_address}
                    </p>
                  </div>
                  {d.is_blocked && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded font-semibold uppercase shrink-0"
                      style={{ background: 'rgba(239,68,68,0.15)', color: '#f87171', border: '1px solid rgba(239,68,68,0.3)' }}>
                      Blocked
                    </span>
                  )}
                  {d.is_blocked ? (
                    <button onClick={() => handleUnblockDevice(d.mac_address)}
                      className="px-3 py-1 rounded-lg text-xs font-semibold shrink-0 flex items-center gap-1"
                      style={{ background: 'rgba(16,185,129,0.15)', color: '#10b981', border: '1px solid rgba(16,185,129,0.3)' }}>
                      <Wifi size={11} /> Unblock
                    </button>
                  ) : (
                    <button onClick={() => handleBlockDevice(d.mac_address)}
                      className="px-3 py-1 rounded-lg text-xs font-semibold shrink-0 flex items-center gap-1"
                      style={{ background: 'rgba(239,68,68,0.1)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.25)' }}>
                      <WifiOff size={11} /> Block
                    </button>
                  )}
                </div>
              ))}
          </div>
        )}
      </PageSection>
    </div>
  )
}
