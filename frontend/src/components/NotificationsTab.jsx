import { useState, useEffect, useCallback } from 'react'
import {
  Bell, Plus, Trash2, Edit2, Send, Check, X, ChevronDown, ChevronRight,
  Eye, EyeOff, Loader,
} from 'lucide-react'
import { api } from '../api'

// ---------------------------------------------------------------------------
// Service definitions — one entry per Apprise-supported service
// ---------------------------------------------------------------------------
const SERVICES = {
  // Virtual / in-app channels (no credentials needed)
  toast: {
    label: 'Toast (in-app)',
    fields: [],
  },
  browser: {
    label: 'Browser notification',
    fields: [],
  },

  // External Apprise-powered services
  ntfy: {
    label: 'ntfy',
    fields: [
      { key: 'server',   label: 'Server URL', type: 'url',      placeholder: 'https://ntfy.sh', required: false },
      { key: 'topic',    label: 'Topic',       type: 'text',     placeholder: 'my-inspectre-alerts', required: true },
      { key: 'user',     label: 'Username',    type: 'text',     placeholder: 'optional', required: false },
      { key: 'password', label: 'Password',    type: 'password', placeholder: 'optional', required: false },
    ],
  },
  gotify: {
    label: 'Gotify',
    fields: [
      { key: 'server', label: 'Server URL',  type: 'url',      placeholder: 'https://gotify.example.com', required: true },
      { key: 'token',  label: 'App Token',   type: 'password', placeholder: 'App token from Gotify', required: true },
    ],
  },
  home_assistant: {
    label: 'Home Assistant',
    fields: [
      { key: 'host',     label: 'Host',                    type: 'text',     placeholder: 'homeassistant.local  (or https://ha.domain.com)', required: true },
      { key: 'token',    label: 'Long-lived access token', type: 'password', placeholder: 'your HA long-lived token', required: true },
      { key: 'port',     label: 'Port',                    type: 'number',   placeholder: '8123 (blank = default)', required: false },
      { key: 'secure',   label: 'Use HTTPS',               type: 'toggle',   required: false },
      { key: 'notifier', label: 'HA service path',          type: 'text',     placeholder: 'blank = persistent_notification/create', required: false },
    ],
  },
  mqtt: {
    label: 'MQTT',
    fields: [
      { key: 'host',     label: 'Broker host',           type: 'text',     placeholder: 'mqtt.example.com', required: true },
      { key: 'topic',    label: 'Topic',                 type: 'text',     placeholder: 'inspectre/alerts', required: true },
      { key: 'user',     label: 'Username',              type: 'text',     placeholder: 'optional',         required: false },
      { key: 'password', label: 'Password',              type: 'password', placeholder: 'optional',         required: false },
      { key: 'port',     label: 'Port',                  type: 'number',   placeholder: '1883',             required: false },
      { key: 'secure',   label: 'Use TLS (port 8883)',   type: 'toggle',   required: false },
    ],
  },
  telegram: {
    label: 'Telegram',
    fields: [
      { key: 'bot_token', label: 'Bot Token', type: 'password', placeholder: '123456:ABC-DEF…', required: true },
      { key: 'chat_id',   label: 'Chat ID',   type: 'text',     placeholder: '-100… or @channel', required: true },
    ],
  },
  discord: {
    label: 'Discord',
    fields: [
      { key: 'webhook_id',    label: 'Webhook ID',    type: 'text',     placeholder: '123456789012345678', required: true },
      { key: 'webhook_token', label: 'Webhook Token', type: 'password', placeholder: 'token from the webhook URL', required: true },
    ],
  },
  slack: {
    label: 'Slack',
    fields: [
      { key: 'token_a', label: 'Token A (T…)', type: 'text',     placeholder: 'T00000000', required: true },
      { key: 'token_b', label: 'Token B (B…)', type: 'text',     placeholder: 'B00000000', required: true },
      { key: 'token_c', label: 'Token C',      type: 'password', placeholder: 'xxxxxxxxxxxxxxxxxxxxxxxx', required: true },
    ],
  },
  matrix: {
    label: 'Matrix',
    fields: [
      { key: 'user',     label: 'Username',       type: 'text',     placeholder: '@user:matrix.org', required: true },
      { key: 'password', label: 'Password',        type: 'password', placeholder: 'account password', required: true },
      { key: 'host',     label: 'Homeserver host', type: 'text',     placeholder: 'matrix.org',       required: true },
      { key: 'room',     label: 'Room',            type: 'text',     placeholder: '#room:matrix.org (optional)', required: false },
      { key: 'port',     label: 'Port',            type: 'number',   placeholder: 'blank = default',  required: false },
      { key: 'secure',   label: 'Use HTTPS',       type: 'toggle',   required: false },
    ],
  },
  msteams: {
    label: 'Microsoft Teams',
    fields: [
      { key: 'webhook_url', label: 'Incoming webhook URL', type: 'url', placeholder: 'https://xxx.webhook.office.com/webhookb2/…', required: true },
    ],
  },
  pushover: {
    label: 'Pushover',
    fields: [
      { key: 'user_key',  label: 'User Key',  type: 'password', placeholder: 'User key from Pushover',  required: true },
      { key: 'api_token', label: 'API Token', type: 'password', placeholder: 'App token from Pushover', required: true },
    ],
  },
  signal: {
    label: 'Signal',
    fields: [
      { key: 'from_phone', label: 'Your Signal number', type: 'text', placeholder: '+447700000000', required: true },
      { key: 'to_phone',   label: 'Recipient number',   type: 'text', placeholder: '+447700000001', required: true },
      { key: 'host',       label: 'signal-cli REST API host', type: 'text', placeholder: 'localhost', required: false },
      { key: 'port',       label: 'Port',                type: 'number', placeholder: '8080', required: false },
    ],
  },
  whatsapp: {
    label: 'WhatsApp',
    fields: [
      { key: 'token',    label: 'API access token',  type: 'password', placeholder: 'Meta WhatsApp Business API token', required: true },
      { key: 'phone_id', label: 'Phone Number ID',   type: 'text',     placeholder: 'Phone Number ID from Meta',        required: true },
      { key: 'to_phone', label: 'Recipient number',  type: 'text',     placeholder: '+447700000001',                    required: true },
    ],
  },
  pushbullet: {
    label: 'Pushbullet',
    fields: [
      { key: 'api_key', label: 'API Key', type: 'password', placeholder: 'o.XXXX…', required: true },
    ],
  },
  ifttt: {
    label: 'IFTTT',
    fields: [
      { key: 'webhook_key', label: 'Maker Webhooks key', type: 'password', placeholder: 'your IFTTT key', required: true },
      { key: 'event_id',    label: 'Event name',          type: 'text',     placeholder: 'inspectre_alert', required: true },
    ],
  },
  email: {
    label: 'Email (SMTP)',
    fields: [
      { key: 'to_email',      label: 'To',          type: 'email',    placeholder: 'you@example.com', required: true },
      { key: 'smtp_host',     label: 'SMTP Host',   type: 'text',     placeholder: 'smtp.gmail.com',  required: true },
      { key: 'smtp_port',     label: 'Port',        type: 'number',   placeholder: '587',             required: false },
      { key: 'smtp_user',     label: 'Username',    type: 'text',     placeholder: 'you@example.com', required: true },
      { key: 'smtp_password', label: 'Password',    type: 'password', placeholder: 'App password',    required: true },
    ],
  },
  webhook: {
    label: 'Webhook (JSON)',
    fields: [
      { key: 'url', label: 'URL', type: 'url', placeholder: 'https://example.com/webhook', required: true },
    ],
  },
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
function SectionHeader({ label, Icon }) {
  return (
    <div className="flex items-center gap-2 pt-2 pb-1">
      {Icon && <Icon size={14} style={{ color: 'var(--color-brand)' }} />}
      <span className="text-xs font-semibold uppercase tracking-wide"
            style={{ color: 'var(--color-text-muted)' }}>{label}</span>
    </div>
  )
}

function StatusBadge({ status, msg }) {
  if (!status) return null
  const colours = { ok: '#22c55e', error: '#ef4444', testing: 'var(--color-text-muted)' }
  return (
    <span className="text-xs" style={{ color: colours[status] }}>
      {status === 'testing' && <Loader size={10} className="inline mr-1 animate-spin" />}
      {msg}
    </span>
  )
}

function PasswordField({ value, onChange, placeholder, className = '' }) {
  const [show, setShow] = useState(false)
  return (
    <div className="relative">
      <input
        type={show ? 'text' : 'password'}
        className={`input text-sm pr-9 font-mono ${className}`}
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
      />
      <button type="button"
        onClick={() => setShow(v => !v)}
        className="absolute right-2.5 top-1/2 -translate-y-1/2 opacity-50 hover:opacity-100 transition-opacity">
        {show ? <EyeOff size={13} /> : <Eye size={13} />}
      </button>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Channel form (create / edit)
// ---------------------------------------------------------------------------
function ChannelForm({ initial, onSave, onCancel }) {
  const [name, setName]       = useState(initial?.name    ?? '')
  const [service, setService] = useState(initial?.service ?? 'ntfy')
  const [config, setConfig]   = useState(initial?.config  ?? {})
  const [enabled, setEnabled] = useState(initial?.enabled ?? true)
  const [saving, setSaving]   = useState(false)
  const [err, setErr]         = useState('')

  const svcDef = SERVICES[service] ?? SERVICES.ntfy

  const setField = (key, val) => setConfig(c => ({ ...c, [key]: val }))

  const handleSubmit = async e => {
    e.preventDefault()
    setSaving(true); setErr('')
    try {
      await onSave({ name: name.trim(), service, config, enabled })
    } catch (ex) {
      setErr(ex.message || 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="card p-4 space-y-3 border"
          style={{ borderColor: 'var(--color-brand)', borderRadius: '8px' }}>
      {/* Name + service selector */}
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Channel name</label>
          <input className="input text-sm" value={name} onChange={e => setName(e.target.value)}
                 placeholder="My alerts" required />
        </div>
        <div className="space-y-1">
          <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Service</label>
          <select className="input text-sm" value={service}
                  onChange={e => { setService(e.target.value); setConfig({}) }}>
            {Object.entries(SERVICES).map(([k, v]) => (
              <option key={k} value={k}>{v.label}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Service-specific fields */}
      {svcDef.fields.map(f => (
        f.type === 'toggle'
          ? (
            <div key={f.key} className="flex items-center justify-between gap-3 py-0.5">
              <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>{f.label}</label>
              <button type="button"
                onClick={() => setField(f.key, !config[f.key])}
                className={`relative inline-flex h-5 w-9 shrink-0 rounded-full transition-colors ${
                  config[f.key] ? 'bg-blue-500' : 'bg-gray-400'
                }`} style={{ minWidth: '36px' }}>
                <span className={`inline-block h-4 w-4 mt-0.5 rounded-full bg-white shadow transition-transform ${
                  config[f.key] ? 'translate-x-4' : 'translate-x-0.5'
                }`} />
              </button>
            </div>
          )
          : (
            <div key={f.key} className="space-y-1">
              <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>
                {f.label}{f.required && <span style={{ color: '#ef4444' }}> *</span>}
              </label>
              {f.type === 'password'
                ? <PasswordField value={config[f.key] ?? ''} onChange={v => setField(f.key, v)} placeholder={f.placeholder} />
                : <input type={f.type} className="input text-sm" placeholder={f.placeholder}
                         value={config[f.key] ?? ''} onChange={e => setField(f.key, e.target.value)}
                         required={f.required} />
              }
            </div>
          )
      ))}

      <div className="flex items-center gap-2">
        <input type="checkbox" id="ch-enabled" checked={enabled} onChange={e => setEnabled(e.target.checked)} />
        <label htmlFor="ch-enabled" className="text-xs" style={{ color: 'var(--color-text-muted)' }}>Enabled</label>
      </div>

      {err && <p className="text-xs" style={{ color: '#ef4444' }}>{err}</p>}

      <div className="flex gap-2 pt-1">
        <button type="submit" disabled={saving} className="btn-primary text-sm flex items-center gap-1.5">
          {saving ? <Loader size={12} className="animate-spin" /> : <Check size={12} />}
          {saving ? 'Saving…' : 'Save channel'}
        </button>
        <button type="button" onClick={onCancel} className="btn-secondary text-sm">Cancel</button>
      </div>
    </form>
  )
}

// ---------------------------------------------------------------------------
// Channel card
// ---------------------------------------------------------------------------
function ChannelCard({ channel, onEdit, onDelete, onTest }) {
  const [testStatus, setTestStatus] = useState(null)
  const [testMsg,    setTestMsg]    = useState('')

  const handleTest = async () => {
    setTestStatus('testing'); setTestMsg('Sending…')
    try {
      await onTest(channel.id)
      setTestStatus('ok'); setTestMsg('Sent successfully')
    } catch (ex) {
      setTestStatus('error'); setTestMsg(ex.message || 'Test failed')
    }
    setTimeout(() => setTestStatus(null), 5000)
  }

  const svcLabel = SERVICES[channel.service]?.label ?? channel.service

  return (
    <div className="card p-3 flex items-center gap-3"
         style={{ opacity: channel.enabled ? 1 : 0.55 }}>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium truncate" style={{ color: 'var(--color-text)' }}>{channel.name}</p>
        <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>{svcLabel}</p>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        <StatusBadge status={testStatus} msg={testMsg} />
        <button onClick={handleTest} disabled={testStatus === 'testing'}
                className="btn-secondary text-xs flex items-center gap-1" title="Send test notification">
          <Send size={11} /> Test
        </button>
        <button onClick={() => onEdit(channel)} className="btn-secondary text-xs p-1.5" title="Edit">
          <Edit2 size={12} />
        </button>
        <button onClick={() => onDelete(channel.id)} className="btn-secondary text-xs p-1.5"
                title="Delete" style={{ color: '#ef4444' }}>
          <Trash2 size={12} />
        </button>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Profile editor (create / edit)
// ---------------------------------------------------------------------------
function ProfileEditor({ initial, channels, eventGroups, onSave, onCancel }) {
  const [name,    setName]    = useState(initial?.name    ?? '')
  const [events,  setEvents]  = useState(initial?.events  ?? {})
  const [chIds,   setChIds]   = useState(new Set(initial?.channel_ids ?? []))
  const [saving,  setSaving]  = useState(false)
  const [err,     setErr]     = useState('')
  const [openCats, setOpenCats] = useState({})

  const toggleEvent = type => setEvents(ev => ({ ...ev, [type]: !ev[type] }))
  const toggleCh    = id   => setChIds(s  => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n })
  const toggleCat   = cat  => setOpenCats(o => ({ ...o, [cat]: !o[cat] }))

  const handleSubmit = async e => {
    e.preventDefault()
    setSaving(true); setErr('')
    try {
      await onSave({ name: name.trim(), events, channel_ids: [...chIds] })
    } catch (ex) {
      setErr(ex.message || 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="card p-4 space-y-4 border"
          style={{ borderColor: 'var(--color-brand)', borderRadius: '8px' }}>
      <div className="space-y-1">
        <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Profile name</label>
        <input className="input text-sm" value={name} onChange={e => setName(e.target.value)}
               placeholder="Critical Alerts" required />
      </div>

      {/* Event toggles by category */}
      <div>
        <p className="text-xs font-semibold mb-2" style={{ color: 'var(--color-text-muted)' }}>
          Notification events
        </p>
        <div className="space-y-1">
          {eventGroups.map(({ category, events: catEvents }) => {
            const isOpen = openCats[category] !== false  // default open
            return (
              <div key={category}>
                <button type="button"
                  onClick={() => toggleCat(category)}
                  className="flex items-center gap-1.5 w-full text-left py-1">
                  {isOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                  <span className="text-xs font-semibold" style={{ color: 'var(--color-text-muted)' }}>
                    {category}
                  </span>
                  <span className="text-xs ml-auto" style={{ color: 'var(--color-text-faint)' }}>
                    {catEvents.filter(e => events[e.type]).length}/{catEvents.length}
                  </span>
                </button>
                {isOpen && (
                  <div className="ml-4 space-y-1 pb-1">
                    {catEvents.map(ev => (
                      <label key={ev.type} className="flex items-start gap-2 cursor-pointer py-0.5">
                        <input type="checkbox"
                               checked={!!events[ev.type]}
                               onChange={() => toggleEvent(ev.type)}
                               className="mt-0.5 shrink-0" />
                        <div>
                          <span className="text-xs font-medium" style={{ color: 'var(--color-text)' }}>
                            {ev.label}
                          </span>
                          <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                            {ev.description}
                          </p>
                        </div>
                      </label>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* Channels */}
      <div>
        <p className="text-xs font-semibold mb-2" style={{ color: 'var(--color-text-muted)' }}>
          Deliver to channels
        </p>
        {channels.length === 0
          ? <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
              No channels configured yet — add one above first.
            </p>
          : <div className="space-y-1">
              {channels.map(ch => (
                <label key={ch.id} className="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox"
                         checked={chIds.has(ch.id)}
                         onChange={() => toggleCh(ch.id)} />
                  <span className="text-xs" style={{ color: 'var(--color-text)' }}>{ch.name}</span>
                  <span className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                    ({SERVICES[ch.service]?.label ?? ch.service})
                  </span>
                </label>
              ))}
            </div>
        }
      </div>

      {err && <p className="text-xs" style={{ color: '#ef4444' }}>{err}</p>}

      <div className="flex gap-2">
        <button type="submit" disabled={saving} className="btn-primary text-sm flex items-center gap-1.5">
          {saving ? <Loader size={12} className="animate-spin" /> : <Check size={12} />}
          {saving ? 'Saving…' : 'Save profile'}
        </button>
        <button type="button" onClick={onCancel} className="btn-secondary text-sm">Cancel</button>
      </div>
    </form>
  )
}

// ---------------------------------------------------------------------------
// Profile card
// ---------------------------------------------------------------------------
function ProfileCard({ profile, channels, onEdit, onDelete }) {
  const enabledCount = Object.values(profile.events ?? {}).filter(Boolean).length
  const chNames = (profile.channel_ids ?? [])
    .map(id => channels.find(c => c.id === id)?.name)
    .filter(Boolean)

  return (
    <div className="card p-3 flex items-center gap-3">
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>{profile.name}</p>
        <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
          {enabledCount} event{enabledCount !== 1 ? 's' : ''}
          {chNames.length > 0 && ` · ${chNames.join(', ')}`}
        </p>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        <button onClick={() => onEdit(profile)} className="btn-secondary text-xs p-1.5" title="Edit">
          <Edit2 size={12} />
        </button>
        <button onClick={() => onDelete(profile.id)} className="btn-secondary text-xs p-1.5"
                title="Delete" style={{ color: '#ef4444' }}>
          <Trash2 size={12} />
        </button>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main NotificationsTab component
// ---------------------------------------------------------------------------
export function NotificationsTab({ settings, dirty, onchange }) {
  const [channels,     setChannels]     = useState([])
  const [profiles,     setProfiles]     = useState([])
  const [eventGroups,  setEventGroups]  = useState([])
  const [loading,      setLoading]      = useState(true)

  // UI state
  const [showChForm,   setShowChForm]   = useState(false)
  const [editingCh,    setEditingCh]    = useState(null)   // channel being edited
  const [showPrForm,   setShowPrForm]   = useState(false)
  const [editingPr,    setEditingPr]    = useState(null)   // profile being edited

  // Browser permission state
  const [browserPerm, setBrowserPerm] = useState(
    typeof Notification !== 'undefined' ? Notification.permission : 'unsupported'
  )

  const val = key => {
    if (dirty[key] !== undefined) return dirty[key]
    return settings.find(s => s.key === key)?.value ?? ''
  }
  const hasBrowserChannel = channels.some(c => c.service === 'browser')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [chs, prs, evs] = await Promise.all([
        api.notifChannels(),
        api.notifProfiles(),
        api.notifEvents(),
      ])
      setChannels(chs)
      setProfiles(prs)
      setEventGroups(evs)
    } catch { /* ignore */ }
    setLoading(false)
  }, [])

  useEffect(() => { load() }, [load])

  // ---- Channel CRUD ----
  const handleSaveCh = async data => {
    if (editingCh) {
      const updated = await api.updateNotifChannel(editingCh.id, data)
      setChannels(cs => cs.map(c => c.id === editingCh.id ? updated : c))
      setEditingCh(null)
    } else {
      const created = await api.createNotifChannel(data)
      setChannels(cs => [...cs, created])
      setShowChForm(false)
    }
  }

  const handleDeleteCh = async id => {
    if (!confirm('Delete this notification channel?')) return
    await api.deleteNotifChannel(id)
    setChannels(cs => cs.filter(c => c.id !== id))
    // Remove from profiles
    setProfiles(ps => ps.map(p => ({
      ...p,
      channel_ids: (p.channel_ids ?? []).filter(cid => cid !== id),
    })))
  }

  const handleTestCh = async id => {
    const result = await api.testNotifChannel(id)
    if (!result?.sent) throw new Error('Test notification not confirmed sent')
    return result
  }

  // ---- Profile CRUD ----
  const handleSavePr = async data => {
    if (editingPr) {
      const updated = await api.updateNotifProfile(editingPr.id, data)
      setProfiles(ps => ps.map(p => p.id === editingPr.id ? updated : p))
      setEditingPr(null)
    } else {
      const created = await api.createNotifProfile(data)
      setProfiles(ps => [...ps, created])
      setShowPrForm(false)
    }
  }

  const handleDeletePr = async id => {
    if (!confirm('Delete this notification profile?')) return
    await api.deleteNotifProfile(id)
    setProfiles(ps => ps.filter(p => p.id !== id))
  }

  const handleRequestBrowserPermission = async () => {
    if (typeof Notification === 'undefined') return
    const perm = await Notification.requestPermission()
    setBrowserPerm(perm)
  }

  // ---- Speedtest settings ----
  const speedtestFields = [
    { key: 'speedtest_expected_download', label: 'Expected Download', unit: 'Mbps', placeholder: '0 = disabled' },
    { key: 'speedtest_expected_upload',   label: 'Expected Upload',   unit: 'Mbps', placeholder: '0 = disabled' },
    { key: 'speedtest_alert_threshold',   label: 'Alert Threshold',   unit: '%',    placeholder: '80' },
  ]

  return (
    <div className="space-y-1">
      <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
        Configure notification channels (where to send) and profiles (what events to notify about).
      </p>

      {/* ── In-app toggles ─────────────────────────────────────── */}
      <SectionHeader label="In-App" Icon={Bell} />
      {['notifications_enabled', 'float_new_to_top'].map(key => {
        const s = settings.find(s => s.key === key)
        if (!s) return null
        const labels = {
          notifications_enabled: 'Toast Notifications (global)',
          float_new_to_top: 'Surface New Items First',
        }
        const descs = {
          notifications_enabled: 'Master switch for in-app toasts. Per-event control is via Notification Profiles below.',
          float_new_to_top: 'Float unacknowledged new devices to the top of the list.',
        }
        const current = val(key)
        return (
          <div key={key} className="card p-3 flex items-center justify-between gap-3">
            <div>
              <p className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>{labels[key]}</p>
              <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>{descs[key]}</p>
            </div>
            <button
              onClick={() => onchange(key, current === 'true' ? 'false' : 'true')}
              className={`relative inline-flex h-5 w-9 shrink-0 rounded-full transition-colors ${
                current === 'true' ? 'bg-blue-500' : 'bg-gray-400'
              }`}
              style={{ minWidth: '36px' }}>
              <span className={`inline-block h-4 w-4 mt-0.5 rounded-full bg-white shadow transition-transform ${
                current === 'true' ? 'translate-x-4' : 'translate-x-0.5'
              }`} />
            </button>
          </div>
        )
      })}

      {/* Browser permission helper — shown when a browser channel exists */}
      {hasBrowserChannel && browserPerm !== 'unsupported' && (
        <div className="rounded-lg p-3 text-xs space-y-2"
             style={{ background: 'var(--color-surface-offset)', border: '1px solid var(--color-border)' }}>
          <div className="flex items-center justify-between">
            <span className="font-medium" style={{ color: 'var(--color-text)' }}>Browser permission</span>
            <span className="text-xs px-1.5 py-0.5 rounded"
                  style={{
                    background: browserPerm === 'granted' ? '#16a34a22' : '#f5952222',
                    color: browserPerm === 'granted' ? '#16a34a' : '#f59522',
                  }}>
              {browserPerm}
            </span>
          </div>
          {browserPerm === 'default' && (
            <>
              <p style={{ color: 'var(--color-text-muted)' }}>Permission required to show OS-level notifications.</p>
              <button onClick={handleRequestBrowserPermission} className="btn-secondary text-xs flex items-center gap-1.5">
                <Bell size={11} /> Request Permission
              </button>
            </>
          )}
          {browserPerm === 'denied' && (
            <p style={{ color: '#ef4444' }}>Permission denied. Reset in your browser's site settings.</p>
          )}
          {browserPerm === 'granted' && (
            <p style={{ color: 'var(--color-text-muted)' }}>OS notifications are active.</p>
          )}
        </div>
      )}

      {/* ── Speed test alert thresholds ──────────────────────────── */}
      <SectionHeader label="Speed Test Alerts" Icon={Bell} />
      <div className="card p-4 space-y-3">
        <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
          Alert when scheduled speed test drops below a percentage of your contracted speeds.
          Set expected speeds to 0 to disable.
        </p>
        {speedtestFields.map(f => (
          <div key={f.key} className="flex items-center gap-3">
            <label className="text-xs font-medium w-40 shrink-0"
                   style={{ color: 'var(--color-text-muted)' }}>{f.label}</label>
            <div className="flex items-center gap-1.5 flex-1">
              <input type="number" className="input text-sm w-24"
                     value={val(f.key)}
                     onChange={e => onchange(f.key, e.target.value)}
                     placeholder={f.placeholder} min="0" />
              <span className="text-xs" style={{ color: 'var(--color-text-faint)' }}>{f.unit}</span>
            </div>
          </div>
        ))}
        <div className="flex items-center gap-3">
          <label className="text-xs font-medium w-40 shrink-0"
                 style={{ color: 'var(--color-text-muted)' }}>Device Returned After</label>
          <div className="flex items-center gap-1.5 flex-1">
            <input type="number" className="input text-sm w-24"
                   value={val('device_returned_days')}
                   onChange={e => onchange('device_returned_days', e.target.value)}
                   placeholder="7" min="1" />
            <span className="text-xs" style={{ color: 'var(--color-text-faint)' }}>days</span>
          </div>
        </div>
        <div className="space-y-1">
          <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>
            Suspicious Countries
          </label>
          <input type="text" className="input text-sm"
                 value={val('traffic_suspicious_countries')}
                 onChange={e => onchange('traffic_suspicious_countries', e.target.value)}
                 placeholder="CN,RU,KP — comma-separated ISO codes, blank to disable" />
        </div>
      </div>

      {/* ── Channels ─────────────────────────────────────────────── */}
      <SectionHeader label="Notification Channels" Icon={Bell} />
      <p className="text-xs -mt-1" style={{ color: 'var(--color-text-faint)' }}>
        Where notifications are sent. Powered by Apprise.
      </p>

      {loading
        ? <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>Loading…</p>
        : <>
            <div className="space-y-2">
              {channels.map(ch => (
                editingCh?.id === ch.id
                  ? <ChannelForm key={ch.id} initial={ch}
                      onSave={handleSaveCh}
                      onCancel={() => setEditingCh(null)} />
                  : <ChannelCard key={ch.id} channel={ch}
                      onEdit={c => { setEditingCh(c); setShowChForm(false) }}
                      onDelete={handleDeleteCh}
                      onTest={handleTestCh} />
              ))}
            </div>

            {showChForm && !editingCh && (
              <ChannelForm
                onSave={handleSaveCh}
                onCancel={() => setShowChForm(false)} />
            )}

            {!showChForm && !editingCh && (
              <button onClick={() => setShowChForm(true)}
                      className="btn-secondary text-sm flex items-center gap-1.5 w-full justify-center">
                <Plus size={13} /> Add channel
              </button>
            )}
          </>
      }

      {/* ── Profiles ─────────────────────────────────────────────── */}
      <SectionHeader label="Notification Profiles" Icon={Bell} />
      <p className="text-xs -mt-1" style={{ color: 'var(--color-text-faint)' }}>
        A profile links a set of events to one or more channels. Create multiple profiles
        for different urgency levels or audiences.
      </p>

      {loading
        ? <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>Loading…</p>
        : <>
            <div className="space-y-2">
              {profiles.map(pr => (
                editingPr?.id === pr.id
                  ? <ProfileEditor key={pr.id} initial={pr}
                      channels={channels} eventGroups={eventGroups}
                      onSave={handleSavePr}
                      onCancel={() => setEditingPr(null)} />
                  : <ProfileCard key={pr.id} profile={pr} channels={channels}
                      onEdit={p => { setEditingPr(p); setShowPrForm(false) }}
                      onDelete={handleDeletePr} />
              ))}
            </div>

            {showPrForm && !editingPr && (
              <ProfileEditor
                channels={channels} eventGroups={eventGroups}
                onSave={handleSavePr}
                onCancel={() => setShowPrForm(false)} />
            )}

            {!showPrForm && !editingPr && (
              <button onClick={() => setShowPrForm(true)}
                      className="btn-secondary text-sm flex items-center gap-1.5 w-full justify-center">
                <Plus size={13} /> Add profile
              </button>
            )}
          </>
      }
    </div>
  )
}
