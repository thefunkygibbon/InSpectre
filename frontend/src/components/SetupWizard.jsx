import { useState, useEffect } from 'react'
import {
  User, Lock, Network, Shield, Bell, ArrowRight,
  CheckCircle, Eye, EyeOff, Upload, RotateCcw, Database,
  Box, Server, Plus, Loader2, Check,
} from 'lucide-react'
import { Logo } from './Logo'
import { api, setToken } from '../api'

// Steps for the "fresh setup" path only (restore path bypasses all of these)
const FRESH_STEPS = [
  { id: 'user',       label: 'Create Account',   Icon: User        },
  { id: 'network',    label: 'Network Settings', Icon: Network     },
  { id: 'vuln',       label: 'Vuln Scans',       Icon: Shield      },
  { id: 'notify',     label: 'Notifications',    Icon: Bell        },
  { id: 'containers', label: 'Container Hosts',  Icon: Box         },
  { id: 'done',       label: 'All Set!',         Icon: CheckCircle },
]

const WIZARD_HOST_TYPES = [
  { value: 'docker_local',  label: 'Docker — Local socket',  hint: 'Connects via unix socket (requires socket mount).' },
  { value: 'docker_remote', label: 'Docker — Remote TCP',    hint: 'Connects to a remote Docker daemon over TCP.' },
  { value: 'proxmox',       label: 'Proxmox VE',            hint: 'Connects to a Proxmox VE node via REST API.' },
]

function wizardDefaultUrl(type) {
  if (type === 'docker_local')  return 'unix:///var/run/docker.sock'
  if (type === 'docker_remote') return 'tcp://192.168.1.x:2375'
  if (type === 'proxmox')       return 'https://192.168.1.x:8006'
  return ''
}

function StepDot({ step, current, completed }) {
  const isDone = completed > step
  const isCur  = current === step
  return (
    <div
      className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold transition-all"
      style={{
        background: isDone ? '#10b981' : isCur ? 'var(--color-brand)' : 'var(--color-surface-offset)',
        color: isDone || isCur ? 'white' : 'var(--color-text-muted)',
        border: isCur ? '2px solid var(--color-brand)' : 'none',
      }}
    >
      {isDone ? <CheckCircle size={14} /> : step + 1}
    </div>
  )
}

// ── Choice screen ──────────────────────────────────────────────────────────
function ChoiceScreen({ onFresh, onRestore }) {
  return (
    <div className="space-y-4">
      <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
        Is this a new installation or are you migrating from an existing one?
      </p>

      <button
        onClick={onFresh}
        className="w-full p-4 rounded-xl border-2 text-left flex items-start gap-4 transition-colors hover:border-[var(--color-brand)]"
        style={{ borderColor: 'var(--color-border)', background: 'var(--color-surface-offset)' }}
      >
        <User size={22} className="mt-0.5 shrink-0" style={{ color: 'var(--color-brand)' }} />
        <div>
          <p className="font-semibold text-sm" style={{ color: 'var(--color-text)' }}>Start fresh</p>
          <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-muted)' }}>
            New installation — create a new admin account and configure settings.
          </p>
        </div>
      </button>

      <button
        onClick={onRestore}
        className="w-full p-4 rounded-xl border-2 text-left flex items-start gap-4 transition-colors hover:border-[var(--color-brand)]"
        style={{ borderColor: 'var(--color-border)', background: 'var(--color-surface-offset)' }}
      >
        <Database size={22} className="mt-0.5 shrink-0" style={{ color: 'var(--color-brand)' }} />
        <div>
          <p className="font-semibold text-sm" style={{ color: 'var(--color-text)' }}>Restore from backup</p>
          <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-muted)' }}>
            Import a backup file — restores all devices, settings, history, and credentials.
          </p>
        </div>
      </button>
    </div>
  )
}

// ── Restore path ───────────────────────────────────────────────────────────
function RestorePath({ onComplete, onBack }) {
  const [status,  setStatus]  = useState(null)   // null | {ok, msg, stats}
  const [loading, setLoading] = useState(false)

  async function handleFile(e) {
    const file = e.target.files?.[0]
    if (!file) return
    setLoading(true)
    setStatus(null)
    try {
      const result = await api.setupRestoreFromBackup(file)
      const r = result.restored ?? {}
      setStatus({
        ok: true,
        msg: `Restored successfully — ${r.devices ?? 0} devices, ${r.settings ?? 0} settings, `
           + `${r.device_events ?? 0} events, ${r.vuln_reports ?? 0} vuln reports.`,
      })
    } catch (err) {
      setStatus({ ok: false, msg: 'Restore failed — invalid or incompatible backup file.' })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
        Select your <code className="text-xs px-1 py-0.5 rounded" style={{ background: 'var(--color-surface-offset)' }}>inspectre_backup.json</code> file.
        All devices, settings, timelines, vuln history, and your login credentials will be restored.
      </p>

      {!status?.ok && (
        <label
          className={`flex flex-col items-center justify-center gap-3 border-2 border-dashed rounded-xl p-8 cursor-pointer transition-colors ${loading ? 'opacity-50 pointer-events-none' : ''}`}
          style={{ borderColor: 'var(--color-border)', background: 'var(--color-surface-offset)' }}
        >
          <Upload size={24} style={{ color: 'var(--color-text-muted)' }} />
          <span className="text-sm font-medium text-center" style={{ color: 'var(--color-text-muted)' }}>
            {loading ? 'Restoring…' : 'Click to select backup file'}
          </span>
          <input type="file" accept=".json" className="hidden" onChange={handleFile} disabled={loading} />
        </label>
      )}

      {status && (
        <div className="px-4 py-3 rounded-xl space-y-1"
          style={{ background: status.ok ? 'rgba(16,185,129,0.1)' : 'rgba(239,68,68,0.1)',
                   border: `1px solid ${status.ok ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)'}` }}>
          <p className="text-sm font-semibold" style={{ color: status.ok ? '#10b981' : '#ef4444' }}>
            {status.ok ? 'Restore complete' : 'Restore failed'}
          </p>
          <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>{status.msg}</p>
          {status.ok && (
            <p className="text-xs mt-1" style={{ color: 'var(--color-text-faint)' }}>
              Please log in using your previous credentials.
            </p>
          )}
        </div>
      )}

      <div className="flex gap-3">
        {!status?.ok && (
          <button
            onClick={onBack}
            className="py-2.5 px-4 rounded-xl text-sm font-medium border transition-colors"
            style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)', background: 'transparent' }}
            disabled={loading}
          >
            Back
          </button>
        )}
        {status?.ok && (
          <button
            onClick={onComplete}
            className="w-full py-2.5 rounded-xl font-semibold text-sm flex items-center justify-center gap-2"
            style={{ background: 'var(--color-brand)', color: 'white' }}
          >
            Go to Login <ArrowRight size={14} />
          </button>
        )}
      </div>
    </div>
  )
}

// ── Fresh path steps ───────────────────────────────────────────────────────

function StepUser({ onNext }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirm,  setConfirm]  = useState('')
  const [showPw,   setShowPw]   = useState(false)
  const [error,    setError]    = useState('')
  const [loading,  setLoading]  = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    if (username.trim().length < 3) { setError('Username must be at least 3 characters'); return }
    if (password.length < 8)        { setError('Password must be at least 8 characters'); return }
    if (password !== confirm)        { setError('Passwords do not match'); return }
    setLoading(true)
    try {
      const data = await api.setupCreateUser(username.trim().toLowerCase(), password)
      setToken(data.token)
      onNext({ username: data.username })
    } catch (err) {
      setError(err.message?.includes('403') ? 'User already exists — please log in instead.' : 'Failed to create user.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
        Create the administrator account for InSpectre. You'll use these credentials to log in.
      </p>

      <div className="space-y-3">
        <div className="relative">
          <User size={14} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
            style={{ color: 'var(--color-text-muted)' }} />
          <input className="input pl-9 w-full" placeholder="Username (min 3 chars)"
            value={username} onChange={e => setUsername(e.target.value)} disabled={loading} />
        </div>

        <div className="relative">
          <Lock size={14} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
            style={{ color: 'var(--color-text-muted)' }} />
          <input className="input pl-9 pr-10 w-full" placeholder="Password (min 8 chars)"
            type={showPw ? 'text' : 'password'}
            value={password} onChange={e => setPassword(e.target.value)} disabled={loading} />
          <button type="button" onClick={() => setShowPw(v => !v)}
            className="absolute right-3 top-1/2 -translate-y-1/2 opacity-50 hover:opacity-100 transition-opacity" tabIndex={-1}>
            {showPw ? <EyeOff size={14} /> : <Eye size={14} />}
          </button>
        </div>

        <input className="input w-full" placeholder="Confirm password"
          type="password" value={confirm} onChange={e => setConfirm(e.target.value)} disabled={loading} />
      </div>

      {error && <p className="text-xs" style={{ color: '#ef4444' }}>{error}</p>}

      <button type="submit" disabled={loading}
        className="w-full py-2.5 rounded-xl font-semibold text-sm flex items-center justify-center gap-2"
        style={{ background: 'var(--color-brand)', color: 'white', opacity: loading ? 0.7 : 1 }}>
        {loading ? 'Creating…' : <><span>Create Account</span><ArrowRight size={14} /></>}
      </button>
    </form>
  )
}

function StepNetwork({ onNext }) {
  const [ipRange,   setIpRange]   = useState('')
  const [dns,       setDns]       = useState('')
  const [gateway,   setGateway]   = useState('')
  const [loading,   setLoading]   = useState(false)
  const [detecting, setDetecting] = useState(true)
  const [error,     setError]     = useState('')

  useEffect(() => {
    api.setupNetworkInfo().then(info => {
      if (info.ip_range)   setIpRange(info.ip_range)
      if (info.dns_server) setDns(info.dns_server)
      if (info.gateway)    setGateway(info.gateway)
    }).catch(() => {}).finally(() => setDetecting(false))
  }, [])

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    if (!ipRange.trim()) { setError('IP range is required'); return }
    setLoading(true)
    try {
      await api.setupApplyNetwork({ ip_range: ipRange.trim(), dns_server: dns.trim(), gateway: gateway.trim() })
      onNext({ ip_range: ipRange.trim(), dns_server: dns.trim() })
    } catch (err) {
      setError('Failed to save network settings.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
        Confirm the network range InSpectre will scan. These have been auto-detected from your network interface.
      </p>

      {detecting && (
        <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
          <RotateCcw size={12} className="inline mr-1 animate-spin" />Detecting network…
        </p>
      )}

      <div className="space-y-3">
        <div>
          <label className="block text-xs font-medium mb-1" style={{ color: 'var(--color-text-muted)' }}>
            Scan Range (CIDR)
          </label>
          <input className="input w-full" placeholder="e.g. 192.168.1.0/24"
            value={ipRange} onChange={e => setIpRange(e.target.value)} disabled={loading} />
        </div>
        <div>
          <label className="block text-xs font-medium mb-1" style={{ color: 'var(--color-text-muted)' }}>
            DNS Server / Gateway IP
          </label>
          <input className="input w-full" placeholder="e.g. 192.168.1.1"
            value={dns} onChange={e => setDns(e.target.value)} disabled={loading} />
          <p className="text-xs mt-1" style={{ color: 'var(--color-text-faint)' }}>
            Used for hostname resolution. Your router's IP is usually correct.
          </p>
        </div>
        <div>
          <label className="block text-xs font-medium mb-1" style={{ color: 'var(--color-text-muted)' }}>
            Gateway IP (for ARP blocking)
          </label>
          <input className="input w-full" placeholder="e.g. 192.168.1.1"
            value={gateway} onChange={e => setGateway(e.target.value)} disabled={loading} />
        </div>
      </div>

      {error && <p className="text-xs" style={{ color: '#ef4444' }}>{error}</p>}

      <button type="submit" disabled={loading}
        className="w-full py-2.5 rounded-xl font-semibold text-sm flex items-center justify-center gap-2"
        style={{ background: 'var(--color-brand)', color: 'white', opacity: loading ? 0.7 : 1 }}>
        {loading ? 'Saving…' : <><span>Confirm Network</span><ArrowRight size={14} /></>}
      </button>
    </form>
  )
}

function StepVuln({ onNext }) {
  const [enabled,  setEnabled]  = useState(false)
  const [schedule, setSchedule] = useState('24h')
  const [onNew,    setOnNew]    = useState(false)

  function handleNext() {
    onNext({ vuln_scan_enabled: enabled, vuln_scan_schedule: schedule, vuln_scan_on_new: onNew })
  }

  return (
    <div className="space-y-5">
      <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
        InSpectre can run vulnerability scans against discovered devices using Nuclei templates.
        You can change these at any time in Settings.
      </p>

      <label className="flex items-start gap-3 cursor-pointer p-3 rounded-xl border transition-colors"
        style={{
          borderColor: enabled ? 'var(--color-brand)' : 'var(--color-border)',
          background: enabled ? 'rgba(99,102,241,0.06)' : 'transparent',
        }}>
        <input type="checkbox" className="mt-0.5" checked={enabled}
          onChange={e => setEnabled(e.target.checked)} />
        <div>
          <p className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>Enable vulnerability scanning</p>
          <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-muted)' }}>
            Checks devices for known CVEs, misconfigurations, and exposed services.
          </p>
        </div>
      </label>

      {enabled && (
        <div className="space-y-3 pl-1">
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--color-text-muted)' }}>
              Scan schedule
            </label>
            <select className="input w-full" value={schedule} onChange={e => setSchedule(e.target.value)}>
              <option value="disabled">Disabled (manual only)</option>
              <option value="6h">Every 6 hours</option>
              <option value="12h">Every 12 hours</option>
              <option value="24h">Daily</option>
              <option value="weekly">Weekly</option>
            </select>
          </div>

          <label className="flex items-center gap-3 cursor-pointer">
            <input type="checkbox" checked={onNew} onChange={e => setOnNew(e.target.checked)} />
            <div>
              <p className="text-xs font-medium" style={{ color: 'var(--color-text)' }}>Scan new devices automatically</p>
              <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                Runs a vuln scan when a new device joins the network.
              </p>
            </div>
          </label>
        </div>
      )}

      <button onClick={handleNext}
        className="w-full py-2.5 rounded-xl font-semibold text-sm flex items-center justify-center gap-2"
        style={{ background: 'var(--color-brand)', color: 'white' }}>
        Continue <ArrowRight size={14} />
      </button>
    </div>
  )
}

function StepNotify({ onNext }) {
  const [toasts,      setToasts]      = useState(true)
  const [provider,    setProvider]    = useState('None')
  const [ntfyTopic,   setNtfyTopic]   = useState('')
  const [ntfyUrl,     setNtfyUrl]     = useState('https://ntfy.sh')
  const [gotifyUrl,   setGotifyUrl]   = useState('')
  const [gotifyToken, setGotifyToken] = useState('')
  const [pbKey,       setPbKey]       = useState('')
  const [webhookUrl,  setWebhookUrl]  = useState('')

  function handleNext() {
    const data = { notifications_enabled: toasts }
    if (provider === 'ntfy') {
      data.ntfy_topic = ntfyTopic.trim()
      data.ntfy_url   = ntfyUrl.trim()
    } else if (provider === 'Gotify') {
      data.gotify_url   = gotifyUrl.trim()
      data.gotify_token = gotifyToken.trim()
    } else if (provider === 'Pushbullet') {
      data.pushbullet_api_key = pbKey.trim()
    } else if (provider === 'Webhook') {
      data.alert_webhook_url = webhookUrl.trim()
    }
    onNext(data)
  }

  return (
    <div className="space-y-5">
      <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
        Choose how you'd like to be notified about new devices and security events.
        These can be changed later in Settings → Notifications.
      </p>

      <label className="flex items-center gap-3 cursor-pointer p-3 rounded-xl border"
        style={{ borderColor: 'var(--color-border)' }}>
        <input type="checkbox" checked={toasts} onChange={e => setToasts(e.target.checked)} />
        <div>
          <p className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>In-app toast notifications</p>
          <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>Show alerts in the browser UI.</p>
        </div>
      </label>

      <div className="space-y-3">
        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider mb-1.5" style={{ color: 'var(--color-text-muted)' }}>
            Push notification provider
          </label>
          <select className="input w-full" value={provider} onChange={e => setProvider(e.target.value)}>
            <option value="None">None</option>
            <option value="ntfy">ntfy</option>
            <option value="Gotify">Gotify</option>
            <option value="Pushbullet">Pushbullet</option>
            <option value="Webhook">Webhook</option>
          </select>
        </div>

        {provider === 'ntfy' && (
          <>
            <div>
              <label className="block text-xs font-medium mb-1" style={{ color: 'var(--color-text-muted)' }}>
                ntfy topic
              </label>
              <input className="input w-full" placeholder="e.g. inspectre-alerts"
                value={ntfyTopic} onChange={e => setNtfyTopic(e.target.value)} />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1" style={{ color: 'var(--color-text-muted)' }}>
                ntfy server URL
              </label>
              <input className="input w-full" value={ntfyUrl} onChange={e => setNtfyUrl(e.target.value)} />
            </div>
          </>
        )}

        {provider === 'Gotify' && (
          <>
            <div>
              <label className="block text-xs font-medium mb-1" style={{ color: 'var(--color-text-muted)' }}>
                Gotify server URL
              </label>
              <input className="input w-full" placeholder="https://gotify.example.com"
                value={gotifyUrl} onChange={e => setGotifyUrl(e.target.value)} />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1" style={{ color: 'var(--color-text-muted)' }}>
                App token
              </label>
              <input className="input w-full font-mono" placeholder="A1b2C3d4…"
                value={gotifyToken} onChange={e => setGotifyToken(e.target.value)} />
            </div>
          </>
        )}

        {provider === 'Pushbullet' && (
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--color-text-muted)' }}>
              Pushbullet API key
            </label>
            <input className="input w-full font-mono" placeholder="o.XXXXXXXXXXXXXXXXXXXXXXXX"
              value={pbKey} onChange={e => setPbKey(e.target.value)} />
          </div>
        )}

        {provider === 'Webhook' && (
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--color-text-muted)' }}>
              Webhook URL
            </label>
            <input type="url" className="input w-full" placeholder="https://example.com/webhook"
              value={webhookUrl} onChange={e => setWebhookUrl(e.target.value)} />
          </div>
        )}
      </div>

      <button onClick={handleNext}
        className="w-full py-2.5 rounded-xl font-semibold text-sm flex items-center justify-center gap-2"
        style={{ background: 'var(--color-brand)', color: 'white' }}>
        Continue <ArrowRight size={14} />
      </button>
    </div>
  )
}

function StepContainers({ onNext }) {
  const [hosts,     setHosts]     = useState([])
  const [type,      setType]      = useState('docker_local')
  const [name,      setName]      = useState('')
  const [url,       setUrl]       = useState(wizardDefaultUrl('docker_local'))
  const [authUser,  setAuthUser]  = useState('')
  const [authToken, setAuthToken] = useState('')
  const [tlsVerify, setTlsVerify] = useState(false)
  const [node,      setNode]      = useState('pve')
  const [adding,    setAdding]    = useState(false)
  const [error,     setError]     = useState('')

  function handleTypeChange(t) {
    setType(t)
    setUrl(wizardDefaultUrl(t))
  }

  async function handleAdd() {
    setError('')
    if (!name.trim()) { setError('Name is required.'); return }
    if (type !== 'docker_local' && !url.trim()) { setError('URL is required.'); return }
    if (type === 'proxmox' && !authUser.trim()) { setError('Token ID is required.'); return }
    const body = {
      name: name.trim(), type, url: url.trim() || null,
      auth_user: authUser.trim() || null,
      tls_verify: tlsVerify, node: node.trim() || 'pve', enabled: true,
    }
    if (authToken) body.auth_token = authToken
    setAdding(true)
    try {
      const created = await api.createContainerHost(body)
      setHosts(prev => [...prev, created])
      setName(''); setAuthUser(''); setAuthToken('')
      setTlsVerify(false); setNode('pve')
      setUrl(wizardDefaultUrl(type))
    } catch (e) {
      setError(`Failed to add host: ${e.message}`)
    } finally {
      setAdding(false)
    }
  }

  const TypeIcon = type === 'docker_local' ? Box : Server

  return (
    <div className="space-y-4">
      <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
        Optionally connect Docker or Proxmox hosts to monitor running containers.
        You can add or change these later in Settings → Docker.
      </p>

      {/* Added hosts list */}
      {hosts.length > 0 && (
        <div className="space-y-1.5">
          {hosts.map(h => (
            <div key={h.id} className="flex items-center gap-2 px-3 py-2 rounded-xl text-xs"
              style={{ background: 'var(--color-surface-offset)', border: '1px solid var(--color-border)' }}>
              <Check size={12} style={{ color: '#10b981' }} />
              <span style={{ color: 'var(--color-text)' }}>{h.name}</span>
              <span style={{ color: 'var(--color-text-faint)' }}>
                ({WIZARD_HOST_TYPES.find(t => t.value === h.type)?.label})
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Add host form */}
      <div className="space-y-3 p-4 rounded-xl border"
        style={{ background: 'var(--color-surface-offset)', borderColor: 'var(--color-border)' }}>

        <div className="space-y-1">
          <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Host Type</label>
          <select className="input w-full text-sm" value={type} onChange={e => handleTypeChange(e.target.value)}>
            {WIZARD_HOST_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
          </select>
          <p className="text-[11px]" style={{ color: 'var(--color-text-faint)' }}>
            {WIZARD_HOST_TYPES.find(t => t.value === type)?.hint}
          </p>
        </div>

        <div className="space-y-1">
          <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Display Name</label>
          <input className="input w-full text-sm" placeholder="e.g. Home Server"
            value={name} onChange={e => setName(e.target.value)} />
        </div>

        {type === 'docker_local' && (
          <div className="space-y-1">
            <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Socket Path</label>
            <input className="input w-full font-mono text-sm" value={url}
              onChange={e => setUrl(e.target.value)} placeholder="unix:///var/run/docker.sock" />
          </div>
        )}

        {type !== 'docker_local' && (
          <div className="space-y-1">
            <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>
              {type === 'proxmox' ? 'Proxmox URL' : 'Docker TCP URL'}
            </label>
            <input className="input w-full font-mono text-sm" value={url}
              onChange={e => setUrl(e.target.value)} placeholder={wizardDefaultUrl(type)} />
          </div>
        )}

        {type === 'proxmox' && (
          <>
            <div className="space-y-1">
              <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>
                Token ID <span className="font-mono">(user@realm!tokenname)</span>
              </label>
              <input className="input w-full font-mono text-sm" value={authUser}
                onChange={e => setAuthUser(e.target.value)} placeholder="root@pam!mytoken" />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>
                Token Secret <span className="font-mono">(UUID)</span>
              </label>
              <input className="input w-full font-mono text-sm" type="password"
                value={authToken} onChange={e => setAuthToken(e.target.value)}
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Default Node</label>
              <input className="input w-full font-mono text-sm" value={node}
                onChange={e => setNode(e.target.value)} placeholder="pve" />
            </div>
          </>
        )}

        {(type === 'docker_remote' || type === 'proxmox') && (
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>Verify TLS</p>
              <p className="text-[11px]" style={{ color: 'var(--color-text-faint)' }}>
                Disable for self-signed certs on trusted LANs.
              </p>
            </div>
            <button type="button" role="switch" aria-checked={tlsVerify}
              onClick={() => setTlsVerify(v => !v)}
              className="relative inline-flex h-5 w-9 items-center rounded-full transition-colors shrink-0"
              style={{ background: tlsVerify ? 'var(--color-brand)' : 'var(--color-border)' }}>
              <span className="inline-block h-3.5 w-3.5 rounded-full bg-white shadow transition-transform"
                style={{ transform: tlsVerify ? 'translateX(19px)' : 'translateX(3px)' }} />
            </button>
          </div>
        )}

        {error && <p className="text-xs" style={{ color: '#ef4444' }}>{error}</p>}

        <button onClick={handleAdd} disabled={adding}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-white disabled:opacity-50"
          style={{ background: 'var(--color-brand)' }}>
          {adding
            ? <><Loader2 size={12} className="animate-spin" /> Adding…</>
            : <><Plus size={12} /> Add Host</>}
        </button>
      </div>

      <button onClick={() => onNext({})}
        className="w-full py-2.5 rounded-xl font-semibold text-sm flex items-center justify-center gap-2"
        style={{ background: 'var(--color-brand)', color: 'white' }}>
        {hosts.length > 0 ? 'Continue' : 'Skip'} <ArrowRight size={14} />
      </button>
    </div>
  )
}

function StepDone({ onFinish }) {
  return (
    <div className="space-y-6 text-center">
      <div className="flex justify-center">
        <CheckCircle size={56} style={{ color: '#10b981' }} />
      </div>
      <div>
        <h3 className="text-lg font-bold" style={{ color: 'var(--color-text)' }}>You're all set!</h3>
        <p className="text-sm mt-2" style={{ color: 'var(--color-text-muted)' }}>
          InSpectre is configured and ready. It will start scanning your network shortly.
          You can adjust any of these settings later from the Settings panel.
        </p>
      </div>
      <button onClick={onFinish}
        className="w-full py-2.5 rounded-xl font-semibold text-sm"
        style={{ background: 'var(--color-brand)', color: 'white' }}>
        Go to Dashboard
      </button>
    </div>
  )
}

// ── Main wizard ────────────────────────────────────────────────────────────
export function SetupWizard({ onComplete }) {
  // mode: null = choice screen, 'restore' = restore path, 'fresh' = fresh setup path
  const [mode,      setMode]      = useState(null)
  const [step,      setStep]      = useState(0)
  const [collected, setCollected] = useState({})

  function handleNext(data = {}) {
    setCollected(prev => ({ ...prev, ...data }))
    setStep(s => s + 1)
  }

  async function handleFinish() {
    try {
      await api.setupComplete({
        vuln_scan_enabled:     collected.vuln_scan_enabled    ?? false,
        vuln_scan_schedule:    collected.vuln_scan_schedule   ?? 'disabled',
        vuln_scan_on_new:      collected.vuln_scan_on_new     ?? false,
        notifications_enabled: collected.notifications_enabled ?? true,
        ntfy_topic:            collected.ntfy_topic            ?? '',
        ntfy_url:              collected.ntfy_url              ?? 'https://ntfy.sh',
        gotify_url:            collected.gotify_url            ?? '',
        gotify_token:          collected.gotify_token          ?? '',
        pushbullet_api_key:    collected.pushbullet_api_key    ?? '',
        alert_webhook_url:     collected.alert_webhook_url     ?? '',
      })
    } catch (_) { /* ignore — dashboard still loads */ }
    onComplete()
  }

  // Determine header content
  const isChoice = mode === null
  const isRestore = mode === 'restore'
  const isFresh = mode === 'fresh'
  const currentStep = isFresh ? FRESH_STEPS[step] : null

  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-4"
         style={{ background: 'var(--color-bg)' }}>
      <div className="noise-overlay" />
      <div className="header-glow" />

      <div className="relative z-10 w-full max-w-md">
        <div className="flex flex-col items-center gap-2 mb-6">
          <Logo size={36} />
          <h1 className="text-xl font-bold" style={{ color: 'var(--color-text)' }}>Welcome to InSpectre</h1>
          {isChoice && (
            <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>How would you like to get started?</p>
          )}
          {isRestore && (
            <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>Restoring from backup</p>
          )}
          {isFresh && (
            <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>Initial setup — step {step + 1} of {FRESH_STEPS.length}</p>
          )}
        </div>

        {/* Progress dots — only for fresh path */}
        {isFresh && (
          <div className="flex items-center justify-center gap-2 mb-6">
            {FRESH_STEPS.map((s, i) => (
              <StepDot key={s.id} step={i} current={step} completed={step} />
            ))}
          </div>
        )}

        <div className="card p-6">
          {/* Card header */}
          <div className="flex items-center gap-2 mb-5">
            {isChoice  && <Database  size={18} style={{ color: 'var(--color-brand)' }} />}
            {isRestore && <Upload    size={18} style={{ color: 'var(--color-brand)' }} />}
            {isFresh   && currentStep && <currentStep.Icon size={18} style={{ color: 'var(--color-brand)' }} />}
            <h2 className="text-base font-semibold" style={{ color: 'var(--color-text)' }}>
              {isChoice  ? 'Get started'           : ''}
              {isRestore ? 'Restore from backup'   : ''}
              {isFresh   ? currentStep?.label      : ''}
            </h2>
          </div>

          {/* Choice screen */}
          {isChoice && (
            <ChoiceScreen
              onFresh={() => setMode('fresh')}
              onRestore={() => setMode('restore')}
            />
          )}

          {/* Restore path */}
          {isRestore && (
            <RestorePath
              onComplete={onComplete}
              onBack={() => setMode(null)}
            />
          )}

          {/* Fresh setup steps */}
          {isFresh && step === 0 && <StepUser       onNext={handleNext} />}
          {isFresh && step === 1 && <StepNetwork    onNext={handleNext} />}
          {isFresh && step === 2 && <StepVuln       onNext={handleNext} />}
          {isFresh && step === 3 && <StepNotify     onNext={handleNext} />}
          {isFresh && step === 4 && <StepContainers onNext={handleNext} />}
          {isFresh && step === 5 && <StepDone       onFinish={handleFinish} />}
        </div>
      </div>
    </div>
  )
}
