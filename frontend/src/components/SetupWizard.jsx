import { useState, useEffect } from 'react'
import {
  User, Lock, Network, Shield, Bell, ArrowRight,
  CheckCircle, Eye, EyeOff, Upload, RotateCcw,
} from 'lucide-react'
import { Logo } from './Logo'
import { api, setToken } from '../api'

const STEPS = [
  { id: 'user',    label: 'Create Account',      Icon: User    },
  { id: 'restore', label: 'Restore Backup',       Icon: Upload  },
  { id: 'network', label: 'Network Settings',     Icon: Network },
  { id: 'vuln',    label: 'Vulnerability Scans',  Icon: Shield  },
  { id: 'notify',  label: 'Notifications',        Icon: Bell    },
  { id: 'done',    label: 'All Set!',             Icon: CheckCircle },
]

function StepDot({ step, current, completed }) {
  const isDone = completed > step
  const isCur  = current === step
  return (
    <div className="flex flex-col items-center gap-1">
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
    </div>
  )
}

// ── Step 1: Create user ────────────────────────────────────────────────────
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

// ── Step 2: Restore backup ─────────────────────────────────────────────────
function StepRestore({ onNext, onSkip }) {
  const [status, setStatus] = useState(null)
  const [loading, setLoading] = useState(false)

  async function handleFile(e) {
    const file = e.target.files?.[0]
    if (!file) return
    setLoading(true)
    setStatus(null)
    try {
      const result = await api.importRestore(file)
      setStatus({ ok: true, msg: `Restored: ${result.settings} settings, ${result.fingerprints_merged} fingerprints` })
    } catch (err) {
      setStatus({ ok: false, msg: 'Restore failed — invalid backup file.' })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
        If you have a backup from a previous InSpectre installation, you can restore it now.
        Device data and fingerprints will be merged; settings will be restored.
      </p>

      <label className={`flex flex-col items-center justify-center gap-3 border-2 border-dashed rounded-xl p-8 cursor-pointer transition-colors ${loading ? 'opacity-50 pointer-events-none' : ''}`}
        style={{ borderColor: 'var(--color-border)', background: 'var(--color-surface-offset)' }}>
        <Upload size={24} style={{ color: 'var(--color-text-muted)' }} />
        <span className="text-sm font-medium" style={{ color: 'var(--color-text-muted)' }}>
          {loading ? 'Restoring…' : 'Click to select backup file (inspectre_backup.json)'}
        </span>
        <input type="file" accept=".json" className="hidden" onChange={handleFile} />
      </label>

      {status && (
        <div className="text-xs px-3 py-2 rounded-lg"
          style={{ background: status.ok ? 'rgba(16,185,129,0.1)' : 'rgba(239,68,68,0.1)',
                   color: status.ok ? '#10b981' : '#ef4444' }}>
          {status.msg}
        </div>
      )}

      <div className="flex gap-3">
        <button onClick={onSkip} className="flex-1 py-2.5 rounded-xl text-sm font-medium border transition-colors"
          style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)', background: 'transparent' }}>
          Skip
        </button>
        <button onClick={onNext} className="flex-1 py-2.5 rounded-xl text-sm font-semibold flex items-center justify-center gap-2"
          style={{ background: 'var(--color-brand)', color: 'white' }}>
          Continue <ArrowRight size={14} />
        </button>
      </div>
    </div>
  )
}

// ── Step 3: Network settings ───────────────────────────────────────────────
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

// ── Step 4: Vulnerability scans ────────────────────────────────────────────
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

// ── Step 5: Notifications ──────────────────────────────────────────────────
function StepNotify({ onNext }) {
  const [toasts,    setToasts]    = useState(true)
  const [ntfyTopic, setNtfyTopic] = useState('')
  const [ntfyUrl,   setNtfyUrl]   = useState('https://ntfy.sh')

  function handleNext() {
    onNext({ notifications_enabled: toasts, ntfy_topic: ntfyTopic.trim(), ntfy_url: ntfyUrl.trim() })
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
        <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--color-text-muted)' }}>
          ntfy push notifications (optional)
        </p>
        <div>
          <label className="block text-xs font-medium mb-1" style={{ color: 'var(--color-text-muted)' }}>
            ntfy topic (leave blank to skip)
          </label>
          <input className="input w-full" placeholder="e.g. inspectre-alerts"
            value={ntfyTopic} onChange={e => setNtfyTopic(e.target.value)} />
        </div>
        {ntfyTopic && (
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--color-text-muted)' }}>
              ntfy server URL
            </label>
            <input className="input w-full" value={ntfyUrl} onChange={e => setNtfyUrl(e.target.value)} />
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

// ── Step 6: Done ───────────────────────────────────────────────────────────
function StepDone({ onFinish }) {
  const [loading, setLoading] = useState(false)

  async function handleFinish() {
    setLoading(true)
    // Complete is called by the wizard coordinator — just fire onFinish
    onFinish()
  }

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
      <button onClick={handleFinish} disabled={loading}
        className="w-full py-2.5 rounded-xl font-semibold text-sm"
        style={{ background: 'var(--color-brand)', color: 'white', opacity: loading ? 0.7 : 1 }}>
        {loading ? 'Finishing…' : 'Go to Dashboard'}
      </button>
    </div>
  )
}

// ── Main wizard ────────────────────────────────────────────────────────────
export function SetupWizard({ onComplete }) {
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
      })
    } catch (_) { /* ignore — dashboard still loads */ }
    onComplete()
  }

  const currentStep = STEPS[step]

  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-4"
         style={{ background: 'var(--color-bg)' }}>
      <div className="noise-overlay" />
      <div className="header-glow" />

      <div className="relative z-10 w-full max-w-md">
        <div className="flex flex-col items-center gap-2 mb-6">
          <Logo size={36} />
          <h1 className="text-xl font-bold" style={{ color: 'var(--color-text)' }}>Welcome to InSpectre</h1>
          <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>Initial setup — step {step + 1} of {STEPS.length}</p>
        </div>

        {/* Progress dots */}
        <div className="flex items-center justify-center gap-2 mb-6">
          {STEPS.map((s, i) => (
            <StepDot key={s.id} step={i} current={step} completed={step} />
          ))}
        </div>

        <div className="card p-6">
          <div className="flex items-center gap-2 mb-5">
            <currentStep.Icon size={18} style={{ color: 'var(--color-brand)' }} />
            <h2 className="text-base font-semibold" style={{ color: 'var(--color-text)' }}>
              {currentStep.label}
            </h2>
          </div>

          {step === 0 && <StepUser      onNext={handleNext} />}
          {step === 1 && <StepRestore   onNext={handleNext} onSkip={() => handleNext()} />}
          {step === 2 && <StepNetwork   onNext={handleNext} />}
          {step === 3 && <StepVuln      onNext={handleNext} />}
          {step === 4 && <StepNotify    onNext={handleNext} />}
          {step === 5 && <StepDone      onFinish={handleFinish} />}
        </div>
      </div>
    </div>
  )
}
