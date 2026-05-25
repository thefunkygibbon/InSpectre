import { useState, useEffect } from 'react'
import {
  Plus, Trash2, Edit2, Check, X, Loader2, Wifi, WifiOff,
  Box, Server, ChevronDown, ChevronRight,
} from 'lucide-react'
import { api } from '../api'

const HOST_TYPES = [
  { value: 'docker_local',  label: 'Docker — Local socket',   hint: 'Connects via unix socket (requires socket mount).' },
  { value: 'docker_remote', label: 'Docker — Remote TCP',      hint: 'Connects to a remote Docker daemon over TCP.' },
  { value: 'proxmox',       label: 'Proxmox VE',              hint: 'Connects to a Proxmox VE node via REST API.' },
]

const TYPE_ICON = {
  docker_local:  Box,
  docker_remote: Server,
  proxmox:       Server,
}

const TYPE_COLOR = {
  docker_local:  '#3b82f6',
  docker_remote: '#6366f1',
  proxmox:       '#f59e0b',
}

function defaultUrl(type) {
  if (type === 'docker_local')  return 'unix:///var/run/docker.sock'
  if (type === 'docker_remote') return 'tcp://192.168.1.x:2375'
  if (type === 'proxmox')       return 'https://192.168.1.x:8006'
  return ''
}

function HostForm({ initial, onSave, onCancel, saving }) {
  const [name,      setName]      = useState(initial?.name      || '')
  const [type,      setType]      = useState(initial?.type      || 'docker_local')
  const [url,       setUrl]       = useState(initial?.url       || defaultUrl(initial?.type || 'docker_local'))
  const [authUser,  setAuthUser]  = useState(initial?.auth_user || '')
  const [authToken, setAuthToken] = useState('')  // never pre-fill token
  const [tlsVerify, setTlsVerify] = useState(initial?.tls_verify || false)
  const [node,      setNode]      = useState(initial?.node      || 'pve')
  const [localIp,   setLocalIp]   = useState(initial?.local_ip  || '')
  const [error,     setError]     = useState('')

  function handleTypeChange(t) {
    setType(t)
    if (!initial) setUrl(defaultUrl(t))
  }

  function handleSubmit(e) {
    e.preventDefault()
    setError('')
    if (!name.trim()) { setError('Name is required.'); return }
    if (type !== 'docker_local' && !url.trim()) { setError('URL is required.'); return }
    if (type === 'proxmox' && !authUser.trim()) { setError('Token ID (e.g. root@pam!mytoken) is required.'); return }
    const body = {
      name: name.trim(), type, url: url.trim() || null,
      auth_user: authUser.trim() || null,
      tls_verify: tlsVerify, node: node.trim() || 'pve', enabled: true,
      local_ip: localIp.trim() || null,
    }
    if (authToken) body.auth_token = authToken
    onSave(body)
  }

  const isDocker  = type.startsWith('docker')
  const isProxmox = type === 'proxmox'

  return (
    <form onSubmit={handleSubmit} className="space-y-3 p-4 rounded-xl border"
      style={{ background: 'var(--color-surface-offset)', borderColor: 'var(--color-border)' }}>

      {/* Name */}
      <div className="space-y-1">
        <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Display Name</label>
        <input className="input w-full" placeholder="e.g. Home Server" value={name} onChange={e => setName(e.target.value)} />
      </div>

      {/* Local IP */}
      <div className="space-y-1">
        <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Local IP Address</label>
        <input className="input w-full font-mono text-sm" placeholder="e.g. 192.168.1.10" value={localIp} onChange={e => setLocalIp(e.target.value)} />
        <p className="text-[11px]" style={{ color: 'var(--color-text-faint)' }}>
          Internal IP of the Docker/Proxmox host. Used for port links in the dashboard.
        </p>
      </div>

      {/* Type */}
      <div className="space-y-1">
        <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Host Type</label>
        <select className="input w-full" value={type} onChange={e => handleTypeChange(e.target.value)}>
          {HOST_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
        </select>
        <p className="text-[11px]" style={{ color: 'var(--color-text-faint)' }}>
          {HOST_TYPES.find(t => t.value === type)?.hint}
        </p>
      </div>

      {/* URL */}
      {type !== 'docker_local' && (
        <div className="space-y-1">
          <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>
            {isProxmox ? 'Proxmox URL' : 'Docker TCP URL'}
          </label>
          <input className="input w-full font-mono text-sm" value={url}
            onChange={e => setUrl(e.target.value)}
            placeholder={defaultUrl(type)} />
        </div>
      )}
      {type === 'docker_local' && (
        <div className="space-y-1">
          <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Socket Path</label>
          <input className="input w-full font-mono text-sm" value={url}
            onChange={e => setUrl(e.target.value)}
            placeholder="unix:///var/run/docker.sock" />
        </div>
      )}

      {/* Proxmox credentials */}
      {isProxmox && (
        <>
          <div className="space-y-1">
            <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>
              Token ID <span className="font-mono">(user@realm!tokenname)</span>
            </label>
            <input className="input w-full font-mono text-sm" value={authUser}
              onChange={e => setAuthUser(e.target.value)} placeholder="root@pam!mytoken" />
            <p className="text-[11px]" style={{ color: 'var(--color-text-faint)' }}>
              The Token ID shown in Datacenter → API Tokens in the Proxmox UI.
            </p>
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>
              Token Secret <span className="font-mono">(UUID)</span>
            </label>
            <input className="input w-full font-mono text-sm" type="password"
              value={authToken} onChange={e => setAuthToken(e.target.value)}
              placeholder={initial ? '(unchanged)' : 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'} />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Default Node</label>
            <input className="input w-full font-mono text-sm" value={node}
              onChange={e => setNode(e.target.value)} placeholder="pve" />
          </div>
        </>
      )}

      {/* TLS verify (Docker TCP and Proxmox) */}
      {(type === 'docker_remote' || isProxmox) && (
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

      <div className="flex gap-2 pt-1">
        <button type="submit" disabled={saving}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-white disabled:opacity-50"
          style={{ background: 'var(--color-brand)' }}>
          {saving ? <Loader2 size={12} className="animate-spin" /> : <Check size={12} />}
          {saving ? 'Saving…' : initial ? 'Update Host' : 'Add Host'}
        </button>
        <button type="button" onClick={onCancel}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border"
          style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}>
          <X size={12} /> Cancel
        </button>
      </div>
    </form>
  )
}

function HostRow({ host, onEdit, onDelete, onToggle }) {
  const [testing,    setTesting]    = useState(false)
  const [testResult, setTestResult] = useState(null)
  const [deleting,   setDeleting]   = useState(false)
  const Icon = TYPE_ICON[host.type] || Server
  const color = TYPE_COLOR[host.type] || '#6b7280'

  async function handleTest() {
    setTesting(true)
    setTestResult(null)
    try {
      const r = await api.testContainerHost(host.id)
      setTestResult(r)
    } catch (e) {
      setTestResult({ ok: false, detail: e.message })
    } finally {
      setTesting(false)
    }
  }

  async function handleDelete() {
    if (!confirm(`Remove host "${host.name}"? This cannot be undone.`)) return
    setDeleting(true)
    try {
      await api.deleteContainerHost(host.id)
      onDelete(host.id)
    } finally {
      setDeleting(false)
    }
  }

  return (
    <div className="card overflow-hidden">
      <div className="p-3 flex items-center gap-3">
        <span className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0"
          style={{ background: `${color}20` }}>
          <Icon size={14} style={{ color }} />
        </span>

        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium truncate" style={{ color: 'var(--color-text)' }}>{host.name}</p>
          <p className="text-[10px] font-mono truncate" style={{ color: 'var(--color-text-faint)' }}>
            {HOST_TYPES.find(t => t.value === host.type)?.label}
            {host.url && ` · ${host.url}`}
          </p>
        </div>

        {/* Enabled toggle */}
        <button type="button" role="switch" aria-checked={host.enabled}
          onClick={() => onToggle(host.id, !host.enabled)}
          className="relative inline-flex h-5 w-9 items-center rounded-full transition-colors shrink-0"
          style={{ background: host.enabled ? 'var(--color-brand)' : 'var(--color-border)' }}>
          <span className="inline-block h-3.5 w-3.5 rounded-full bg-white shadow transition-transform"
            style={{ transform: host.enabled ? 'translateX(19px)' : 'translateX(3px)' }} />
        </button>

        {/* Actions */}
        <div className="flex items-center gap-1 shrink-0">
          <button onClick={handleTest} disabled={testing} title="Test connection"
            className="btn-ghost p-1.5" style={{ color: testing ? 'var(--color-text-faint)' : undefined }}>
            {testing ? <Loader2 size={13} className="animate-spin" /> : <Wifi size={13} />}
          </button>
          <button onClick={onEdit} title="Edit" className="btn-ghost p-1.5">
            <Edit2 size={13} />
          </button>
          <button onClick={handleDelete} disabled={deleting} title="Remove"
            className="btn-ghost p-1.5 hover:text-red-400 transition-colors">
            {deleting ? <Loader2 size={13} className="animate-spin" /> : <Trash2 size={13} />}
          </button>
        </div>
      </div>

      {testResult && (
        <div className="px-3 pb-2.5 text-[11px]"
          style={{ color: testResult.ok ? '#22c55e' : '#ef4444' }}>
          {testResult.ok ? '✓' : '✗'} {testResult.detail}
        </div>
      )}
    </div>
  )
}

export function HostsManager() {
  const [hosts,   setHosts]   = useState([])
  const [loading, setLoading] = useState(true)
  const [adding,  setAdding]  = useState(false)
  const [editing, setEditing] = useState(null)   // host id being edited
  const [saving,  setSaving]  = useState(false)

  useEffect(() => {
    api.listContainerHosts().then(setHosts).catch(() => {}).finally(() => setLoading(false))
  }, [])

  async function handleAdd(body) {
    setSaving(true)
    try {
      const created = await api.createContainerHost(body)
      setHosts(prev => [...prev, created])
      setAdding(false)
    } catch (e) {
      alert(`Failed to add host: ${e.message}`)
    } finally {
      setSaving(false)
    }
  }

  async function handleUpdate(id, body) {
    setSaving(true)
    try {
      const updated = await api.updateContainerHost(id, body)
      setHosts(prev => prev.map(h => h.id === id ? updated : h))
      setEditing(null)
    } catch (e) {
      alert(`Failed to update host: ${e.message}`)
    } finally {
      setSaving(false)
    }
  }

  async function handleToggle(id, enabled) {
    const updated = await api.updateContainerHost(id, { enabled }).catch(() => null)
    if (updated) setHosts(prev => prev.map(h => h.id === id ? updated : h))
  }

  return (
    <div className="space-y-3">
      {loading && (
        <div className="text-xs py-4 text-center" style={{ color: 'var(--color-text-faint)' }}>
          <Loader2 size={13} className="inline animate-spin mr-1" /> Loading hosts…
        </div>
      )}

      {!loading && hosts.length === 0 && !adding && (
        <div className="text-center py-6 text-xs" style={{ color: 'var(--color-text-faint)' }}>
          No hosts configured. Add a Docker or Proxmox host to monitor containers.
        </div>
      )}

      {hosts.map(h => (
        editing === h.id ? (
          <HostForm key={h.id} initial={h} saving={saving}
            onSave={body => handleUpdate(h.id, body)}
            onCancel={() => setEditing(null)} />
        ) : (
          <HostRow key={h.id} host={h}
            onEdit={() => setEditing(h.id)}
            onDelete={id => setHosts(prev => prev.filter(x => x.id !== id))}
            onToggle={handleToggle} />
        )
      ))}

      {adding ? (
        <HostForm saving={saving} onSave={handleAdd} onCancel={() => setAdding(false)} />
      ) : (
        <button onClick={() => setAdding(true)}
          className="w-full flex items-center justify-center gap-2 px-3 py-2.5 rounded-xl border-2 border-dashed text-xs font-medium transition-colors hover:border-brand hover:text-brand"
          style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}>
          <Plus size={14} /> Add Host
        </button>
      )}
    </div>
  )
}
