import { useState, useEffect, useRef } from 'react'
import {
  ChevronLeft, ChevronDown, ChevronRight, Upload, AlertTriangle,
  CheckCircle, XCircle, ToggleLeft, ToggleRight, Trash2, Eye, EyeOff,
  ExternalLink, Package, Loader, RefreshCw,
} from 'lucide-react'
import { api } from '../api'

function relativeTime(iso) {
  if (!iso) return ''
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (diff < 60)  return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

// ── Capability badge colours ──────────────────────────────────────────────────
const CAP_COLORS = {
  export:       { bg: 'rgba(59,130,246,0.15)',  color: '#60a5fa' },
  notification: { bg: 'rgba(139,92,246,0.15)',  color: '#a78bfa' },
  discovery:    { bg: 'rgba(16,185,129,0.15)',  color: '#34d399' },
  blocking:     { bg: 'rgba(239,68,68,0.15)',   color: '#f87171' },
  enrichment:   { bg: 'rgba(245,158,11,0.15)',  color: '#fbbf24' },
  dns:          { bg: 'rgba(20,184,166,0.15)',  color: '#2dd4bf' },
  presence:     { bg: 'rgba(99,102,241,0.15)',  color: '#818cf8' },
  traffic:      { bg: 'rgba(234,179,8,0.15)',   color: '#facc15' },
}

function CapBadge({ cap }) {
  const style = CAP_COLORS[cap] || { bg: 'rgba(107,114,128,0.15)', color: '#9ca3af' }
  return (
    <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase"
      style={{ background: style.bg, color: style.color }}>
      {cap}
    </span>
  )
}

function StatusDot({ status }) {
  const map = {
    active:   'bg-green-400',
    error:    'bg-red-400',
    disabled: 'bg-gray-400',
  }
  return (
    <span className={`inline-block w-2 h-2 rounded-full flex-shrink-0 ${map[status] || 'bg-gray-400'}`} />
  )
}

function PluginIcon({ manifest }) {
  if (manifest.icon) {
    return (
      <img src={manifest.icon} alt="" className="w-10 h-10 rounded-lg object-contain"
        style={{ background: 'var(--color-surface-offset)' }} />
    )
  }
  // Initials fallback
  const initials = (manifest.name || '?').split(' ').slice(0, 2).map(w => w[0]).join('')
  return (
    <div className="w-10 h-10 rounded-lg flex items-center justify-center text-sm font-bold flex-shrink-0"
      style={{ background: 'color-mix(in srgb, var(--color-brand) 15%, var(--color-surface-offset))', color: 'var(--color-brand)' }}>
      {initials.toUpperCase()}
    </div>
  )
}

// ── Plugin card (list view) ───────────────────────────────────────────────────

function PluginCard({ plugin, onOpen, onToggle }) {
  const [toggling, setToggling] = useState(false)

  async function handleToggle(e) {
    e.stopPropagation()
    setToggling(true)
    try { await onToggle() } finally { setToggling(false) }
  }

  return (
    <div
      className="card p-4 cursor-pointer transition-all hover:shadow-md"
      style={{ borderColor: plugin.enabled ? 'color-mix(in srgb, var(--color-brand) 30%, var(--color-border))' : 'var(--color-border)' }}
      onClick={onOpen}
    >
      <div className="flex items-start gap-3">
        <PluginIcon manifest={plugin.manifest} />

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>
              {plugin.name}
            </span>
            <span className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
              v{plugin.version}
            </span>
            {plugin.source === 'builtin' ? (
              <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold"
                style={{ background: 'color-mix(in srgb, var(--color-brand) 12%, transparent)', color: 'var(--color-brand)' }}>
                built-in
              </span>
            ) : (
              <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold"
                style={{ background: 'rgba(245,158,11,0.12)', color: '#f59e0b' }}>
                community
              </span>
            )}
          </div>

          {plugin.author && (
            <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-faint)' }}>by {plugin.author}</p>
          )}

          <div className="flex flex-wrap gap-1 mt-2">
            {(plugin.capabilities || []).map(c => <CapBadge key={c} cap={c} />)}
          </div>

          {plugin.status === 'error' && plugin.last_error && (
            <p className="text-xs mt-1.5 truncate" style={{ color: '#ef4444' }}>
              {plugin.last_error}
            </p>
          )}

          {plugin.enabled && plugin.last_polled && (
            <p className="text-xs mt-1" style={{ color: 'var(--color-text-faint)' }}>
              Last sync: {relativeTime(plugin.last_polled)}
              {plugin.last_device_count != null && ` · ${plugin.last_device_count} device(s)`}
            </p>
          )}
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          <div className="flex items-center gap-1.5">
            <StatusDot status={plugin.status} />
            <span className="text-xs capitalize" style={{ color: 'var(--color-text-muted)' }}>
              {plugin.status}
            </span>
          </div>
          <button
            className="p-1 rounded transition-opacity"
            style={{ color: plugin.enabled ? 'var(--color-brand)' : 'var(--color-text-muted)', opacity: toggling ? 0.5 : 1 }}
            onClick={handleToggle}
            disabled={toggling}
            title={plugin.enabled ? 'Disable plugin' : 'Enable plugin'}
          >
            {plugin.enabled ? <ToggleRight size={20} /> : <ToggleLeft size={20} />}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Config field renderer ─────────────────────────────────────────────────────

function ConfigField({ field, value, onChange }) {
  const [showPwd, setShowPwd] = useState(false)
  const { key, label, type = 'string', help, options = [] } = field

  if (type === 'boolean') {
    const isOn = value === true || value === 'true'
    return (
      <div className="card p-4 space-y-1.5">
        <div className="flex items-center justify-between">
          <label className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>{label}</label>
          <button type="button" role="switch" aria-checked={isOn}
            onClick={() => onChange(key, !isOn)}
            className="relative inline-flex h-6 w-11 items-center rounded-full transition-colors duration-200"
            style={{ background: isOn ? 'var(--color-brand)' : 'var(--color-border)', flexShrink: 0 }}>
            <span className="inline-block h-4 w-4 rounded-full bg-white shadow transition-transform duration-200"
              style={{ transform: isOn ? 'translateX(22px)' : 'translateX(4px)' }} />
          </button>
        </div>
        {help && <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>{help}</p>}
      </div>
    )
  }

  if (type === 'select') {
    return (
      <div className="card p-4 space-y-1.5">
        <label className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>{label}</label>
        <select className="input w-full" value={value ?? ''} onChange={e => onChange(key, e.target.value)}>
          {options.map(o => (
            <option key={typeof o === 'string' ? o : o.value} value={typeof o === 'string' ? o : o.value}>
              {typeof o === 'string' ? o : o.label}
            </option>
          ))}
        </select>
        {help && <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>{help}</p>}
      </div>
    )
  }

  if (type === 'multiline') {
    return (
      <div className="card p-4 space-y-1.5">
        <label className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>{label}</label>
        <textarea className="input w-full" rows={4} value={value ?? ''}
          onChange={e => onChange(key, e.target.value)} />
        {help && <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>{help}</p>}
      </div>
    )
  }

  if (type === 'password') {
    return (
      <div className="card p-4 space-y-1.5">
        <label className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>{label}</label>
        <div className="relative">
          <input
            type={showPwd ? 'text' : 'password'}
            className="input w-full pr-10"
            value={value ?? ''}
            onChange={e => onChange(key, e.target.value)}
            placeholder={value === '**redacted**' ? '(saved — leave blank to keep)' : ''}
          />
          <button type="button" onClick={() => setShowPwd(v => !v)}
            className="absolute right-3 top-1/2 -translate-y-1/2 opacity-50 hover:opacity-100 transition-opacity"
            tabIndex={-1}>
            {showPwd ? <EyeOff size={14} /> : <Eye size={14} />}
          </button>
        </div>
        {help && <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>{help}</p>}
      </div>
    )
  }

  if (type === 'filepath') {
    return (
      <div className="card p-4 space-y-1.5">
        <label className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>{label}</label>
        <input
          type="text"
          className="input w-full font-mono text-xs"
          value={value ?? ''}
          onChange={e => onChange(key, e.target.value)}
          placeholder="/data/leases.txt"
          spellCheck={false}
          autoComplete="off"
        />
        <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
          Container-internal path. Mount the file via <code>volumes:</code> in <code>docker-compose.yml</code>.
        </p>
        {help && <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>{help}</p>}
      </div>
    )
  }

  // string, integer, url → text/number input
  const inputType = type === 'integer' ? 'number' : (type === 'url' ? 'url' : 'text')
  return (
    <div className="card p-4 space-y-1.5">
      <label className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>{label}</label>
      <input
        type={inputType}
        className="input w-full"
        value={value ?? ''}
        onChange={e => onChange(key, e.target.value)}
      />
      {help && <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>{help}</p>}
    </div>
  )
}

// ── Plugin config panel ───────────────────────────────────────────────────────

function PluginConfigPanel({ plugin, config, onChange, onSave, onTest, onPoll, onBack, onDelete,
                             saving, testing, testResult, polling, pollResult, showRawManifest, setShowRawManifest }) {
  const manifest = plugin.manifest

  return (
    <div className="space-y-4">
      {/* Back + header */}
      <div className="flex items-center gap-2">
        <button onClick={onBack} className="btn-ghost p-1.5" aria-label="Back">
          <ChevronLeft size={16} />
        </button>
        <PluginIcon manifest={manifest} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>
              {plugin.name}
            </span>
            <span className="text-xs" style={{ color: 'var(--color-text-faint)' }}>v{plugin.version}</span>
            {plugin.source === 'builtin' ? (
              <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold"
                style={{ background: 'color-mix(in srgb, var(--color-brand) 12%, transparent)', color: 'var(--color-brand)' }}>
                built-in
              </span>
            ) : (
              <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold"
                style={{ background: 'rgba(245,158,11,0.12)', color: '#f59e0b' }}>
                community
              </span>
            )}
          </div>
          {plugin.author && (
            <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>by {plugin.author}</p>
          )}
        </div>
      </div>

      {/* Community warning */}
      {plugin.source === 'uploaded' && (
        <div className="rounded-lg p-3 text-xs flex gap-2"
          style={{ background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.3)', color: '#d97706' }}>
          <AlertTriangle size={14} className="flex-shrink-0 mt-0.5" />
          <p>This is a community-provided plugin and has not been audited by InSpectre.
            Only install plugins from sources you trust.</p>
        </div>
      )}

      {/* Description */}
      {manifest.description && (
        <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>{manifest.description}</p>
      )}

      {/* Capabilities + homepage */}
      <div className="flex flex-wrap items-center gap-2">
        {(manifest.capabilities || []).map(c => <CapBadge key={c} cap={c} />)}
        {manifest.homepage && (
          <a href={manifest.homepage} target="_blank" rel="noopener noreferrer"
            className="flex items-center gap-1 text-xs"
            style={{ color: 'var(--color-brand)' }}
            onClick={e => e.stopPropagation()}>
            <ExternalLink size={11} /> Homepage
          </a>
        )}
      </div>

      {/* Error state */}
      {plugin.status === 'error' && plugin.last_error && (
        <div className="rounded-lg p-3 text-xs flex gap-2"
          style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)', color: '#ef4444' }}>
          <XCircle size={14} className="flex-shrink-0 mt-0.5" />
          <p>{plugin.last_error}</p>
        </div>
      )}

      {/* Config form */}
      {(manifest.config_schema || []).length > 0 && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold pt-1" style={{ color: 'var(--color-text)' }}>Configuration</h3>
          {manifest.config_schema.map(field => (
            <ConfigField
              key={field.key}
              field={field}
              value={config[field.key] ?? (field.default ?? '')}
              onChange={onChange}
            />
          ))}
        </div>
      )}

      {/* Save + Test + Sync buttons */}
      <div className="flex gap-2 pt-1 flex-wrap">
        <button onClick={onSave} disabled={saving}
          className="btn-primary flex-1 flex items-center justify-center gap-2 text-sm"
          style={{ opacity: saving ? 0.5 : 1 }}>
          {saving ? <Loader size={13} className="animate-spin" /> : null}
          {saving ? 'Saving…' : 'Save Configuration'}
        </button>
        {manifest.actions?.test_connection && (
          <button onClick={onTest} disabled={testing}
            className="btn-secondary flex items-center gap-2 text-sm"
            style={{ opacity: testing ? 0.5 : 1 }}>
            {testing ? <Loader size={13} className="animate-spin" /> : null}
            {testing ? 'Testing…' : 'Test Connection'}
          </button>
        )}
        {manifest.polling?.action && plugin.enabled && (
          <button onClick={onPoll} disabled={polling}
            className="btn-secondary flex items-center gap-2 text-sm"
            style={{ opacity: polling ? 0.5 : 1 }}
            title="Trigger a manual device sync right now">
            {polling ? <Loader size={13} className="animate-spin" /> : <RefreshCw size={13} />}
            {polling ? 'Syncing…' : 'Sync Now'}
          </button>
        )}
      </div>

      {/* Polling status */}
      {plugin.enabled && plugin.last_polled && (
        <div className="rounded-lg p-3 text-xs space-y-0.5"
          style={{ background: 'var(--color-surface-offset)', border: '1px solid var(--color-border)' }}>
          <div className="flex justify-between">
            <span style={{ color: 'var(--color-text-muted)' }}>Last sync</span>
            <span style={{ color: 'var(--color-text)' }}>{relativeTime(plugin.last_polled)}</span>
          </div>
          {plugin.last_device_count != null && (
            <div className="flex justify-between">
              <span style={{ color: 'var(--color-text-muted)' }}>Devices returned</span>
              <span style={{ color: 'var(--color-text)' }}>{plugin.last_device_count}</span>
            </div>
          )}
        </div>
      )}

      {/* Test result */}
      {testResult && (
        <div className="rounded-lg p-3 text-xs flex gap-2"
          style={{
            background: testResult.ok ? 'rgba(16,185,129,0.08)' : 'rgba(239,68,68,0.08)',
            border:     `1px solid ${testResult.ok ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)'}`,
            color:      testResult.ok ? '#10b981' : '#ef4444',
          }}>
          {testResult.ok ? <CheckCircle size={14} className="flex-shrink-0 mt-0.5" /> : <XCircle size={14} className="flex-shrink-0 mt-0.5" />}
          <p>{testResult.ok ? 'Connection successful' : (testResult.error || 'Connection failed')}</p>
        </div>
      )}

      {/* Poll result */}
      {pollResult && (
        <div className="rounded-lg p-3 text-xs flex gap-2"
          style={{
            background: pollResult.ok ? 'rgba(16,185,129,0.08)' : 'rgba(239,68,68,0.08)',
            border:     `1px solid ${pollResult.ok ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)'}`,
            color:      pollResult.ok ? '#10b981' : '#ef4444',
          }}>
          {pollResult.ok
            ? <CheckCircle size={14} className="flex-shrink-0 mt-0.5" />
            : <XCircle size={14} className="flex-shrink-0 mt-0.5" />}
          <p>{pollResult.ok
            ? `Sync complete — ${pollResult.last_device_count ?? 0} device(s) found`
            : (pollResult.error || pollResult.last_error || 'Sync failed')}</p>
        </div>
      )}

      {/* Event hooks info */}
      {Object.keys(manifest.event_hooks || {}).length > 0 && (
        <div className="space-y-1.5">
          <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>Event hooks</h3>
          <div className="rounded-lg p-3 space-y-1"
            style={{ background: 'var(--color-surface-offset)', border: '1px solid var(--color-border)' }}>
            {Object.entries(manifest.event_hooks).map(([evt, action]) => (
              <div key={evt} className="flex items-center justify-between text-xs">
                <span style={{ color: 'var(--color-text-muted)' }}>{evt}</span>
                <span className="font-mono" style={{ color: 'var(--color-text-faint)' }}>{action}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Raw manifest (collapsible) */}
      <div>
        <button type="button" onClick={() => setShowRawManifest(v => !v)}
          className="flex items-center gap-1.5 text-xs"
          style={{ color: 'var(--color-text-muted)' }}>
          {showRawManifest ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          Raw manifest
        </button>
        {showRawManifest && (
          <pre className="mt-2 rounded-lg p-3 text-xs overflow-auto"
            style={{
              background:  'var(--color-surface-offset)',
              color:       'var(--color-text-muted)',
              border:      '1px solid var(--color-border)',
              maxHeight:   '300px',
              whiteSpace:  'pre-wrap',
              wordBreak:   'break-all',
            }}>
            {JSON.stringify(manifest, null, 2)}
          </pre>
        )}
      </div>

      {/* Delete button (uploaded only) */}
      {plugin.source === 'uploaded' && (
        <button onClick={onDelete}
          className="flex items-center gap-2 text-xs text-red-400 hover:text-red-300 transition-colors pt-1">
          <Trash2 size={13} /> Remove plugin
        </button>
      )}
    </div>
  )
}

// ── Main PluginsTab export ────────────────────────────────────────────────────

export function PluginsTab() {
  const [plugins,          setPlugins]          = useState([])
  const [loading,          setLoading]          = useState(true)
  const [selectedId,       setSelectedId]       = useState(null)
  const [config,           setConfig]           = useState({})
  const [saving,           setSaving]           = useState(false)
  const [testing,          setTesting]          = useState(false)
  const [testResult,       setTestResult]       = useState(null)
  const [polling,          setPolling]          = useState(false)
  const [pollResult,       setPollResult]       = useState(null)
  const [uploading,        setUploading]        = useState(false)
  const [uploadError,      setUploadError]      = useState(null)
  const [fetchError,       setFetchError]       = useState(null)
  const [showRawManifest,  setShowRawManifest]  = useState(false)
  const uploadRef = useRef(null)

  useEffect(() => { loadPlugins() }, [])

  async function loadPlugins() {
    setLoading(true)
    setFetchError(null)
    try {
      setPlugins(await api.listPlugins())
    } catch (err) {
      setFetchError(String(err))
    } finally { setLoading(false) }
  }

  const selected = selectedId ? plugins.find(p => p.id === selectedId) : null

  function openPlugin(plugin) {
    setSelectedId(plugin.id)
    setTestResult(null)
    setShowRawManifest(false)
    // Initialise form from saved config (keep redacted markers for passwords)
    const cfg = {}
    for (const field of (plugin.manifest.config_schema || [])) {
      cfg[field.key] = plugin.config?.[field.key] ?? (field.default ?? '')
    }
    setConfig(cfg)
  }

  function handleChange(key, value) {
    setConfig(c => ({ ...c, [key]: value }))
  }

  async function handleSave() {
    setSaving(true)
    try {
      await api.savePluginConfig(selectedId, config)
      await loadPlugins()
    } catch (e) { alert('Failed to save: ' + e.message) }
    finally { setSaving(false) }
  }

  async function handleTest() {
    setTesting(true)
    setTestResult(null)
    try { setTestResult(await api.testPlugin(selectedId)) }
    catch (e) { setTestResult({ ok: false, error: e.message }) }
    finally { setTesting(false) }
  }

  async function handlePoll() {
    setPolling(true)
    setPollResult(null)
    try {
      const r = await api.pollPlugin(selectedId)
      setPollResult(r)
      await loadPlugins()
    } catch (e) { setPollResult({ ok: false, error: e.message }) }
    finally { setPolling(false) }
  }

  async function handleToggle(pluginId, currentEnabled) {
    try {
      if (currentEnabled) await api.disablePlugin(pluginId)
      else                await api.enablePlugin(pluginId)
      await loadPlugins()
    } catch (e) { alert('Failed: ' + e.message) }
  }

  async function handleDelete() {
    if (!confirm('Remove this plugin? All its stored data will be deleted.')) return
    try {
      await api.deletePlugin(selectedId)
      setSelectedId(null)
      await loadPlugins()
    } catch (e) { alert('Failed: ' + e.message) }
  }

  async function handleUpload(e) {
    const file = e.target.files?.[0]
    if (!file) return
    setUploading(true)
    setUploadError(null)
    try {
      await api.uploadPlugin(file)
      await loadPlugins()
    } catch (e) { setUploadError(e.message) }
    finally {
      setUploading(false)
      if (uploadRef.current) uploadRef.current.value = ''
    }
  }

  if (loading) {
    return (
      <div className="space-y-3">
        {[...Array(2)].map((_, i) => (
          <div key={i} className="card p-4 space-y-3">
            <div className="skeleton h-3 w-32" /><div className="skeleton h-9 w-full" />
          </div>
        ))}
      </div>
    )
  }

  if (selectedId && selected) {
    return (
      <PluginConfigPanel
        plugin={selected}
        config={config}
        onChange={handleChange}
        onSave={handleSave}
        onTest={handleTest}
        onPoll={handlePoll}
        onBack={() => setSelectedId(null)}
        onDelete={handleDelete}
        saving={saving}
        testing={testing}
        testResult={testResult}
        polling={polling}
        pollResult={pollResult}
        showRawManifest={showRawManifest}
        setShowRawManifest={setShowRawManifest}
      />
    )
  }

  return (
    <div className="space-y-4">
      <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
        Plugins extend InSpectre with new integrations. Built-in plugins are
        shipped with InSpectre. Community plugins are uploaded manually and
        have not been audited.
      </p>

      <div className="flex items-center justify-between">
        <span className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>
          {plugins.length} plugin{plugins.length !== 1 ? 's' : ''} installed
        </span>
        <button
          className="btn-secondary flex items-center gap-1.5 text-xs"
          onClick={() => uploadRef.current?.click()}
          disabled={uploading}
        >
          {uploading ? <Loader size={12} className="animate-spin" /> : <Upload size={12} />}
          {uploading ? 'Uploading…' : 'Upload Plugin'}
        </button>
        <input
          ref={uploadRef}
          type="file"
          accept=".json,.yaml,.yml"
          className="sr-only"
          onChange={handleUpload}
        />
      </div>

      {uploadError && (
        <div className="rounded-lg p-3 text-xs flex gap-2"
          style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)', color: '#ef4444' }}>
          <XCircle size={13} className="flex-shrink-0 mt-0.5" />
          <p>{uploadError}</p>
        </div>
      )}

      {fetchError && (
        <div className="rounded-lg p-3 text-xs flex gap-2 items-start"
          style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)', color: '#ef4444' }}>
          <XCircle size={14} className="flex-shrink-0 mt-0.5" />
          <div>
            <p className="font-semibold mb-0.5">Failed to load plugins</p>
            <p className="font-mono">{fetchError}</p>
            <p className="mt-1 opacity-70">If this says "404", the backend needs to be rebuilt: <code>./inspectre.sh rebuild keep-data</code></p>
          </div>
        </div>
      )}

      {!fetchError && plugins.length === 0 && (
        <div className="rounded-lg p-6 text-center"
          style={{ background: 'var(--color-surface-offset)', border: '1px dashed var(--color-border)' }}>
          <Package size={24} className="mx-auto mb-2" style={{ color: 'var(--color-text-faint)' }} />
          <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>No plugins installed</p>
          <p className="text-xs mt-1" style={{ color: 'var(--color-text-faint)' }}>
            Upload a JSON manifest to add community integrations
          </p>
        </div>
      )}

      <div className="space-y-2">
        {plugins.map(plugin => (
          <PluginCard
            key={plugin.id}
            plugin={plugin}
            onOpen={() => openPlugin(plugin)}
            onToggle={() => handleToggle(plugin.id, plugin.enabled)}
          />
        ))}
      </div>
    </div>
  )
}
