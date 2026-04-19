import { useState, useEffect, useRef } from 'react'
import {
  Save, RotateCcw, Settings2, X, Download, Upload, FileText,
  Database, Bell, ScanLine, Eye, EyeOff, Send, Globe, Zap,
} from 'lucide-react'
import { api } from '../api'

// ── Setting definitions ────────────────────────────────────────────────────────
const SETTING_META = {
  // Scanner tab
  scan_interval:           { label: 'Scan Interval',       unit: 'seconds',       type: 'number', min: 5,  max: 3600, tab: 'scanner' },
  offline_miss_threshold:  { label: 'Offline Threshold',   unit: 'missed sweeps', type: 'number', min: 1,  max: 20,   tab: 'scanner' },
  os_confidence_threshold: { label: 'OS Confidence Min',   unit: '%',             type: 'number', min: 50, max: 100,  tab: 'scanner' },
  sniffer_workers:         { label: 'Sniffer Workers',     unit: 'threads',       type: 'number', min: 1,  max: 16,   tab: 'scanner' },
  ip_range:                { label: 'IP Range',            unit: '',              type: 'text',              tab: 'scanner' },
  nmap_args:               { label: 'Nmap Arguments',      unit: '',              type: 'text',              tab: 'scanner' },
  vuln_scan_scripts:       { label: 'Vuln Scan Scripts',   unit: '',              type: 'text',              tab: 'scanner',
    description: 'Comma-separated Nmap NSE scripts for vulnerability scanning.' },
  vuln_scan_schedule:      { label: 'Scheduled Vuln Scans', unit: '',             type: 'select', tab: 'scanner',
    options: [
      { value: 'disabled', label: 'Disabled' },
      { value: '6h',       label: 'Every 6 hours' },
      { value: '12h',      label: 'Every 12 hours' },
      { value: '24h',      label: 'Daily' },
      { value: 'weekly',   label: 'Weekly' },
    ],
  },
  vuln_scan_targets:       { label: 'Scan Targets',        unit: '',             type: 'select', tab: 'scanner',
    options: [
      { value: 'all',       label: 'All devices' },
      { value: 'important', label: 'Watched devices only' },
    ],
  },
  vuln_scan_on_new_device: { label: 'Auto-scan New Devices', type: 'toggle', tab: 'scanner',
    description: 'Automatically run a vulnerability scan when a new device is first discovered.' },

  // Notifications tab — in-app
  notifications_enabled:         { label: 'Toast Notifications',    type: 'toggle', tab: 'notifications',
    description: 'Show in-app popup toasts when new devices appear or go offline.' },
  browser_notifications_enabled: { label: 'Browser Notifications',  type: 'toggle', tab: 'notifications',
    description: 'Show OS-level notifications even when the tab is in the background. Requires browser permission.' },

  // Notifications tab — alert triggers (control the backend dispatch loop)
  alert_on_new_device: { label: 'Alert on New Device',      type: 'toggle', tab: 'notifications',
    description: 'Send an external alert when a new device is discovered.' },
  alert_on_offline:    { label: 'Alert on Device Offline',  type: 'toggle', tab: 'notifications',
    description: 'Send an external alert when a watched device goes offline.' },
  alert_on_vuln:       { label: 'Alert on Vulnerability',   type: 'toggle', tab: 'notifications',
    description: 'Send an external alert when a vulnerability scan finds issues.' },

  // Delivery channels — handled as special sections in the UI, referenced here for tab routing
  alert_webhook_url: { tab: 'notifications' },
  ntfy_url:          { tab: 'notifications' },
  ntfy_topic:        { tab: 'notifications' },
  gotify_url:        { tab: 'notifications' },
  gotify_token:      { tab: 'notifications' },
  pushbullet_api_key:{ tab: 'notifications' },
}

// Keys rendered as custom delivery-channel cards, not through SettingRow
const DELIVERY_KEYS = new Set(['alert_webhook_url','ntfy_url','ntfy_topic','gotify_url','gotify_token','pushbullet_api_key'])

const TABS = [
  { id: 'scanner',       label: 'Scanner',       Icon: ScanLine },
  { id: 'notifications', label: 'Notifications', Icon: Bell     },
  { id: 'data',          label: 'Data',          Icon: Database },
]

async function downloadResponse(res, filename) {
  const blob = await res.blob()
  const url  = URL.createObjectURL(blob)
  const a    = document.createElement('a')
  a.href     = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export function SettingsPanel({ onClose, onSettingChange }) {
  const [activeTab,     setActiveTab]     = useState('scanner')
  const [settings,      setSettings]      = useState([])
  const [dirty,         setDirty]         = useState({})
  const [saving,        setSaving]        = useState(false)
  const [saved,         setSaved]         = useState(false)
  const [fpStats,       setFpStats]       = useState(null)
  const [exportingDevs, setExportingDevs] = useState(false)
  const [exportingFp,   setExportingFp]   = useState(false)
  const [importStatus,  setImportStatus]  = useState(null)
  const [showPbKey,     setShowPbKey]     = useState(false)
  const [showGotifyToken, setShowGotifyToken] = useState(false)
  const [pbTestStatus,  setPbTestStatus]  = useState(null)
  const [pbTestMsg,     setPbTestMsg]     = useState('')
  const [browserPerm,   setBrowserPerm]   = useState(
    typeof Notification !== 'undefined' ? Notification.permission : 'unsupported'
  )
  const fileInputRef = useRef(null)

  useEffect(() => {
    api.getSettings().then(setSettings).catch(() => {})
    api.getFingerprintStats().then(setFpStats).catch(() => {})
  }, [])

  function handleChange(key, value) {
    setDirty(d => ({ ...d, [key]: value }))
    onSettingChange?.(key, value)
  }

  async function handleSave() {
    setSaving(true)
    await Promise.all(
      Object.entries(dirty).map(([key, value]) => api.updateSetting(key, value))
    )
    setSaving(false)
    setDirty({})
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
    api.getSettings().then(setSettings)
  }

  async function handleReset() {
    if (!confirm('Reset all settings to defaults?')) return
    await api.resetSettings()
    api.getSettings().then(s => {
      setSettings(s)
      setDirty({})
      s.forEach(x => onSettingChange?.(x.key, x.value))
    })
  }

  async function handleRequestBrowserPermission() {
    if (typeof Notification === 'undefined') return
    const result = await Notification.requestPermission()
    setBrowserPerm(result)
  }

  async function handleTestPushbullet() {
    const currentKey = (
      dirty['pushbullet_api_key'] ??
      settings.find(s => s.key === 'pushbullet_api_key')?.value ??
      ''
    ).trim()
    if (!currentKey) {
      setPbTestStatus('error'); setPbTestMsg('Enter an API key first.')
      setTimeout(() => setPbTestStatus(null), 4000)
      return
    }
    setPbTestStatus('testing')
    try {
      await api.testPushbullet(currentKey)
      setPbTestStatus('ok'); setPbTestMsg('Test notification sent!')
    } catch (e) {
      setPbTestStatus('error')
      setPbTestMsg((e.message || '').includes('401') ? 'Invalid API key.' : 'Failed — check key and connection.')
    }
    setTimeout(() => setPbTestStatus(null), 6000)
  }

  async function handleExportDevices() {
    setExportingDevs(true)
    try { await downloadResponse(await api.exportDevicesCsv(), 'inspectre-devices.csv') }
    catch (e) { alert('Export failed: ' + e.message) }
    finally { setExportingDevs(false) }
  }

  async function handleExportFingerprints() {
    setExportingFp(true)
    try { await downloadResponse(await api.exportFingerprintsJson(), 'inspectre-fingerprints.json') }
    catch (e) { alert('Export failed: ' + e.message) }
    finally { setExportingFp(false) }
  }

  async function handleImportFingerprints(e) {
    const file = e.target.files?.[0]
    if (!file) return
    setImportStatus('loading')
    try {
      setImportStatus(await api.importFingerprintsJson(file))
      api.getFingerprintStats().then(setFpStats)
    } catch { setImportStatus('error') }
    finally { if (fileInputRef.current) fileInputRef.current.value = '' }
  }

  const hasDirty   = Object.keys(dirty).length > 0
  const showFooter = activeTab !== 'data'

  // Returns current value for a key (dirty-aware)
  function val(key) {
    return dirty[key] ?? settings.find(s => s.key === key)?.value ?? ''
  }

  // Standard setting rows for a tab (excludes delivery-channel keys)
  function tabRows(tab) {
    return settings.filter(s => SETTING_META[s.key]?.tab === tab && !DELIVERY_KEYS.has(s.key))
  }

  const bnEnabled = val('browser_notifications_enabled') === 'true'

  // ── Scanner tab grouping ────────────────────────────────────────────────────
  const networkScanKeys = ['scan_interval','offline_miss_threshold','os_confidence_threshold','sniffer_workers','ip_range','nmap_args']
  const vulnScanKeys    = ['vuln_scan_scripts','vuln_scan_schedule','vuln_scan_targets','vuln_scan_on_new_device']

  // ── Notifications tab grouping ──────────────────────────────────────────────
  const inAppKeys   = ['notifications_enabled','browser_notifications_enabled']
  const triggerKeys = ['alert_on_new_device','alert_on_offline','alert_on_vuln']

  function settingsByKeys(keys) {
    return keys.map(k => settings.find(s => s.key === k)).filter(Boolean)
  }

  return (
    <>
      <div
        className="fixed inset-0 z-40 animate-fade-in"
        style={{ background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }}
        onClick={onClose}
      />

      <aside
        className="fixed right-0 top-0 h-full w-full max-w-md z-50 flex flex-col shadow-2xl animate-slide-in"
        style={{ background: 'var(--color-surface)', borderLeft: '1px solid var(--color-border)' }}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-5"
          style={{ borderBottom: '1px solid var(--color-border)' }}>
          <div className="flex items-center gap-3">
            <span className="w-8 h-8 rounded-lg flex items-center justify-center"
              style={{ background: 'color-mix(in srgb, var(--color-brand) 12%, var(--color-surface-offset))' }}>
              <Settings2 size={16} style={{ color: 'var(--color-brand)' }} />
            </span>
            <h2 className="font-semibold" style={{ color: 'var(--color-text)' }}>Settings</h2>
          </div>
          <button onClick={onClose} className="btn-ghost p-2" aria-label="Close"><X size={18} /></button>
        </div>

        {/* Tab bar */}
        <div className="flex px-6 gap-1"
          style={{ borderBottom: '1px solid var(--color-border)', paddingTop: '12px' }}>
          {TABS.map(({ id, label, Icon }) => {
            const isActive = activeTab === id
            return (
              <button key={id} onClick={() => setActiveTab(id)}
                className="flex items-center gap-1.5 px-3 pb-3 text-sm font-medium transition-colors relative"
                style={{
                  color: isActive ? 'var(--color-brand)' : 'var(--color-text-muted)',
                  borderBottom: isActive ? '2px solid var(--color-brand)' : '2px solid transparent',
                  marginBottom: '-1px',
                }}>
                <Icon size={13} />{label}
              </button>
            )
          })}
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-5">

          {/* ── Scanner tab ─────────────────────────────────────────────────── */}
          {activeTab === 'scanner' && (
            <>
              <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                Changes are written to the database immediately. The probe reads these
                values at the start of each scan cycle — no restart needed.
              </p>

              {settings.length === 0 && <SkeletonRows count={6} />}

              {/* Network scanning */}
              <SectionHeader label="Network Scanning" Icon={ScanLine} />
              {settingsByKeys(networkScanKeys).map(s => (
                <SettingRow key={s.key} s={s} dirty={dirty} onchange={handleChange} />
              ))}

              {/* Vulnerability scanning */}
              <SectionHeader label="Vulnerability Scanning" Icon={ScanLine} />
              {settingsByKeys(vulnScanKeys).map(s => (
                <SettingRow key={s.key} s={s} dirty={dirty} onchange={handleChange} />
              ))}
            </>
          )}

          {/* ── Notifications tab ───────────────────────────────────────────── */}
          {activeTab === 'notifications' && (
            <>
              <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                Configure how and where you receive alerts about network events.
              </p>

              {settings.length === 0 && <SkeletonRows count={5} />}

              {/* In-app */}
              <SectionHeader label="In-App" Icon={Bell} />
              {settingsByKeys(inAppKeys).map(s => (
                <SettingRow key={s.key} s={s} dirty={dirty} onchange={handleChange} />
              ))}

              {/* Browser permission helper */}
              {bnEnabled && browserPerm !== 'unsupported' && (
                <div className="rounded-lg p-3 text-xs space-y-2"
                  style={{ background: 'var(--color-surface-offset)', border: '1px solid var(--color-border)' }}>
                  <div className="flex items-center justify-between">
                    <span className="font-medium" style={{ color: 'var(--color-text)' }}>Browser permission</span>
                    <PermBadge perm={browserPerm} />
                  </div>
                  {browserPerm === 'default' && (
                    <>
                      <p style={{ color: 'var(--color-text-muted)' }}>Permission required to show OS-level notifications.</p>
                      <button onClick={handleRequestBrowserPermission}
                        className="btn-secondary text-xs flex items-center gap-1.5">
                        <Bell size={11} /> Request Permission
                      </button>
                    </>
                  )}
                  {browserPerm === 'denied' && (
                    <p style={{ color: '#ef4444' }}>Permission denied. Reset in your browser's site settings, then reload.</p>
                  )}
                  {browserPerm === 'granted' && (
                    <p style={{ color: 'var(--color-text-muted)' }}>OS notifications are active.</p>
                  )}
                </div>
              )}

              {/* Alert triggers */}
              <SectionHeader label="Alert Triggers" Icon={Bell} />
              <p className="text-xs -mt-2" style={{ color: 'var(--color-text-faint)' }}>
                Which events fire alerts to the delivery channels below.
              </p>
              {settingsByKeys(triggerKeys).map(s => (
                <SettingRow key={s.key} s={s} dirty={dirty} onchange={handleChange} />
              ))}

              {/* Delivery: Webhook */}
              <SectionHeader label="Webhook" Icon={Globe} />
              <div className="card p-4 space-y-2">
                <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                  POST JSON to a URL when an alert fires. Leave blank to disable.
                </p>
                <input
                  type="url"
                  className="input text-sm"
                  placeholder="https://example.com/webhook"
                  value={val('alert_webhook_url')}
                  onChange={e => handleChange('alert_webhook_url', e.target.value)}
                  style={dirty['alert_webhook_url'] !== undefined ? { borderColor: 'color-mix(in srgb, var(--color-brand) 50%, transparent)' } : {}}
                />
              </div>

              {/* Delivery: ntfy */}
              <SectionHeader label="ntfy" Icon={Globe} />
              <div className="card p-4 space-y-3">
                <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                  Self-hosted or ntfy.sh push notifications. Leave topic blank to disable.
                </p>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Server URL</label>
                  <input type="url" className="input text-sm" placeholder="https://ntfy.sh"
                    value={val('ntfy_url')} onChange={e => handleChange('ntfy_url', e.target.value)}
                    style={dirty['ntfy_url'] !== undefined ? { borderColor: 'color-mix(in srgb, var(--color-brand) 50%, transparent)' } : {}} />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Topic</label>
                  <input type="text" className="input text-sm" placeholder="my-inspectre-alerts"
                    value={val('ntfy_topic')} onChange={e => handleChange('ntfy_topic', e.target.value)}
                    style={dirty['ntfy_topic'] !== undefined ? { borderColor: 'color-mix(in srgb, var(--color-brand) 50%, transparent)' } : {}} />
                </div>
              </div>

              {/* Delivery: Gotify */}
              <SectionHeader label="Gotify" Icon={Globe} />
              <div className="card p-4 space-y-3">
                <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                  Self-hosted Gotify push notifications. Leave URL blank to disable.
                </p>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Server URL</label>
                  <input type="url" className="input text-sm" placeholder="https://gotify.example.com"
                    value={val('gotify_url')} onChange={e => handleChange('gotify_url', e.target.value)}
                    style={dirty['gotify_url'] !== undefined ? { borderColor: 'color-mix(in srgb, var(--color-brand) 50%, transparent)' } : {}} />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>App Token</label>
                  <div className="relative">
                    <input type={showGotifyToken ? 'text' : 'password'} className="input text-sm pr-10 font-mono"
                      placeholder="A1b2C3d4…"
                      value={val('gotify_token')} onChange={e => handleChange('gotify_token', e.target.value)}
                      style={dirty['gotify_token'] !== undefined ? { borderColor: 'color-mix(in srgb, var(--color-brand) 50%, transparent)' } : {}} />
                    <button type="button" onClick={() => setShowGotifyToken(v => !v)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 opacity-50 hover:opacity-100 transition-opacity"
                      aria-label={showGotifyToken ? 'Hide token' : 'Show token'}>
                      {showGotifyToken ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  </div>
                </div>
              </div>

              {/* Delivery: Pushbullet */}
              <SectionHeader label="Pushbullet" Icon={Send} />
              <div className="card p-4 space-y-3">
                <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                  Push to your phone and desktop via the Pushbullet app.
                  Get your token at <span style={{ color: 'var(--color-brand)' }}>pushbullet.com/account</span>.
                </p>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>API Key</label>
                  <div className="relative">
                    <input type={showPbKey ? 'text' : 'password'} className="input text-sm pr-10 font-mono"
                      placeholder="o.XXXXXXXXXXXXXXXXXXXXXXXX"
                      value={val('pushbullet_api_key')} onChange={e => handleChange('pushbullet_api_key', e.target.value)}
                      style={dirty['pushbullet_api_key'] !== undefined ? { borderColor: 'color-mix(in srgb, var(--color-brand) 50%, transparent)' } : {}} />
                    <button type="button" onClick={() => setShowPbKey(v => !v)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 opacity-50 hover:opacity-100 transition-opacity"
                      aria-label={showPbKey ? 'Hide key' : 'Show key'}>
                      {showPbKey ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  </div>
                </div>
                <div className="flex items-center gap-3 flex-wrap">
                  <button onClick={handleTestPushbullet} disabled={pbTestStatus === 'testing'}
                    className="btn-secondary flex items-center gap-2 text-sm">
                    <Send size={12} />
                    {pbTestStatus === 'testing' ? 'Sending…' : 'Send test push'}
                  </button>
                  {pbTestStatus === 'ok'    && <span className="text-xs" style={{ color: 'var(--color-success)' }}>✓ {pbTestMsg}</span>}
                  {pbTestStatus === 'error' && <span className="text-xs" style={{ color: '#ef4444' }}>{pbTestMsg}</span>}
                </div>
              </div>
            </>
          )}

          {/* ── Data tab ────────────────────────────────────────────────────── */}
          {activeTab === 'data' && (
            <>
              <SectionHeader label="Device List" Icon={FileText} />
              <div className="card p-4 space-y-2">
                <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                  Download all discovered devices as a CSV spreadsheet.
                </p>
                <button onClick={handleExportDevices} disabled={exportingDevs}
                  className="btn-secondary flex items-center gap-2 text-sm">
                  <FileText size={13} />
                  {exportingDevs ? 'Exporting…' : 'Export devices.csv'}
                </button>
              </div>

              <SectionHeader label="Fingerprint Database" Icon={Database} />
              <div className="card p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <p className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>
                    {fpStats ? `${fpStats.total} entries` : 'Loading…'}
                  </p>
                  {fpStats && (
                    <span className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                      {fpStats.manual} manual · {fpStats.community} community · {fpStats.auto} auto
                    </span>
                  )}
                </div>
                <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                  Export your trained fingerprint database. MAC addresses are stripped before export.
                </p>
                <div className="flex gap-2 flex-wrap">
                  <button onClick={handleExportFingerprints} disabled={exportingFp}
                    className="btn-secondary flex items-center gap-2 text-sm">
                    <Download size={13} />
                    {exportingFp ? 'Exporting…' : 'Export fingerprints.json'}
                  </button>
                  <button onClick={() => fileInputRef.current?.click()}
                    className="btn-secondary flex items-center gap-2 text-sm">
                    <Upload size={13} /> Import fingerprints.json
                  </button>
                  <input ref={fileInputRef} type="file" accept=".json,application/json"
                    className="sr-only" onChange={handleImportFingerprints} />
                </div>

                {importStatus === 'loading' && (
                  <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>Importing…</p>
                )}
                {importStatus === 'error' && (
                  <p className="text-xs" style={{ color: '#ef4444' }}>
                    Import failed — check the file is a valid InSpectre fingerprints.json.
                  </p>
                )}
                {importStatus && importStatus !== 'loading' && importStatus !== 'error' && (
                  <div className="rounded-lg p-3 text-xs space-y-1"
                    style={{
                      background: 'color-mix(in srgb, var(--color-success) 10%, var(--color-surface-offset))',
                      color: 'var(--color-success)',
                    }}>
                    <p className="font-medium">Import complete ✓</p>
                    <p>{importStatus.inserted} new · {importStatus.merged} merged · {importStatus.corrected} devices auto-corrected</p>
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        {showFooter && (
          <div className="px-6 py-4 flex gap-3" style={{ borderTop: '1px solid var(--color-border)' }}>
            <button onClick={handleSave} disabled={!hasDirty || saving}
              className={`btn-primary flex-1 flex items-center justify-center gap-2 ${!hasDirty || saving ? 'opacity-40 cursor-not-allowed' : ''}`}>
              <Save size={14} />
              {saving ? 'Saving…' : saved ? 'Saved ✓' : 'Save Changes'}
            </button>
            <button onClick={handleReset} className="btn-ghost flex items-center gap-2">
              <RotateCcw size={14} /> Reset
            </button>
          </div>
        )}
      </aside>
    </>
  )
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function SectionHeader({ label, Icon }) {
  return (
    <div className="flex items-center gap-2 pt-1">
      {Icon && <Icon size={13} style={{ color: 'var(--color-text-muted)' }} />}
      <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>{label}</h3>
    </div>
  )
}

function PermBadge({ perm }) {
  const color = perm === 'granted' ? 'var(--color-success)' : perm === 'denied' ? '#ef4444' : 'var(--color-brand)'
  const bg    = perm === 'granted'
    ? 'color-mix(in srgb, var(--color-success) 15%, transparent)'
    : perm === 'denied' ? 'rgba(239,68,68,0.15)' : 'color-mix(in srgb, var(--color-brand) 12%, transparent)'
  return (
    <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase"
      style={{ background: bg, color }}>
      {perm}
    </span>
  )
}

function SkeletonRows({ count }) {
  return (
    <div className="space-y-3">
      {[...Array(count)].map((_, i) => (
        <div key={i} className="card p-4 space-y-3">
          <div className="skeleton h-3 w-32" /><div className="skeleton h-9 w-full" />
        </div>
      ))}
    </div>
  )
}

function SettingRow({ s, dirty, onchange }) {
  const meta    = SETTING_META[s.key] || { label: s.key, type: 'text', unit: '' }
  const value   = dirty[s.key] ?? s.value
  const isDirty = dirty[s.key] !== undefined
  const dirtyStyle = isDirty ? { borderColor: 'color-mix(in srgb, var(--color-brand) 50%, transparent)' } : {}

  if (meta.type === 'toggle') {
    const isOn = value === 'true'
    return (
      <div className="card p-4 space-y-2">
        <div className="flex items-center justify-between">
          <label className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>{meta.label}</label>
          <button type="button" role="switch" aria-checked={isOn} aria-label={meta.label}
            onClick={() => onchange(s.key, isOn ? 'false' : 'true')}
            className="relative inline-flex h-6 w-11 items-center rounded-full transition-colors duration-200 focus:outline-none focus-visible:ring-2"
            style={{ background: isOn ? 'var(--color-brand)' : 'var(--color-border)', flexShrink: 0 }}>
            <span className="inline-block h-4 w-4 rounded-full bg-white shadow transition-transform duration-200"
              style={{ transform: isOn ? 'translateX(22px)' : 'translateX(4px)' }} />
          </button>
        </div>
        {(meta.description || s.description) && (
          <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>{meta.description || s.description}</p>
        )}
      </div>
    )
  }

  if (meta.type === 'select') {
    return (
      <div className="card p-4 space-y-2">
        <label className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>{meta.label}</label>
        <select className="input" style={dirtyStyle} value={value} onChange={e => onchange(s.key, e.target.value)}>
          {meta.options?.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        {(meta.description || s.description) && (
          <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>{meta.description || s.description}</p>
        )}
      </div>
    )
  }

  return (
    <div className="card p-4 space-y-2">
      <div className="flex items-center justify-between">
        <label className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>{meta.label}</label>
        {meta.unit && <span className="text-xs" style={{ color: 'var(--color-text-faint)' }}>{meta.unit}</span>}
      </div>
      <input type={meta.type || 'text'} min={meta.min} max={meta.max}
        className="input" style={dirtyStyle} value={value}
        onChange={e => onchange(s.key, e.target.value)} />
      {(meta.description || s.description) && (
        <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>{meta.description || s.description}</p>
      )}
    </div>
  )
}
