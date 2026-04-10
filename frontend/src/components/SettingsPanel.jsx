import { useState, useEffect, useRef } from 'react'
import { Save, RotateCcw, Settings2, X, Download, Upload, FileText, Database } from 'lucide-react'
import { api } from '../api'

const SETTING_META = {
  scan_interval:           { label: 'Scan Interval',        unit: 'seconds',       type: 'number',  min: 5,  max: 3600 },
  offline_miss_threshold:  { label: 'Offline Threshold',    unit: 'missed sweeps', type: 'number',  min: 1,  max: 20   },
  os_confidence_threshold: { label: 'OS Confidence Min',    unit: '%',             type: 'number',  min: 50, max: 100  },
  sniffer_workers:         { label: 'Sniffer Workers',      unit: 'threads',       type: 'number',  min: 1,  max: 16   },
  ip_range:                { label: 'IP Range',             unit: '',              type: 'text'                        },
  nmap_args:               { label: 'Nmap Arguments',       unit: '',              type: 'text'                        },
  notifications_enabled:   { label: 'Device Notifications', unit: '',              type: 'toggle',
                             description: 'Show popup toasts when new devices appear or devices go offline.' },
}

// ── small utility: trigger a browser file download from a fetch Response ──────
async function downloadResponse(res, filename) {
  const blob = await res.blob()
  const url  = URL.createObjectURL(blob)
  const a    = document.createElement('a')
  a.href     = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export function SettingsPanel({ onClose, onNotificationsChange }) {
  const [settings,       setSettings]       = useState([])
  const [dirty,          setDirty]          = useState({})
  const [saving,         setSaving]         = useState(false)
  const [saved,          setSaved]          = useState(false)
  const [fpStats,        setFpStats]        = useState(null)
  const [exportingDevs,  setExportingDevs]  = useState(false)
  const [exportingFp,    setExportingFp]    = useState(false)
  const [importStatus,   setImportStatus]   = useState(null)   // null | 'loading' | { ok, inserted, merged, corrected } | 'error'
  const fileInputRef = useRef(null)

  useEffect(() => {
    api.getSettings().then(setSettings).catch(() => {})
    api.getFingerprintStats().then(setFpStats).catch(() => {})
  }, [])

  function handleChange(key, value) {
    setDirty(d => ({ ...d, [key]: value }))
    if (key === 'notifications_enabled' && onNotificationsChange) {
      onNotificationsChange(value === 'true')
    }
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
      const notif = s.find(x => x.key === 'notifications_enabled')
      if (notif && onNotificationsChange) onNotificationsChange(notif.value === 'true')
    })
  }

  async function handleExportDevices() {
    setExportingDevs(true)
    try {
      const res = await api.exportDevicesCsv()
      await downloadResponse(res, 'inspectre-devices.csv')
    } catch (e) {
      alert('Export failed: ' + e.message)
    } finally {
      setExportingDevs(false)
    }
  }

  async function handleExportFingerprints() {
    setExportingFp(true)
    try {
      const res = await api.exportFingerprintsJson()
      await downloadResponse(res, 'inspectre-fingerprints.json')
    } catch (e) {
      alert('Export failed: ' + e.message)
    } finally {
      setExportingFp(false)
    }
  }

  async function handleImportFingerprints(e) {
    const file = e.target.files?.[0]
    if (!file) return
    setImportStatus('loading')
    try {
      const result = await api.importFingerprintsJson(file)
      setImportStatus(result)
      api.getFingerprintStats().then(setFpStats)
    } catch (err) {
      setImportStatus('error')
    } finally {
      // reset file input so the same file can be re-imported if needed
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  const hasDirty = Object.keys(dirty).length > 0

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 animate-fade-in"
        style={{ background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }}
        onClick={onClose}
      />

      {/* Panel */}
      <aside
        className="fixed right-0 top-0 h-full w-full max-w-md z-50 flex flex-col shadow-2xl animate-slide-in"
        style={{
          background: 'var(--color-surface)',
          borderLeft: '1px solid var(--color-border)',
        }}
      >
        {/* Header */}
        <div
          className="flex items-center justify-between px-6 py-5"
          style={{ borderBottom: '1px solid var(--color-border)' }}
        >
          <div className="flex items-center gap-3">
            <span
              className="w-8 h-8 rounded-lg flex items-center justify-center"
              style={{ background: 'color-mix(in srgb, var(--color-brand) 12%, var(--color-surface-offset))' }}
            >
              <Settings2 size={16} style={{ color: 'var(--color-brand)' }} />
            </span>
            <h2 className="font-semibold" style={{ color: 'var(--color-text)' }}>Settings</h2>
          </div>
          <button onClick={onClose} className="btn-ghost p-2" aria-label="Close">
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">

          {/* ── Scanner settings ── */}
          <div className="space-y-4">
            <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
              Changes are written to the database immediately. The probe reads these
              values at the start of each scan cycle — no restart needed.
            </p>

            {settings.length === 0 && (
              <div className="space-y-3">
                {[...Array(5)].map((_, i) => (
                  <div key={i} className="card p-4 space-y-3">
                    <div className="skeleton h-3 w-32" />
                    <div className="skeleton h-9 w-full" />
                  </div>
                ))}
              </div>
            )}

            {settings.map(s => {
              const meta    = SETTING_META[s.key] || { label: s.key, type: 'text', unit: '' }
              const value   = dirty[s.key] ?? s.value
              const isDirty = dirty[s.key] !== undefined

              if (meta.type === 'toggle') {
                const isOn = value === 'true'
                return (
                  <div key={s.key} className="card p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <label className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>
                        {meta.label}
                      </label>
                      <button
                        type="button"
                        onClick={() => handleChange(s.key, isOn ? 'false' : 'true')}
                        className="relative inline-flex h-6 w-11 items-center rounded-full transition-colors duration-200 focus:outline-none focus-visible:ring-2"
                        style={{
                          background: isOn ? 'var(--color-brand)' : 'var(--color-border)',
                          flexShrink: 0,
                        }}
                        role="switch"
                        aria-checked={isOn}
                        aria-label={meta.label}
                      >
                        <span
                          className="inline-block h-4 w-4 rounded-full bg-white shadow transition-transform duration-200"
                          style={{ transform: isOn ? 'translateX(22px)' : 'translateX(4px)' }}
                        />
                      </button>
                    </div>
                    {(meta.description || s.description) && (
                      <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                        {meta.description || s.description}
                      </p>
                    )}
                  </div>
                )
              }

              return (
                <div key={s.key} className="card p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>
                      {meta.label}
                    </label>
                    {meta.unit && (
                      <span className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                        {meta.unit}
                      </span>
                    )}
                  </div>
                  <input
                    type={meta.type || 'text'}
                    min={meta.min}
                    max={meta.max}
                    className="input"
                    style={isDirty ? { borderColor: 'color-mix(in srgb, var(--color-brand) 50%, transparent)' } : {}}
                    value={value}
                    onChange={e => handleChange(s.key, e.target.value)}
                  />
                  {s.description && (
                    <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                      {s.description}
                    </p>
                  )}
                </div>
              )
            })}
          </div>

          {/* ── Divider ── */}
          <hr style={{ borderColor: 'var(--color-border)' }} />

          {/* ── Export / Import ── */}
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <Database size={14} style={{ color: 'var(--color-text-muted)' }} />
              <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>
                Export &amp; Import
              </h3>
            </div>

            {/* Device list export */}
            <div className="card p-4 space-y-2">
              <p className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>
                Device List
              </p>
              <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                Download all discovered devices as a CSV spreadsheet.
              </p>
              <button
                onClick={handleExportDevices}
                disabled={exportingDevs}
                className="btn-secondary flex items-center gap-2 text-sm"
              >
                <FileText size={13} />
                {exportingDevs ? 'Exporting…' : 'Export devices.csv'}
              </button>
            </div>

            {/* Fingerprint DB export */}
            <div className="card p-4 space-y-2">
              <div className="flex items-center justify-between">
                <p className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>
                  Fingerprint Database
                </p>
                {fpStats && (
                  <span
                    className="text-xs px-2 py-0.5 rounded-full"
                    style={{
                      background: 'color-mix(in srgb, var(--color-brand) 12%, var(--color-surface-offset))',
                      color: 'var(--color-brand)',
                    }}
                  >
                    {fpStats.total} entries
                  </span>
                )}
              </div>
              {fpStats && (
                <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                  {fpStats.manual} manual · {fpStats.community} community · {fpStats.auto} auto
                </p>
              )}
              <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                Export your trained fingerprint database to share with other InSpectre
                users. MAC addresses are stripped before export.
              </p>
              <div className="flex gap-2 flex-wrap">
                <button
                  onClick={handleExportFingerprints}
                  disabled={exportingFp}
                  className="btn-secondary flex items-center gap-2 text-sm"
                >
                  <Download size={13} />
                  {exportingFp ? 'Exporting…' : 'Export fingerprints.json'}
                </button>

                <button
                  onClick={() => fileInputRef.current?.click()}
                  className="btn-secondary flex items-center gap-2 text-sm"
                >
                  <Upload size={13} />
                  Import fingerprints.json
                </button>

                {/* Hidden file input */}
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".json,application/json"
                  className="sr-only"
                  onChange={handleImportFingerprints}
                />
              </div>

              {/* Import result feedback */}
              {importStatus === 'loading' && (
                <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>Importing…</p>
              )}
              {importStatus === 'error' && (
                <p className="text-xs" style={{ color: 'var(--color-error)' }}>
                  Import failed — check the file is a valid InSpectre fingerprints.json.
                </p>
              )}
              {importStatus && importStatus !== 'loading' && importStatus !== 'error' && (
                <div
                  className="rounded-lg p-3 text-xs space-y-1"
                  style={{
                    background: 'color-mix(in srgb, var(--color-success) 10%, var(--color-surface-offset))',
                    color: 'var(--color-success)',
                  }}
                >
                  <p className="font-medium">Import complete ✓</p>
                  <p>{importStatus.inserted} new · {importStatus.merged} merged · {importStatus.corrected} devices auto-corrected</p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div
          className="px-6 py-4 flex gap-3"
          style={{ borderTop: '1px solid var(--color-border)' }}
        >
          <button
            onClick={handleSave}
            disabled={!hasDirty || saving}
            className={`btn-primary flex-1 flex items-center justify-center gap-2 ${
              !hasDirty || saving ? 'opacity-40 cursor-not-allowed' : ''
            }`}
          >
            <Save size={14} />
            {saving ? 'Saving…' : saved ? 'Saved ✓' : 'Save Changes'}
          </button>
          <button onClick={handleReset} className="btn-ghost flex items-center gap-2">
            <RotateCcw size={14} /> Reset
          </button>
        </div>
      </aside>
    </>
  )
}
