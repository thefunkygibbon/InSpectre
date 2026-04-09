import { useState, useEffect } from 'react'
import { Save, RotateCcw, Settings2, X } from 'lucide-react'
import { api } from '../api'

const SETTING_META = {
  scan_interval:          { label: 'Scan Interval',          unit: 'seconds', type: 'number', min: 5,   max: 3600 },
  offline_miss_threshold: { label: 'Offline Threshold',      unit: 'missed sweeps', type: 'number', min: 1, max: 20 },
  os_confidence_threshold:{ label: 'OS Confidence Min',      unit: '%',       type: 'number', min: 50,  max: 100 },
  sniffer_workers:        { label: 'Sniffer Workers',        unit: 'threads', type: 'number', min: 1,   max: 16 },
  ip_range:               { label: 'IP Range',               unit: '',        type: 'text' },
  nmap_args:              { label: 'Nmap Arguments',         unit: '',        type: 'text' },
}

export function SettingsPanel({ onClose }) {
  const [settings, setSettings] = useState([])
  const [dirty, setDirty]       = useState({})
  const [saving, setSaving]     = useState(false)
  const [saved, setSaved]       = useState(false)

  useEffect(() => {
    api.getSettings().then(setSettings)
  }, [])

  function handleChange(key, value) {
    setDirty(d => ({ ...d, [key]: value }))
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
    api.getSettings().then(s => { setSettings(s); setDirty({}) })
  }

  const hasDirty = Object.keys(dirty).length > 0

  return (
    <>
      <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 animate-fade-in" onClick={onClose} />
      <aside className="fixed right-0 top-0 h-full w-full max-w-md bg-gray-900 border-l border-white/8
                        z-50 flex flex-col shadow-2xl animate-slide-in">
        <div className="flex items-center justify-between px-6 py-5 border-b border-white/8">
          <div className="flex items-center gap-3">
            <Settings2 size={18} className="text-brand-400" />
            <h2 className="font-semibold text-gray-100">Settings</h2>
          </div>
          <button onClick={onClose} className="btn-ghost p-2" aria-label="Close"><X size={18} /></button>
        </div>

        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-4">
          <p className="text-xs text-gray-500">
            Changes are written to the database immediately. The probe reads these values
            at the start of each scan cycle — no restart needed.
          </p>

          {settings.map(s => {
            const meta = SETTING_META[s.key] || { label: s.key, type: 'text', unit: '' }
            const value = dirty[s.key] ?? s.value
            return (
              <div key={s.key} className="card p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <label className="text-sm font-medium text-gray-200">{meta.label}</label>
                  {meta.unit && <span className="text-xs text-gray-500">{meta.unit}</span>}
                </div>
                <input
                  type={meta.type || 'text'}
                  min={meta.min}
                  max={meta.max}
                  className={`input ${dirty[s.key] !== undefined ? 'border-brand-500/50' : ''}`}
                  value={value}
                  onChange={e => handleChange(s.key, e.target.value)}
                />
                {s.description && (
                  <p className="text-xs text-gray-600">{s.description}</p>
                )}
              </div>
            )
          })}
        </div>

        <div className="px-6 py-4 border-t border-white/8 flex gap-3">
          <button
            onClick={handleSave}
            disabled={!hasDirty || saving}
            className={`btn-primary flex-1 flex items-center justify-center gap-2
              ${ (!hasDirty || saving) ? 'opacity-40 cursor-not-allowed' : '' }`}
          >
            <Save size={14} />
            {saving ? 'Saving…' : saved ? 'Saved!' : 'Save Changes'}
          </button>
          <button onClick={handleReset} className="btn-ghost flex items-center gap-2">
            <RotateCcw size={14} />Reset
          </button>
        </div>
      </aside>
    </>
  )
}
