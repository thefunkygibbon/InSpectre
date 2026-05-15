import { useState, useEffect, useCallback } from 'react'
import { Activity, X, CheckCircle2, XCircle, AlertCircle, Database, Server, Cpu, RefreshCw, Scan, Shield } from 'lucide-react'
import { api } from '../api'

const POLL_MS = 60_000

function ComponentRow({ label, Icon, status }) {
  const ok = status?.ok
  return (
    <div className="flex items-center gap-3 py-2.5"
      style={{ borderBottom: '1px solid var(--color-border)' }}>
      <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
        style={{ background: 'var(--color-surface-offset)' }}>
        <Icon size={15} style={{ color: 'var(--color-text-muted)' }} />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>{label}</p>
        {status?.message && (
          <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-muted)' }}>
            {status.message}
          </p>
        )}
      </div>
      {ok === undefined ? (
        <div className="w-4 h-4 rounded-full skeleton shrink-0" />
      ) : ok ? (
        <CheckCircle2 size={16} style={{ color: '#10b981', flexShrink: 0 }} />
      ) : (
        <XCircle size={16} style={{ color: '#ef4444', flexShrink: 0 }} />
      )}
    </div>
  )
}

function ActiveScansList({ scans, icon: Icon, label, color }) {
  if (!scans?.length) return null
  return (
    <div className="mt-3">
      <div className="flex items-center gap-1.5 mb-1.5">
        <Icon size={11} style={{ color, flexShrink: 0 }} />
        <span className="text-[11px] font-semibold uppercase tracking-wider" style={{ color }}>
          {label}
        </span>
      </div>
      <div className="flex flex-col gap-1">
        {scans.map(s => (
          <div key={s.mac} className="flex items-center gap-2 px-2 py-1 rounded-lg text-xs"
            style={{ background: 'var(--color-surface-offset)' }}>
            <span className="w-1.5 h-1.5 rounded-full shrink-0 animate-pulse" style={{ background: color }} />
            <span className="font-medium truncate" style={{ color: 'var(--color-text)' }}>{s.name}</span>
            {s.name !== s.mac && (
              <span className="font-mono text-[10px] shrink-0" style={{ color: 'var(--color-text-faint)' }}>{s.mac}</span>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

export function StatusButton() {
  const [health, setHealth]           = useState(null)
  const [showModal, setShowModal]     = useState(false)
  const [lastChecked, setLastChecked] = useState(null)
  const [refreshing, setRefreshing]   = useState(false)

  const check = useCallback(async () => {
    setRefreshing(true)
    try {
      const data = await api.getHealth()
      setHealth(data)
    } catch {
      setHealth({
        backend:  { ok: false, message: 'Unreachable' },
        database: { ok: false, message: 'Unknown' },
        probe:    { ok: false, message: 'Unknown' },
        all_ok: false,
        active_scans: { port: [], vuln: [] },
      })
    } finally {
      setLastChecked(new Date())
      setRefreshing(false)
    }
  }, [])

  useEffect(() => {
    check()
    const id = setInterval(check, POLL_MS)
    return () => clearInterval(id)
  }, [check])

  const allOk = health?.all_ok
  const color = health === null
    ? 'var(--color-text-faint)'
    : allOk ? '#10b981' : '#ef4444'
  const label = health === null
    ? 'Checking…'
    : allOk ? 'All systems OK' : 'System issue'

  const portScans = health?.active_scans?.port || []
  const vulnScans = health?.active_scans?.vuln || []
  const totalActive = portScans.length + vulnScans.length

  return (
    <>
      <button
        onClick={() => { setShowModal(true); check() }}
        className="flex items-center gap-1.5 text-xs transition-opacity hover:opacity-75"
        style={{ color }}
        title="Click for system status"
      >
        <Activity size={12} />
        <span>{label}</span>
        {totalActive > 0 && (
          <span className="px-1.5 py-0.5 rounded-full text-[10px] font-semibold"
            style={{ background: 'color-mix(in srgb, var(--color-brand) 15%, transparent)', color: 'var(--color-brand)' }}>
            {totalActive} active
          </span>
        )}
      </button>

      {showModal && (
        <>
          <div
            className="fixed inset-0 z-50"
            style={{ background: 'rgba(0,0,0,0.4)', backdropFilter: 'blur(4px)' }}
            onClick={() => setShowModal(false)}
          />
          <div
            className="fixed z-50 left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-sm rounded-2xl shadow-2xl p-6"
            style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)' }}
          >
            {/* Header */}
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-base font-semibold" style={{ color: 'var(--color-text)' }}>
                System Status
              </h2>
              <button
                onClick={() => setShowModal(false)}
                className="opacity-50 hover:opacity-100 transition-opacity"
                aria-label="Close"
              >
                <X size={16} />
              </button>
            </div>

            {/* Component rows */}
            <div>
              <ComponentRow label="Backend API" Icon={Server}   status={health?.backend}  />
              <ComponentRow label="Database"    Icon={Database} status={health?.database} />
              <ComponentRow label="Probe"       Icon={Cpu}      status={health?.probe}    />
            </div>

            {/* Active scan activity */}
            {(portScans.length > 0 || vulnScans.length > 0) && (
              <div className="mt-4 pt-4" style={{ borderTop: '1px solid var(--color-border)' }}>
                <p className="text-xs font-semibold uppercase tracking-wider mb-1"
                  style={{ color: 'var(--color-text-muted)' }}>
                  Probe Activity
                </p>
                <ActiveScansList scans={portScans} icon={Scan}   label="Port scanning" color="#f59e0b" />
                <ActiveScansList scans={vulnScans} icon={Shield} label="Vuln scanning"  color="var(--color-brand)" />
              </div>
            )}

            {/* Footer row */}
            <div className="mt-4 flex items-center justify-between gap-2">
              {/* Overall status badge */}
              <div
                className="flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-lg font-medium"
                style={{
                  background: health === null
                    ? 'var(--color-surface-offset)'
                    : allOk ? 'rgba(16,185,129,0.1)' : 'rgba(239,68,68,0.1)',
                  color: health === null
                    ? 'var(--color-text-muted)'
                    : allOk ? '#10b981' : '#ef4444',
                }}
              >
                {health === null ? (
                  <AlertCircle size={12} />
                ) : allOk ? (
                  <CheckCircle2 size={12} />
                ) : (
                  <XCircle size={12} />
                )}
                <span>{label}</span>
              </div>

              <div className="flex items-center gap-2">
                {lastChecked && (
                  <span className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                    {lastChecked.toLocaleTimeString()}
                  </span>
                )}
                <button
                  onClick={check}
                  disabled={refreshing}
                  className="flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-lg transition-opacity disabled:opacity-40"
                  style={{ background: 'var(--color-surface-offset)', color: 'var(--color-text-muted)' }}
                  title="Refresh"
                >
                  <RefreshCw size={12} className={refreshing ? 'animate-spin' : ''} />
                  <span>Refresh</span>
                </button>
              </div>
            </div>
          </div>
        </>
      )}
    </>
  )
}
