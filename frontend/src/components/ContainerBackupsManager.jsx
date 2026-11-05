import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import {
  Eye, Download, RotateCcw, Trash2, RefreshCw, Search, X, Copy, Check,
  ChevronDown, ChevronRight, AlertTriangle, Loader2,
} from 'lucide-react'
import { api } from '../api'
import { JobLog, formatJobLine } from './JobLog'

function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

function YamlModal({ title, yaml, onClose }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.6)' }}
      onClick={e => { if (e.target === e.currentTarget) onClose() }}>
      <div className="rounded-xl shadow-2xl flex flex-col w-full max-w-2xl"
        style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', maxHeight: '85vh' }}>
        <div className="flex items-center justify-between px-4 py-3 border-b shrink-0" style={{ borderColor: 'var(--color-border)' }}>
          <span className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>{title}</span>
          <div className="flex items-center gap-2">
            <button className="btn-ghost flex items-center gap-1 text-xs"
              onClick={() => navigator.clipboard.writeText(yaml).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000) })}>
              {copied ? <Check size={11} /> : <Copy size={11} />} {copied ? 'Copied!' : 'Copy'}
            </button>
            <button onClick={onClose} className="btn-ghost p-1"><X size={14} /></button>
          </div>
        </div>
        <pre className="flex-1 overflow-auto p-4 text-[11px] font-mono leading-relaxed" style={{ color: 'var(--color-text)', whiteSpace: 'pre' }}>
          {yaml}
        </pre>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Container compose backups — view / download / restore / delete, including
// backups for containers that no longer exist on the host.
// ---------------------------------------------------------------------------
export function ContainerBackupsManager() {
  const [backups,   setBackups]   = useState(null)
  const [error,     setError]     = useState('')
  const [query,     setQuery]     = useState('')
  const [missingOnly, setMissingOnly] = useState(false)
  const [expanded,  setExpanded]  = useState({})
  const [viewYaml,  setViewYaml]  = useState(null)
  const [confirm,   setConfirm]   = useState(null)   // { type: 'restore'|'delete', id }
  const [restore,   setRestore]   = useState(null)   // { id, name, lines, running }
  const [exporting, setExporting] = useState(false)
  const abortRef = useRef(null)

  const load = useCallback(async () => {
    try {
      const res = await api.dockerListAllBackups()
      setBackups(res.backups || [])
      setError('')
    } catch (e) {
      setError(e.message || 'Failed to load backups')
      setBackups([])
    }
  }, [])

  useEffect(() => { load() }, [load])
  useEffect(() => () => abortRef.current?.abort(), [])

  const groups = useMemo(() => {
    const map = new Map()
    for (const b of backups || []) {
      if (!map.has(b.container_name)) map.set(b.container_name, [])
      map.get(b.container_name).push(b)
    }
    const q = query.trim().toLowerCase()
    return [...map.entries()]
      .map(([name, items]) => ({ name, items, missing: items[0].container_exists === false }))
      .filter(g => (!q || g.name.toLowerCase().includes(q)) && (!missingOnly || g.missing))
      .sort((a, b) => (b.missing - a.missing) || a.name.localeCompare(b.name))
  }, [backups, query, missingOnly])

  async function view(b) {
    try {
      const res = await api.dockerGetBackupCompose(b.id)
      setViewYaml({ title: `Backup #${b.id} — ${b.container_name}`, yaml: res.compose_yaml })
    } catch (e) { setError(e.message) }
  }

  async function download(b) {
    try {
      const res = await api.dockerGetBackupCompose(b.id)
      saveBlob(new Blob([res.compose_yaml], { type: 'text/yaml' }), `${b.container_name}_backup_${b.id}.yml`)
    } catch (e) { setError(e.message) }
  }

  async function exportZip(latestOnly) {
    setExporting(true)
    try {
      const res = await api.dockerExportBackups(latestOnly)
      if (!res.ok) throw new Error(`Export failed (${res.status})`)
      saveBlob(await res.blob(), `inspectre-compose-backups${latestOnly ? '-latest' : ''}.zip`)
    } catch (e) { setError(e.message) } finally { setExporting(false) }
  }

  async function remove(b) {
    setConfirm(null)
    try {
      await api.dockerDeleteBackup(b.id)
      setBackups(list => list.filter(x => x.id !== b.id))
    } catch (e) { setError(e.message) }
  }

  function startRestore(b) {
    setConfirm(null)
    abortRef.current?.abort()
    const ctrl = new AbortController()
    abortRef.current = ctrl
    setRestore({ id: b.id, name: b.container_name, lines: [], running: true })
    const push = text => setRestore(r => r && r.id === b.id ? { ...r, lines: [...r.lines, text] } : r)
    api.dockerRecreateFromBackup(b.id, line => {
      push(formatJobLine(line))
      if (line.startsWith('RECREATE_ERROR:') || line === 'RECREATE_DONE') {
        setRestore(r => r && r.id === b.id ? { ...r, running: false } : r)
        load()
      }
    }, ctrl.signal).catch(e => {
      if (ctrl.signal.aborted) return
      push(`❌ ${e.message || 'Restore failed'}`)
      setRestore(r => r && r.id === b.id ? { ...r, running: false } : r)
    })
  }

  function row(b) {
    const askRestore = confirm?.type === 'restore' && confirm.id === b.id
    const askDelete  = confirm?.type === 'delete'  && confirm.id === b.id
    const busy = restore?.running
    return (
      <div key={b.id} className="flex items-center justify-between gap-2 text-xs py-1.5 border-b" style={{ borderColor: 'var(--color-border)' }}>
        <div className="min-w-0">
          <span className="font-mono text-[11px]" style={{ color: 'var(--color-text-muted)' }}>
            {b.backed_up_at ? new Date(b.backed_up_at).toLocaleString() : '—'}
          </span>
          <span className="ml-2 text-[10px] rounded px-1.5 py-0.5" style={{ background: 'rgba(107,114,128,0.1)', color: 'var(--color-text-muted)' }}>
            {b.reason}
          </span>
          <span className="ml-2 text-[10px] font-mono" style={{ color: 'var(--color-text-faint)' }} title={b.image}>
            #{b.id} · {b.image}
          </span>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          {b.has_compose && (<>
            <button onClick={() => view(b)} className="btn-ghost flex items-center gap-1 text-[11px]" title="View compose YAML"><Eye size={10} /> View</button>
            <button onClick={() => download(b)} className="btn-ghost flex items-center gap-1 text-[11px]" title="Download compose YAML"><Download size={10} /> YAML</button>
          </>)}
          {askRestore ? (
            <span className="flex items-center gap-1">
              <span className="text-[10px]" style={{ color: 'var(--color-text-muted)' }}>Recreate?</span>
              <button onClick={() => startRestore(b)} className="text-[10px] px-1.5 py-0.5 rounded font-semibold" style={{ background: 'rgba(239,68,68,0.15)', color: '#ef4444' }}>Yes</button>
              <button onClick={() => setConfirm(null)} className="btn-ghost text-[10px] px-1">No</button>
            </span>
          ) : askDelete ? (
            <span className="flex items-center gap-1">
              <span className="text-[10px]" style={{ color: 'var(--color-text-muted)' }}>Delete?</span>
              <button onClick={() => remove(b)} className="text-[10px] px-1.5 py-0.5 rounded font-semibold" style={{ background: 'rgba(239,68,68,0.15)', color: '#ef4444' }}>Yes</button>
              <button onClick={() => setConfirm(null)} className="btn-ghost text-[10px] px-1">No</button>
            </span>
          ) : (<>
            <button onClick={() => setConfirm({ type: 'restore', id: b.id })} disabled={busy}
              className="btn-ghost flex items-center gap-1 text-[11px]" title="Recreate / restore the container from this backup">
              <RotateCcw size={10} /> Restore
            </button>
            <button onClick={() => setConfirm({ type: 'delete', id: b.id })}
              className="btn-ghost flex items-center gap-1 text-[11px]" title="Delete this backup" style={{ color: '#ef4444' }}>
              <Trash2 size={10} />
            </button>
          </>)}
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {viewYaml && <YamlModal title={viewYaml.title} yaml={viewYaml.yaml} onClose={() => setViewYaml(null)} />}

      <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
        A backup is saved automatically before every compose edit, update and restore. Use <strong>Restore</strong> to
        recreate a container — even one that has disappeared from the Containers page.
      </p>

      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative flex-1 min-w-[160px]">
          <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2" style={{ color: 'var(--color-text-faint)' }} />
          <input className="input text-xs w-full pl-7" placeholder="Filter by container name…" value={query} onChange={e => setQuery(e.target.value)} />
        </div>
        <label className="flex items-center gap-1.5 text-xs cursor-pointer" style={{ color: 'var(--color-text-muted)' }}>
          <input type="checkbox" checked={missingOnly} onChange={e => setMissingOnly(e.target.checked)} />
          Missing containers only
        </label>
        <button onClick={load} className="btn-ghost flex items-center gap-1 text-xs"><RefreshCw size={12} /> Refresh</button>
        <button onClick={() => exportZip(true)} disabled={exporting} className="btn-ghost flex items-center gap-1 text-xs" title="Zip with the newest compose file per container">
          <Download size={12} /> Latest (zip)
        </button>
        <button onClick={() => exportZip(false)} disabled={exporting} className="btn-ghost flex items-center gap-1 text-xs" title="Zip with every stored compose backup">
          <Download size={12} /> All (zip)
        </button>
      </div>

      {error && <p className="text-xs" style={{ color: '#ef4444' }}>{error}</p>}

      {restore && (
        <div className="space-y-1">
          <div className="flex items-center justify-between text-xs" style={{ color: 'var(--color-text)' }}>
            <span className="font-semibold">Restoring {restore.name} from backup #{restore.id}</span>
            {!restore.running && <button onClick={() => setRestore(null)} className="btn-ghost p-1"><X size={12} /></button>}
          </div>
          <JobLog lines={restore.lines} running={restore.running} />
        </div>
      )}

      {backups === null ? (
        <p className="text-xs flex items-center gap-1.5" style={{ color: 'var(--color-text-faint)' }}><Loader2 size={12} className="animate-spin" /> Loading…</p>
      ) : groups.length === 0 ? (
        <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>No backups found.</p>
      ) : (
        <div className="space-y-1.5">
          {groups.map(g => {
            const open = !!expanded[g.name]
            return (
              <div key={g.name} className="rounded-lg border" style={{ borderColor: 'var(--color-border)' }}>
                <button className="w-full flex items-center justify-between gap-2 px-3 py-2 text-xs"
                  onClick={() => setExpanded(e => ({ ...e, [g.name]: !open }))}>
                  <span className="flex items-center gap-1.5 min-w-0" style={{ color: 'var(--color-text)' }}>
                    {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                    <span className="font-semibold truncate">{g.name}</span>
                    {g.missing && (
                      <span className="flex items-center gap-1 text-[10px] rounded px-1.5 py-0.5" style={{ background: 'rgba(239,68,68,0.12)', color: '#ef4444' }}>
                        <AlertTriangle size={9} /> container missing
                      </span>
                    )}
                  </span>
                  <span className="shrink-0" style={{ color: 'var(--color-text-faint)' }}>
                    {g.items.length} backup{g.items.length === 1 ? '' : 's'} · latest {g.items[0].backed_up_at ? new Date(g.items[0].backed_up_at).toLocaleString() : '—'}
                  </span>
                </button>
                {open && <div className="px-3 pb-2">{g.items.map(row)}</div>}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Background container jobs (updates / compose deploys / restores)
// ---------------------------------------------------------------------------
const STATUS_COLORS = {
  running:  '#38bdf8',
  success:  '#22c55e',
  failed:   '#ef4444',
  finished: 'var(--color-text-muted)',
}

export function ContainerJobsPanel() {
  const [jobs,    setJobs]    = useState(null)
  const [openId,  setOpenId]  = useState(null)
  const [lines,   setLines]   = useState([])
  const [following, setFollowing] = useState(false)
  const abortRef = useRef(null)

  const load = useCallback(() => {
    api.dockerJobs().then(setJobs).catch(() => setJobs([]))
  }, [])

  useEffect(() => {
    load()
    const t = setInterval(load, 5000)
    return () => { clearInterval(t); abortRef.current?.abort() }
  }, [load])

  function toggle(job) {
    abortRef.current?.abort()
    if (openId === job.id) { setOpenId(null); setFollowing(false); return }
    setOpenId(job.id)
    setLines([])
    setFollowing(true)
    const ctrl = new AbortController()
    abortRef.current = ctrl
    api.dockerAttachJob(job.id, line => setLines(l => [...l, formatJobLine(line)]), ctrl.signal)
      .catch(e => { if (!ctrl.signal.aborted) setLines(l => [...l, `❌ ${e.message}`]) })
      .finally(() => { if (!ctrl.signal.aborted) { setFollowing(false); load() } })
  }

  if (jobs === null) return <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>Loading…</p>

  return (
    <div className="space-y-2">
      <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
        Updates, compose deploys and restores started from the web UI run on the server and keep going even if
        your browser disconnects. Full logs are also written to <code>container-backups/_job_logs/</code>.
        The list is kept in memory and resets when the backend restarts.
      </p>
      {jobs.length === 0 && <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>No jobs since the backend started.</p>}
      {jobs.map(j => (
        <div key={j.id} className="rounded-lg border" style={{ borderColor: 'var(--color-border)' }}>
          <button className="w-full flex items-center justify-between gap-2 px-3 py-2 text-xs text-left" onClick={() => toggle(j)}>
            <span className="flex items-center gap-1.5 min-w-0" style={{ color: 'var(--color-text)' }}>
              {openId === j.id ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
              {j.status === 'running' && <Loader2 size={11} className="animate-spin" style={{ color: STATUS_COLORS.running }} />}
              <span className="font-semibold">{j.container_name}</span>
              <span style={{ color: 'var(--color-text-faint)' }}>{j.kind}</span>
              <span className="text-[10px] rounded px-1.5 py-0.5" style={{ color: STATUS_COLORS[j.status] || 'var(--color-text-muted)', background: 'rgba(107,114,128,0.1)' }}>
                {j.status}
              </span>
            </span>
            <span className="shrink-0 font-mono text-[10px]" style={{ color: 'var(--color-text-faint)' }}>
              {new Date(j.started_at).toLocaleString()}
            </span>
          </button>
          {openId !== j.id && j.last_line && (
            <div className="px-3 pb-2 text-[10px] font-mono truncate" style={{ color: 'var(--color-text-faint)' }}>
              {formatJobLine(j.last_line)}
            </div>
          )}
          {openId === j.id && <div className="px-3 pb-3"><JobLog lines={lines} running={following} /></div>}
        </div>
      ))}
    </div>
  )
}
