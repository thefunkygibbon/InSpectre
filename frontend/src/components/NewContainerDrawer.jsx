import { useState } from 'react'
import { X, Loader2, Plus } from 'lucide-react'
import { api } from '../api'

const inputClass = 'w-full rounded-lg border bg-transparent px-3 py-2 text-xs text-text focus:outline-none'
const inputStyle = { borderColor: 'var(--color-border)', background: 'var(--color-surface-offset)' }

export function NewContainerDrawer({ hosts = [], onClose, onCreated }) {
  const [mode, setMode] = useState('form')
  const [hostId, setHostId] = useState(hosts[0]?.id ? String(hosts[0].id) : '')
  const [name, setName] = useState('')
  const [image, setImage] = useState('')
  const [command, setCommand] = useState('')
  const [ports, setPorts] = useState('')
  const [environment, setEnvironment] = useState('')
  const [volumes, setVolumes] = useState('')
  const [network, setNetwork] = useState('')
  const [restart, setRestart] = useState('no')
  const [runAsUser, setRunAsUser] = useState('')
  const [hostname, setHostname] = useState('')
  const [workingDirectory, setWorkingDirectory] = useState('')
  const [memoryLimit, setMemoryLimit] = useState('')
  const [cpuShares, setCpuShares] = useState('')
  const [privileged, setPrivileged] = useState(false)
  const [readOnly, setReadOnly] = useState(false)
  const [advancedOptions, setAdvancedOptions] = useState('')
  const [composeYaml, setComposeYaml] = useState('')
  const [composeService, setComposeService] = useState('')
  const [vmid, setVmid] = useState('')
  const [node, setNode] = useState('')
  const [template, setTemplate] = useState('')
  const [storage, setStorage] = useState('local-lvm')
  const [disk, setDisk] = useState('8')
  const [memory, setMemory] = useState('512')
  const [cores, setCores] = useState('1')
  const [ipAddress, setIpAddress] = useState('')
  const [gateway, setGateway] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const selectedHost = hosts.find(h => String(h.id) === String(hostId))

  async function submit(e) {
    e.preventDefault()
    setBusy(true); setError('')
    const lines = value => value.split('\n').map(v => v.trim()).filter(Boolean)
    let parsedAdvancedOptions
    if (selectedHost?.type !== 'proxmox' && advancedOptions.trim()) {
      try {
        parsedAdvancedOptions = JSON.parse(advancedOptions)
        if (!parsedAdvancedOptions || Array.isArray(parsedAdvancedOptions) || typeof parsedAdvancedOptions !== 'object') {
          throw new Error('Advanced options must be a JSON object.')
        }
      } catch (err) {
        setError(err.message || 'Advanced options must be valid JSON.')
        setBusy(false)
        return
      }
    }
    const configuredOptions = { ...(parsedAdvancedOptions || {}) }
    if (runAsUser.trim()) configuredOptions.user = runAsUser.trim()
    if (hostname.trim()) configuredOptions.hostname = hostname.trim()
    if (workingDirectory.trim()) configuredOptions.working_dir = workingDirectory.trim()
    if (memoryLimit.trim()) configuredOptions.mem_limit = memoryLimit.trim()
    if (cpuShares.trim()) {
      const value = Number(cpuShares)
      if (!Number.isInteger(value) || value < 2) {
        setError('CPU shares must be a whole number of at least 2.')
        setBusy(false)
        return
      }
      configuredOptions.cpu_shares = value
    }
    if (privileged) configuredOptions.privileged = true
    if (readOnly) configuredOptions.read_only = true
    const body = selectedHost?.type === 'proxmox'
      ? { host_id: Number(hostId), name, vmid: Number(vmid), proxmox_node: node || undefined, ostemplate: template, storage, disk_gb: Number(disk), memory_mb: Number(memory), cores: Number(cores), ip_address: ipAddress || undefined, gateway: gateway || undefined }
      : mode === 'compose'
      ? { host_id: hostId ? Number(hostId) : undefined, compose_yaml: composeYaml, compose_service: composeService || undefined }
      : {
          host_id: hostId ? Number(hostId) : undefined, name, image, command: command || undefined,
          ports: lines(ports), environment: lines(environment), volumes: lines(volumes),
          network: network || undefined, restart_policy: restart,
        }
    if (selectedHost?.type !== 'proxmox' && Object.keys(configuredOptions).length > 0) {
      body.advanced_options = configuredOptions
    }
    try {
      const created = await api.dockerCreate(body)
      onCreated(created)
    } catch (err) {
      setError(err.message || 'Failed to create container.')
    } finally { setBusy(false) }
  }

  return (
    <>
      <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40" onClick={onClose} />
      <aside className="fixed right-0 top-0 h-full w-full max-w-md bg-surface border-l border-border z-50 flex flex-col shadow-2xl">
        <div className="flex items-center justify-between px-6 py-5 border-b border-border">
          <h2 className="font-semibold text-text">Create container</h2>
          <button onClick={onClose} className="btn-ghost p-1" aria-label="Close"><X size={16} /></button>
        </div>
        <form onSubmit={submit} className="flex-1 overflow-y-auto px-6 py-5 space-y-4">
          {hosts.length > 0 && (
            <label className="block text-xs text-text-muted">Deployment target
              <select className={inputClass} style={inputStyle} value={hostId} onChange={e => setHostId(e.target.value)}>
                {hosts.map(h => <option key={h.id} value={h.id}>{h.name}</option>)}
              </select>
            </label>
          )}
          {selectedHost?.type !== 'proxmox' && <div className="flex gap-1 rounded-lg p-1" style={{ background: 'var(--color-surface-offset)' }}>
            {['form', 'compose'].map(value => (
              <button type="button" key={value} onClick={() => setMode(value)}
                className="flex-1 rounded-md px-3 py-2 text-xs font-medium"
                style={mode === value ? { background: 'var(--color-brand)', color: 'white' } : { color: 'var(--color-text-muted)' }}>
                {value === 'form' ? 'Container settings' : 'Compose YAML'}
              </button>
            ))}
          </div>}
          {selectedHost?.type === 'proxmox' ? (
            <>
              <p className="text-xs text-text-muted">Proxmox LXC deployment</p>
              <label className="block text-xs text-text-muted">Hostname<input required className={inputClass} style={inputStyle} value={name} onChange={e => setName(e.target.value)} /></label>
              <label className="block text-xs text-text-muted">VMID<input required type="number" className={inputClass} style={inputStyle} value={vmid} onChange={e => setVmid(e.target.value)} /></label>
              <label className="block text-xs text-text-muted">Node<input className={inputClass} style={inputStyle} value={node} onChange={e => setNode(e.target.value)} placeholder={selectedHost.node || 'pve'} /></label>
              <label className="block text-xs text-text-muted">OS template<input required className={inputClass} style={inputStyle} value={template} onChange={e => setTemplate(e.target.value)} placeholder="local:vztmpl/debian-12-standard.tar.zst" /></label>
              <div className="grid grid-cols-2 gap-2">
                <label className="text-xs text-text-muted">Storage<input className={inputClass} style={inputStyle} value={storage} onChange={e => setStorage(e.target.value)} /></label>
                <label className="text-xs text-text-muted">Disk (GB)<input type="number" className={inputClass} style={inputStyle} value={disk} onChange={e => setDisk(e.target.value)} /></label>
                <label className="text-xs text-text-muted">Memory (MB)<input type="number" className={inputClass} style={inputStyle} value={memory} onChange={e => setMemory(e.target.value)} /></label>
                <label className="text-xs text-text-muted">Cores<input type="number" className={inputClass} style={inputStyle} value={cores} onChange={e => setCores(e.target.value)} /></label>
              </div>
              <label className="block text-xs text-text-muted">IPv4/CIDR (optional)<input className={inputClass} style={inputStyle} value={ipAddress} onChange={e => setIpAddress(e.target.value)} placeholder="dhcp or 192.168.1.50/24" /></label>
              <label className="block text-xs text-text-muted">Gateway (optional)<input className={inputClass} style={inputStyle} value={gateway} onChange={e => setGateway(e.target.value)} /></label>
            </>
          ) : mode === 'compose' ? (
            <>
              <label className="block text-xs text-text-muted">Service name (optional)
                <input className={inputClass} style={inputStyle} value={composeService} onChange={e => setComposeService(e.target.value)} placeholder="web" />
              </label>
              <label className="block text-xs text-text-muted">Compose YAML
                <textarea required className={`${inputClass} min-h-80 font-mono`} style={inputStyle} value={composeYaml} onChange={e => setComposeYaml(e.target.value)} placeholder={'services:\n  web:\n    image: nginx:latest\n    ports:\n      - "8080:80"'} />
              </label>
            </>
          ) : (
            <>
              <label className="block text-xs text-text-muted">Name<input required className={inputClass} style={inputStyle} value={name} onChange={e => setName(e.target.value)} /></label>
              <label className="block text-xs text-text-muted">Image<input required className={inputClass} style={inputStyle} value={image} onChange={e => setImage(e.target.value)} placeholder="nginx:latest" /></label>
              <label className="block text-xs text-text-muted">Command (optional)<input className={inputClass} style={inputStyle} value={command} onChange={e => setCommand(e.target.value)} /></label>
              <label className="block text-xs text-text-muted">Port mappings <span className="text-text-faint">(one per line, host:container)</span><textarea className={inputClass} style={inputStyle} value={ports} onChange={e => setPorts(e.target.value)} placeholder="8080:80" /></label>
              <label className="block text-xs text-text-muted">Environment <span className="text-text-faint">(KEY=value per line)</span><textarea className={inputClass} style={inputStyle} value={environment} onChange={e => setEnvironment(e.target.value)} /></label>
              <label className="block text-xs text-text-muted">Volumes <span className="text-text-faint">(host:container per line)</span><textarea className={inputClass} style={inputStyle} value={volumes} onChange={e => setVolumes(e.target.value)} /></label>
              <label className="block text-xs text-text-muted">Network (optional)<input className={inputClass} style={inputStyle} value={network} onChange={e => setNetwork(e.target.value)} placeholder="bridge" /></label>
              <label className="block text-xs text-text-muted">Restart policy
                <select className={inputClass} style={inputStyle} value={restart} onChange={e => setRestart(e.target.value)}>
                  {['no', 'always', 'unless-stopped', 'on-failure'].map(v => <option key={v}>{v}</option>)}
                </select>
              </label>
              <details className="rounded-lg border p-3" style={{ borderColor: 'var(--color-border)' }}>
                <summary className="cursor-pointer text-xs font-medium text-text">Advanced Docker options</summary>
                <p className="mt-2 text-[11px] leading-relaxed text-text-faint">
                  Configure common runtime settings or enter additional Docker create options as JSON. For example, use cap_drop, cap_add, devices, dns, labels, security_opt, sysctls, or tmpfs.
                </p>
                <div className="grid grid-cols-2 gap-2 mt-3">
                  <label className="text-xs text-text-muted">User
                    <input className={inputClass} style={inputStyle} value={runAsUser} onChange={e => setRunAsUser(e.target.value)} placeholder="1000:1000" />
                  </label>
                  <label className="text-xs text-text-muted">Hostname
                    <input className={inputClass} style={inputStyle} value={hostname} onChange={e => setHostname(e.target.value)} />
                  </label>
                  <label className="text-xs text-text-muted">Memory limit
                    <input className={inputClass} style={inputStyle} value={memoryLimit} onChange={e => setMemoryLimit(e.target.value)} placeholder="512m" />
                  </label>
                  <label className="text-xs text-text-muted">CPU shares
                    <input type="number" min="2" step="1" className={inputClass} style={inputStyle} value={cpuShares} onChange={e => setCpuShares(e.target.value)} placeholder="1024" />
                  </label>
                  <label className="col-span-2 text-xs text-text-muted">Working directory
                    <input className={inputClass} style={inputStyle} value={workingDirectory} onChange={e => setWorkingDirectory(e.target.value)} placeholder="/app" />
                  </label>
                </div>
                <div className="flex gap-4 mt-3">
                  <label className="flex items-center gap-2 text-xs text-text-muted">
                    <input type="checkbox" checked={privileged} onChange={e => setPrivileged(e.target.checked)} />
                    Privileged
                  </label>
                  <label className="flex items-center gap-2 text-xs text-text-muted">
                    <input type="checkbox" checked={readOnly} onChange={e => setReadOnly(e.target.checked)} />
                    Read-only root filesystem
                  </label>
                </div>
                <textarea
                  className={`${inputClass} mt-2 min-h-28 font-mono`}
                  style={inputStyle}
                  value={advancedOptions}
                  onChange={e => setAdvancedOptions(e.target.value)}
                  placeholder={'{\n  "mem_limit": "512m",\n  "cpu_shares": 512,\n  "cap_drop": ["ALL"],\n  "read_only": true\n}'}
                  aria-label="Advanced Docker options JSON"
                />
              </details>
            </>
          )}
          {error && <p className="text-xs text-red-400">{error}</p>}
          <button type="submit" disabled={busy} className="btn-primary w-full flex items-center justify-center gap-2">
            {busy ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />} Create container
          </button>
        </form>
      </aside>
    </>
  )
}
