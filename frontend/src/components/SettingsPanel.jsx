import { useState, useEffect, useRef, useCallback } from 'react'
import {
  Save, RotateCcw, Settings2, X, Download, Upload, FileText,
  Database, Bell, ScanLine, Eye, EyeOff, Send, Globe, User, Key, Box,
  AlertTriangle, ChevronDown, ChevronRight, Paintbrush, Package, RefreshCw,
} from 'lucide-react'
import { api } from '../api'
import { COMMON_TIMEZONES } from '../timezones'
import { HostsManager } from './HostsManager'
import { useTheme } from '../hooks/useTheme'
import { NotificationsTab } from './NotificationsTab'
import { PluginsTab } from './PluginsTab'
import { StreamOutput } from './StreamOutput'

// ── Setting definitions ────────────────────────────────────────────────────────
const SETTING_META = {
  // Scanner tab
  scan_interval:           { label: 'Scan Interval',       unit: 'seconds',       type: 'number', min: 5,  max: 3600, tab: 'scanner',
    description: 'How often the probe sweeps the network looking for devices.' },
  offline_miss_threshold:  { label: 'Offline Threshold',   unit: 'missed sweeps', type: 'number', min: 1,  max: 20,   tab: 'scanner',
    description: 'How many consecutive missed ARP sweeps before a device is marked offline.' },
  sniffer_workers:         { label: 'Sniffer Workers',     unit: 'threads',       type: 'number', min: 1,  max: 16,   tab: 'scanner',
    description: 'Number of parallel packet capture threads. Requires probe restart to take effect.' },
  arp_scan_retry:          { label: 'ARP Sweep Retries',   unit: 'extra rounds',  type: 'number', min: 0,  max: 3,    tab: 'scanner',
    description: 'Extra ARP broadcast rounds per sweep (0 = single pass, 1 = two rounds). Each retry wakes sleeping mobile devices and adds broadcast traffic. The passive sniffer catches most devices that miss sweeps.' },
  primary_ip_mode: { label: 'Primary IP Update Mode', type: 'select', tab: 'scanner',
    options: [
      { value: 'locked',  label: 'Locked — respect per-device IP lock (default)' },
      { value: 'dynamic', label: 'Dynamic — always adopt new IP on offline return (main-style)' },
    ],
    description: 'Controls how the primary IP is updated when a device returns from offline at a different IP. Locked: honours the per-device lock flag set in the device drawer. Dynamic: always updates primary IP to track DHCP changes, ignoring any lock.' },
  ip_range:                { label: 'IP Range',            unit: '',              type: 'text',              tab: 'scanner' },
  dns_server:              { label: 'LAN DNS Server',      unit: 'IP',            type: 'text',              tab: 'scanner',
    description: 'DNS server used for hostname resolution. Leave blank to auto-detect from host.' },
  probe_interface:         { label: 'Probe Interface',     unit: '',              type: 'text',              tab: 'scanner',
    description: 'Network interface the probe uses for scanning (e.g. eth0, eno1). Leave blank to auto-detect.' },
  fingerbank_api_key:      { label: 'Fingerbank API Key',  unit: '',              type: 'text',              tab: 'scanner',
    description: 'Free API key from fingerbank.org. When set, DHCP fingerprints are sent to Fingerbank for cloud device identification. Results appear in the DHCP Fingerprint section of each device.' },
  vuln_scan_templates:     { label: 'Vuln Scan Templates', unit: '',              type: 'text',              tab: 'scanner',
    description: 'Comma-separated template tags for vulnerability scanning (e.g. cve,exposure,misconfig,default-login,network).' },
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
  vuln_scan_on_port_change: { label: 'Vuln-scan on Port Change', type: 'toggle', tab: 'scanner',
    description: 'Automatically trigger a vulnerability scan when a new port is detected on a device.' },
  nightly_scan_start:     { label: 'Nightly Scan Window Start', unit: 'hour (0–23)', type: 'number', min: 0, max: 23, tab: 'scanner',
    description: 'Hour of day (24h) when the nightly deep-scan window begins.' },
  nightly_scan_end:       { label: 'Nightly Scan Window End',   unit: 'hour (0–23)', type: 'number', min: 0, max: 23, tab: 'scanner',
    description: 'Hour of day (24h) when the nightly deep-scan window closes.' },
  offline_rescan_hours:   { label: 'Offline Return Rescan',  unit: 'hours offline', type: 'number', min: 1, max: 168, tab: 'scanner',
    description: 'Re-run a deep scan when a device returns online after being offline for this many hours.' },
  baseline_scan_count_threshold: { label: 'Baseline Confirmation Scans', unit: 'scans', type: 'number', min: 1, max: 10, tab: 'scanner',
    description: 'Number of consecutive matching scans required before a port baseline is confirmed.' },
  nuclei_template_update_interval: { label: 'Vuln Template Updates', type: 'select', tab: 'scanner',
    options: [
      { value: 'disabled', label: 'Disabled' },
      { value: '12h',      label: 'Every 12 hours' },
      { value: '24h',      label: 'Daily (default)' },
      { value: '48h',      label: 'Every 48 hours' },
      { value: 'weekly',   label: 'Weekly' },
    ],
    description: 'How often the probe automatically updates vulnerability scan templates.' },

  // Docker monitoring — handled as custom cards, referenced here for tab routing
  docker_enabled:        { tab: 'docker' },
  docker_host:           { tab: 'docker' },
  docker_tls_verify:     { tab: 'docker' },
  trivy_db_update_frequency: { label: 'Trivy DB Auto-Update', type: 'select', tab: 'docker',
    options: [
      { value: 'disabled', label: 'Disabled' },
      { value: '1d',       label: 'Daily' },
      { value: '2d',       label: 'Every 2 days' },
      { value: '7d',       label: 'Weekly' },
      { value: '30d',      label: 'Monthly' },
    ],
    description: 'How often to automatically refresh the Trivy vulnerability database.' },
  docker_scan_on_new:    { label: 'Scan New Containers',     type: 'toggle', tab: 'docker',
    description: 'Automatically run a Trivy vulnerability scan when a new container is created.' },
  docker_scan_on_update: { label: 'Scan Updated Containers', type: 'toggle', tab: 'docker',
    description: 'Automatically run a Trivy vulnerability scan when a container is recreated with an updated image.' },

  // Container update management
  container_update_check_interval: { label: 'Update Check Interval', type: 'select', tab: 'docker',
    options: [
      { value: 'disabled', label: 'Disabled' },
      { value: '1h',       label: 'Every hour' },
      { value: '6h',       label: 'Every 6 hours' },
      { value: '12h',      label: 'Every 12 hours' },
      { value: '24h',      label: 'Every 24 hours' },
    ],
    description: 'How often to check Docker registries for newer image versions. Uses only registry manifest calls — no image pulls.' },
  container_auto_update: { label: 'Auto-Update Mode', type: 'select', tab: 'docker',
    options: [
      { value: 'disabled',        label: 'Disabled — notify only' },
      { value: 'scan_then_update', label: 'Scan then update (block on critical CVEs)' },
      { value: 'auto',            label: 'Auto-update (no scan gate)' },
    ],
    description: 'What to do when an update is detected. Scan-then-update runs Trivy on the new image before deploying.' },
  container_update_block_critical: { label: 'Block Updates with Critical CVEs', type: 'toggle', tab: 'docker',
    description: 'Prevent container updates if the new image contains critical-severity CVEs. The update can still be forced manually from the drawer.' },
  container_backup_enabled: { label: 'Auto-Backup Before Update', type: 'toggle', tab: 'docker',
    description: 'Always capture a full config backup (docker inspect JSON + compose YAML) before any container update.' },
  container_update_health_timeout: { label: 'Health Check Timeout (seconds)', type: 'text', tab: 'docker',
    description: 'How long to wait for a container to become healthy after an update before triggering automatic rollback. Default: 30.' },
  container_update_stagger_seconds: { label: 'Stagger Between Updates (seconds)', type: 'text', tab: 'docker',
    description: 'Delay between each container when running a batch auto-update, to avoid hammering the registry and the Docker host simultaneously.' },
  container_update_pin_labels: { label: 'Honour Pin Labels', type: 'toggle', tab: 'docker',
    description: 'Respect the com.inspectre.update.pin=true Docker label on containers to exclude them from auto-updates.' },

  // Data tab — traffic monitoring
  traffic_enabled:        { label: 'Enable Traffic Monitoring',  type: 'toggle', tab: 'data',
    description: 'Allow per-device traffic capture sessions. Disable to prevent all traffic monitoring.' },
  traffic_retention_days: { label: 'Traffic Data Retention', unit: 'days',     type: 'number', min: 1, max: 365, tab: 'data',
    description: 'How many days to keep traffic statistics before automatic deletion.' },
  traffic_max_sessions:   { label: 'Max Concurrent Sessions', unit: 'sessions', type: 'number', min: 1, max: 50, tab: 'data',
    description: 'Maximum number of simultaneous traffic monitoring sessions allowed.' },

  // Data tab — speed test
  speedtest_schedule: { label: 'Scheduled Speed Tests', type: 'select', tab: 'data',
    options: [
      { value: 'disabled', label: 'Disabled' },
      { value: '30m',      label: 'Every 30 minutes' },
      { value: '1h',       label: 'Hourly' },
      { value: '6h',       label: 'Every 6 hours' },
      { value: '24h',      label: 'Daily' },
    ],
    description: 'How often to run automatic speed tests in the background.' },

  // Scanner tab — auto-block security responses
  auto_block_new_devices:   { label: 'Auto-Block New Devices', type: 'toggle', tab: 'scanner',
    description: 'Automatically block any newly discovered device until it is manually approved. Uses the active block method below.' },
  auto_block_vuln_severity: { label: 'Auto-Block on Vulnerability', type: 'select', tab: 'scanner',
    options: [
      { value: 'none',     label: 'Disabled' },
      { value: 'medium',   label: 'Medium and above' },
      { value: 'high',     label: 'High and above' },
      { value: 'critical', label: 'Critical only' },
    ],
    description: 'Automatically block a device when a vulnerability scan finds issues at or above the selected severity. Uses the active block method below.' },
  // Blocking method (custom UI renders these)
  block_method:    { tab: 'scanner' },
  block_plugin_id: { tab: 'scanner' },

  // Phase 9 — device grouping
  auto_group_by_hostname: { label: 'Auto-group by Hostname', type: 'toggle', tab: 'scanner',
    description: 'Automatically group devices with the same hostname as the same physical device on a different interface (e.g. laptop on WiFi vs Ethernet). When disabled, a suggestion event is written instead and grouping can be done manually in the device admin panel.' },
  scan_grouped_members: { label: 'Scan All Grouped Interfaces', type: 'toggle', tab: 'scanner',
    description: 'By default only a group\'s primary interface is port-scanned and vulnerability-scanned, since grouped interfaces belong to the same physical host. Enable to scan every grouped interface IP separately.' },

  // Here Be Dragons — advanced probe pipeline controls
  enable_arp_sweep: { label: 'Enable Active ARP Sweep', type: 'toggle', tab: 'scanner',
    description: 'Send active ARP broadcast packets to discover devices on the configured subnet. Disable to rely on the passive sniffer only — note that without the sweep, device online/offline state will no longer be tracked.' },
  enable_passive_sniffer: { label: 'Enable Passive ARP Sniffer', type: 'toggle', tab: 'scanner',
    description: 'Listen passively for ARP traffic on the network interface. Disable to stop all passive packet capture. Takes effect immediately.' },
  sniffer_subnet_filter: { label: 'Filter Sniffer to Configured Subnet', type: 'toggle', tab: 'scanner',
    description: 'Restrict the passive sniffer to the configured IP range only. Disable if you intentionally want to track devices from other subnets on the same interface — but note that the active ARP sweep will still only cover the configured range.' },
  enable_hostname_resolution: { label: 'Enable DNS Hostname Resolution', type: 'toggle', tab: 'scanner',
    description: 'Attempt reverse-DNS lookups to resolve device hostnames. Disable to stop all DNS queries from the probe — useful if hostname lookups are hammering your DNS server.' },
  hostname_cooldown_hours: { label: 'Hostname Resolution Cooldown', unit: 'hours', type: 'number', min: 1, max: 168, tab: 'scanner',
    description: 'Minimum hours between DNS resolution retries for each unresolved device. Lower values mean more frequent DNS queries.' },
  enable_port_scanning: { label: 'Enable Port Scanning', type: 'toggle', tab: 'scanner',
    description: 'Run TCP port scans on discovered devices to identify open services. Disable to stop all port scanning and deep scan activity.' },
  port_scan_method: { label: 'Port Scan Method', type: 'select', tab: 'scanner',
    options: [
      { value: 'tcp_connect', label: 'TCP Connect (default — no special privileges)' },
      { value: 'scapy_syn',   label: 'Scapy SYN Scan (raw packets, faster on LAN)' },
    ],
    description: 'TCP Connect uses standard socket connections and works without root. Scapy SYN sends raw TCP SYN packets — often faster on LAN since closed ports return RST immediately rather than waiting for a timeout. Requires CAP_NET_RAW, already granted in the default Docker configuration.' },
  port_scan_workers: { label: 'Port Scan Worker Threads', unit: 'threads', type: 'number', min: 10, max: 500, tab: 'scanner',
    description: 'Concurrent TCP connect threads per port scan (applies to TCP Connect method only, default 200).' },
  gateway_scan_workers: { label: 'Gateway Scan Worker Threads', unit: 'threads', type: 'number', min: 5, max: 200, tab: 'scanner',
    description: 'Concurrent TCP connect threads when scanning the default gateway (default 50). Kept lower than regular scans to avoid overwhelming the gateway device.' },
  enable_service_fingerprinting: { label: 'Enable Service Fingerprinting', type: 'toggle', tab: 'scanner',
    description: 'Run Nerva service fingerprinting after each port scan to identify the service running on each open port. Disable to skip this stage.' },
  enable_mdns: { label: 'Enable mDNS Discovery', type: 'toggle', tab: 'scanner',
    description: 'Probe the mDNS/Bonjour multicast group to discover device names and advertised services. Runs every 2 hours in the background.' },
  enable_nightly_scan: { label: 'Enable Nightly Rescan Window', type: 'toggle', tab: 'scanner',
    description: 'Re-scan all online devices during the configured nightly scan window. Disable to prevent automatic overnight port scan storms.' },
  enable_unscanned_retry: { label: 'Retry Unscanned Devices Each Cycle', type: 'toggle', tab: 'scanner',
    description: 'On each sweep cycle, trigger a port scan for any device that has never been scanned. Disable if new devices are causing too many simultaneous scans.' },
}

// Docker keys handled as custom cards
const DOCKER_KEYS = new Set(['docker_enabled','docker_host','docker_tls_verify'])

const TABS = [
  { id: 'scanner',       label: 'Scanner',       Icon: ScanLine  },
  { id: 'notifications', label: 'Notifications', Icon: Bell      },
  { id: 'plugins',       label: 'Plugins',       Icon: Package   },
  { id: 'docker',        label: 'Docker',        Icon: Box       },
  { id: 'data',          label: 'Data',          Icon: Database  },
  { id: 'admin',         label: 'Admin',         Icon: Settings2 },
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
  const { skin, setSkin, isDark } = useTheme()
  const [activeTab,     setActiveTab]     = useState('scanner')
  const [settings,      setSettings]      = useState([])
  const [dirty,         setDirty]         = useState({})
  const [saving,        setSaving]        = useState(false)
  const [saved,         setSaved]         = useState(false)
  const [fpStats,       setFpStats]       = useState(null)
  const [exportingDevs, setExportingDevs] = useState(false)
  const [exportingFp,   setExportingFp]   = useState(false)
  const [importStatus,  setImportStatus]  = useState(null)
  const [backingUp,      setBackingUp]      = useState(false)
  const [restoreStatus,  setRestoreStatus]  = useState(null)
  const [backupPassword, setBackupPassword] = useState('')
  const [showBackupPwd,  setShowBackupPwd]  = useState(false)
  const restoreInputRef = useRef(null)
  const [dragonsOpen,   setDragonsOpen]   = useState(false)
  const [restarting,    setRestarting]    = useState({})  // { probe: bool, backend: bool }
  const [recheckNames,  setRecheckNames]  = useState({ running: false, result: null })
  const fileInputRef = useRef(null)
  const [detectedInterface, setDetectedInterface] = useState('')
  const [blockPlugins,      setBlockPlugins]      = useState([])
  const [blockPluginError,  setBlockPluginError]  = useState('')

  const [trivyDbStatus,     setTrivyDbStatus]     = useState(null)
  const [trivyUpdating,     setTrivyUpdating]     = useState(false)
  const [trivyLines,        setTrivyLines]        = useState([])
  const trivyAbortRef = useRef(null)

  const [nucleiStatus,      setNucleiStatus]      = useState(null)
  const [nucleiUpdating,    setNucleiUpdating]    = useState(false)
  const [nucleiLines,       setNucleiLines]       = useState([])
  const nucleiAbortRef = useRef(null)

  // Appliance auto-updates (only available on VM/Pi appliance builds)
  const [systemInfo,        setSystemInfo]        = useState(null)
  const [autoUpdateSaving,  setAutoUpdateSaving]  = useState(false)
  const [autoUpdateError,   setAutoUpdateError]   = useState('')
  const [updateRunning,     setUpdateRunning]     = useState(false)
  const [tzSaving,          setTzSaving]          = useState(false)

  const fetchTrivyStatus = useCallback(() => {
    api.trivyDbStatus().then(setTrivyDbStatus).catch(() => {})
  }, [])

  const fetchNucleiStatus = useCallback(() => {
    api.nucleiTemplateStatus().then(setNucleiStatus).catch(() => {})
  }, [])

  useEffect(() => {
    api.getSettings().then(setSettings).catch(() => {})
    api.getFingerprintStats().then(setFpStats).catch(() => {})
    api.setupNetworkInfo().then(info => {
      if (info?.interface) setDetectedInterface(info.interface)
    }).catch(() => {})
    api.listPlugins().then(plugins => {
      setBlockPlugins(plugins.filter(p => p.capabilities?.includes('blocking')))
    }).catch(() => {})
    fetchTrivyStatus()
    fetchNucleiStatus()
    api.getSystemInfo().then(setSystemInfo).catch(() => {})
  }, [fetchTrivyStatus, fetchNucleiStatus])

  function handleChange(key, value) {
    setDirty(d => ({ ...d, [key]: value }))
    onSettingChange?.(key, value)
  }

  async function handleAutoUpdate(enabled, hour, days) {
    setAutoUpdateSaving(true)
    setAutoUpdateError('')
    try {
      await api.setAutoUpdate(enabled, hour, days)
      const info = await api.getSystemInfo()
      setSystemInfo(info)
    } catch (e) {
      setAutoUpdateError((e?.message || String(e)).replace(/^.*?\d{3}\s*/, ''))
    } finally {
      setAutoUpdateSaving(false)
    }
  }

  // Current auto-update config (with sensible fallbacks) for the admin UI.
  function curAutoUpdate() {
    const au = systemInfo?.auto_update || {}
    return {
      enabled: !!au.enabled,
      hour: Number.isInteger(au.hour) ? au.hour : 4,
      days: Array.isArray(au.days) ? au.days : [],   // [] = every day; else cron dow 0-6
    }
  }

  // Toggle a single weekday (cron dow: 0=Sun … 6=Sat). Selecting from the
  // "every day" state ([]) starts a fresh single-day selection; clearing the
  // last day falls back to "every day".
  function toggleAutoUpdateDay(dow) {
    const { enabled, hour, days } = curAutoUpdate()
    const next = days.includes(dow) ? days.filter(d => d !== dow) : [...days, dow].sort((a, b) => a - b)
    handleAutoUpdate(enabled, hour, next)
  }

  function setAutoUpdateEveryDay() {
    const { enabled, hour } = curAutoUpdate()
    handleAutoUpdate(enabled, hour, [])
  }

  async function handleRunUpdateNow() {
    setUpdateRunning(true)
    setAutoUpdateError('')
    try {
      await api.runAutoUpdate()
      const info = await api.getSystemInfo()
      setSystemInfo(info)
    } catch (e) {
      setAutoUpdateError((e?.message || String(e)).replace(/^.*?\d{3}\s*/, ''))
    } finally {
      setUpdateRunning(false)
    }
  }

  async function handleTimezone(tz) {
    setTzSaving(true)
    try {
      await api.updateSetting('timezone', tz)
      const info = await api.getSystemInfo()
      setSystemInfo(info)
    } catch (_) { /* non-fatal */ } finally {
      setTzSaving(false)
    }
  }

  async function handleSave() {
    setSaving(true)
    setBlockPluginError('')
    try {
      await Promise.all(
        Object.entries(dirty).map(([key, value]) => api.updateSetting(key, value))
      )
    } catch (e) {
      const msg = e?.message || String(e)
      if (msg.includes('block_plugin') || dirty.block_plugin_id !== undefined) {
        setBlockPluginError(msg.replace(/^.*\d+\s*/, ''))
      }
      setSaving(false)
      return
    }
    // Push scanner settings to the probe immediately (no need to wait for next scan cycle)
    if (activeTab === 'scanner') {
      api.applySettings().catch(() => {})
    }
    setSaving(false)
    setDirty({})
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
    api.getSettings().then(setSettings)
  }

  async function handleRestart(target) {
    if (!confirm(`Restart the ${target} container? It will be back online in a few seconds (Docker restart policy).`)) return
    setRestarting(r => ({ ...r, [target]: true }))
    try {
      if (target === 'probe')   await api.restartProbe()
      if (target === 'backend') await api.restartBackend()
    } catch { /* container disappears before it can reply — that's expected */ }
    setTimeout(() => setRestarting(r => ({ ...r, [target]: false })), 5000)
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

  async function handleBackup() {
    setBackingUp(true)
    try {
      const fname = backupPassword ? 'inspectre_backup.ienc' : 'inspectre_backup.json'
      await downloadResponse(await api.exportBackup(backupPassword), fname)
    }
    catch (e) { alert('Backup failed: ' + e.message) }
    finally { setBackingUp(false) }
  }

  async function handleRestoreBackup(e) {
    const file = e.target.files?.[0]
    if (!file) return
    setRestoreStatus('loading')
    try {
      const result = await api.importRestore(file, backupPassword)
      setRestoreStatus(result)
    } catch (err) {
      const msg = err.message || ''
      setRestoreStatus(msg.toLowerCase().includes('encrypt') ? 'needs_password' : 'error')
    }
    finally { if (restoreInputRef.current) restoreInputRef.current.value = '' }
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

  const [cpCurrent,    setCpCurrent]    = useState('')
  const [cpNew,        setCpNew]        = useState('')
  const [cpConfirm,    setCpConfirm]    = useState('')
  const [cpError,      setCpError]      = useState('')
  const [cpSuccess,    setCpSuccess]    = useState(false)
  const [cpLoading,    setCpLoading]    = useState(false)
  const [showCpCurr,   setShowCpCurr]   = useState(false)
  const [showCpNew,    setShowCpNew]    = useState(false)

  async function handleChangePassword(e) {
    e.preventDefault()
    if (!cpCurrent || !cpNew || !cpConfirm) return
    if (cpNew !== cpConfirm) { setCpError('New passwords do not match'); return }
    if (cpNew.length < 8)   { setCpError('Password must be at least 8 characters'); return }
    setCpError('')
    setCpLoading(true)
    try {
      await api.changePassword(cpCurrent, cpNew)
      setCpSuccess(true)
      setCpCurrent('')
      setCpNew('')
      setCpConfirm('')
    } catch {
      setCpError('Current password is incorrect')
    } finally {
      setCpLoading(false)
    }
  }

  const hasDirty   = Object.keys(dirty).length > 0
  const showFooter = activeTab !== 'admin' && activeTab !== 'plugins'

  // Returns current value for a key (dirty-aware)
  function val(key) {
    return dirty[key] ?? settings.find(s => s.key === key)?.value ?? ''
  }

  // ── Scanner tab grouping ────────────────────────────────────────────────────
  const networkScanKeys   = ['scan_interval','offline_miss_threshold']
  const networkConfigKeys = ['ip_range','dns_server','probe_interface']

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

        {/* Nav grid */}
        <div className="px-4 py-3 grid grid-cols-3 gap-1.5"
          style={{ borderBottom: '1px solid var(--color-border)' }}>
          {TABS.map(({ id, label, Icon }) => {
            const isActive = activeTab === id
            return (
              <button key={id} onClick={() => setActiveTab(id)}
                className="flex flex-col items-center gap-1.5 py-2.5 px-1 rounded-xl text-xs font-medium transition-all"
                style={{
                  color: isActive ? 'var(--color-brand)' : 'var(--color-text-muted)',
                  background: isActive
                    ? 'color-mix(in srgb, var(--color-brand) 10%, var(--color-surface-offset))'
                    : 'var(--color-surface-offset)',
                  border: `1px solid ${isActive ? 'color-mix(in srgb, var(--color-brand) 30%, transparent)' : 'var(--color-border)'}`,
                }}>
                <Icon size={15} />
                <span style={{ fontSize: '10px', lineHeight: 1 }}>{label}</span>
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

              {/* Network configuration */}
              <SectionHeader label="Network Configuration" Icon={ScanLine} />
              {settingsByKeys(['ip_range','dns_server']).map(s => (
                <SettingRow key={s.key} s={s} dirty={dirty} onchange={handleChange} />
              ))}
              {settingsByKeys(['probe_interface']).map(s => (
                <SettingRow key={s.key} s={s} dirty={dirty} onchange={handleChange}
                  placeholder={detectedInterface || 'auto-detect'} />
              ))}

              {/* Device Identification */}
              <CollapsibleSection label="Device Identification" Icon={Settings2} defaultOpen={false}>
                {settingsByKeys(['fingerbank_api_key']).map(s => (
                  <SettingRow key={s.key} s={s} dirty={dirty} onchange={handleChange} />
                ))}
              </CollapsibleSection>

              {/* Vulnerability Scanning */}
              <CollapsibleSection label="Vulnerability Scanning" Icon={AlertTriangle} defaultOpen={false}>
                {settingsByKeys(['vuln_scan_schedule','vuln_scan_targets','vuln_scan_templates','vuln_scan_on_new_device','vuln_scan_on_port_change']).map(s => (
                  <SettingRow key={s.key} s={s} dirty={dirty} onchange={handleChange} />
                ))}

                {/* Nuclei templates management card */}
                <div className="card p-4 space-y-3 mt-2">
                  <div className="flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <p className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>
                        Nuclei Community Templates
                      </p>
                      {nucleiStatus == null ? (
                        <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-faint)' }}>Checking…</p>
                      ) : nucleiStatus.exists && nucleiStatus.last_updated ? (
                        <p className="text-xs mt-0.5 font-mono" style={{ color: 'var(--color-text-muted)' }}>
                          Updated: {new Date(nucleiStatus.last_updated).toLocaleString()}
                          {nucleiStatus.version ? ` (v${nucleiStatus.version})` : ''}
                        </p>
                      ) : nucleiStatus.exists ? (
                        <p className="text-xs mt-0.5 font-mono" style={{ color: 'var(--color-text-muted)' }}>
                          Templates present{nucleiStatus.version ? ` (v${nucleiStatus.version})` : ''}
                        </p>
                      ) : nucleiStatus.binary_available === false ? (
                        <p className="text-xs mt-0.5" style={{ color: '#ef4444' }}>Nuclei not available</p>
                      ) : (
                        <p className="text-xs mt-0.5" style={{ color: '#f59e0b' }}>Not downloaded yet</p>
                      )}
                    </div>
                    <button
                      onClick={async () => {
                        if (nucleiUpdating) return
                        setNucleiUpdating(true)
                        setNucleiLines([])
                        const ctrl = new AbortController()
                        nucleiAbortRef.current = ctrl
                        try {
                          await api.nucleiTemplateUpdate(line => {
                            if (line === 'NUCLEI_UPDATE_DONE') {
                              setNucleiUpdating(false)
                              fetchNucleiStatus()
                            } else {
                              setNucleiLines(l => [...l, line])
                            }
                          }, ctrl.signal)
                        } catch {
                          /* aborted or network error */
                        } finally {
                          setNucleiUpdating(false)
                        }
                      }}
                      disabled={nucleiUpdating || nucleiStatus?.binary_available === false}
                      className="btn-ghost flex items-center gap-1.5 text-xs shrink-0"
                    >
                      <RefreshCw size={12} className={nucleiUpdating ? 'animate-spin' : ''} />
                      {nucleiUpdating ? 'Updating…' : 'Update Now'}
                    </button>
                  </div>

                  {(nucleiLines.length > 0 || nucleiUpdating) && (
                    <StreamOutput
                      lines={nucleiLines}
                      running={nucleiUpdating}
                      onStop={() => { nucleiAbortRef.current?.abort(); setNucleiUpdating(false) }}
                      mode="generic"
                    />
                  )}
                </div>

                {settingsByKeys(['nuclei_template_update_interval']).map(s => (
                  <SettingRow key={s.key} s={s} dirty={dirty} onchange={handleChange} />
                ))}
              </CollapsibleSection>

              {/* Scan Scheduling */}
              <CollapsibleSection label="Scan Scheduling" Icon={ScanLine} defaultOpen={false}>
                {settingsByKeys(['nightly_scan_start','nightly_scan_end','offline_rescan_hours','baseline_scan_count_threshold']).map(s => (
                  <SettingRow key={s.key} s={s} dirty={dirty} onchange={handleChange} />
                ))}
              </CollapsibleSection>

              {/* Security Responses */}
              <CollapsibleSection label="Security Responses" Icon={AlertTriangle} defaultOpen={false}>
                {settingsByKeys(['auto_block_new_devices','auto_block_vuln_severity']).map(s => (
                  <SettingRow key={s.key} s={s} dirty={dirty} onchange={handleChange} />
                ))}

                {/* Blocking Method — custom UI */}
                {(() => {
                  const currentMethod   = val('block_method') || 'arp'
                  const currentPluginId = val('block_plugin_id') || ''

                  // Derive which methods have a qualifying plugin
                  const dnsPlugins   = blockPlugins.filter(p => p.capabilities?.includes('dns'))
                  const fwPlugins    = blockPlugins.filter(p => p.capabilities?.includes('firewall'))
                  const infraPlugins = blockPlugins.filter(p =>
                    !p.capabilities?.includes('dns') && !p.capabilities?.includes('firewall')
                  )

                  const methodOptions = [
                    { value: 'arp',            label: 'ARP Poisoning (probe-native)',           always: true  },
                    { value: 'dns',            label: 'DNS Block (AdGuard Home / Pi-hole)',      always: false, plugins: dnsPlugins   },
                    { value: 'firewall',       label: 'Firewall Rule (OPNsense / pfSense)',      always: false, plugins: fwPlugins    },
                    { value: 'infrastructure', label: 'Infrastructure (TP-Link Omada / UniFi)', always: false, plugins: infraPlugins },
                  ].filter(o => o.always || o.plugins.length > 0)

                  const pluginsForMethod = currentMethod === 'arp' ? [] :
                    methodOptions.find(o => o.value === currentMethod)?.plugins ?? []

                  const selectedPlugin = blockPlugins.find(p => p.id === currentPluginId)
                  const pluginUnhealthy = selectedPlugin && selectedPlugin.status === 'error'

                  return (
                    <div className="space-y-2 pt-1">
                      <p className="text-xs font-semibold pt-1" style={{ color: 'var(--color-text-muted)' }}>Blocking Method</p>

                      {/* Method selector */}
                      <div className="space-y-1">
                        <label className="text-xs" style={{ color: 'var(--color-text-muted)' }}>Method</label>
                        <select
                          className="w-full rounded-lg px-3 py-2 text-sm"
                          style={{ background: 'var(--color-surface-offset)', border: '1px solid var(--color-border)', color: 'var(--color-text)' }}
                          value={currentMethod}
                          onChange={e => {
                            handleChange('block_method', e.target.value)
                            handleChange('block_plugin_id', '')
                            setBlockPluginError('')
                          }}
                        >
                          {methodOptions.map(o => (
                            <option key={o.value} value={o.value}>{o.label}</option>
                          ))}
                        </select>
                        <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                          {currentMethod === 'arp'
                            ? 'The probe uses ARP poisoning to redirect traffic. No plugin required.'
                            : 'Only methods with an enabled, configured blocking plugin are shown.'}
                        </p>
                      </div>

                      {/* Plugin selector (hidden for ARP) */}
                      {currentMethod !== 'arp' && (
                        <div className="space-y-1">
                          <label className="text-xs" style={{ color: 'var(--color-text-muted)' }}>Blocking Plugin</label>
                          {pluginsForMethod.length === 0 ? (
                            <p className="text-xs rounded-lg px-3 py-2"
                              style={{ background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.3)', color: '#d97706' }}>
                              No enabled plugin found for the selected method. Enable and configure a qualifying plugin in the Plugins tab first.
                            </p>
                          ) : (
                            <select
                              className="w-full rounded-lg px-3 py-2 text-sm"
                              style={{ background: 'var(--color-surface-offset)', border: '1px solid var(--color-border)', color: 'var(--color-text)' }}
                              value={currentPluginId}
                              onChange={e => { handleChange('block_plugin_id', e.target.value); setBlockPluginError('') }}
                            >
                              <option value="">— select plugin —</option>
                              {pluginsForMethod.map(p => (
                                <option key={p.id} value={p.id}>{p.name} ({p.status})</option>
                              ))}
                            </select>
                          )}
                          {blockPluginError && (
                            <p className="text-xs rounded-lg px-3 py-2"
                              style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)', color: '#ef4444' }}>
                              {blockPluginError}
                            </p>
                          )}
                          {pluginUnhealthy && (
                            <p className="text-xs rounded-lg px-3 py-2"
                              style={{ background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.3)', color: '#d97706' }}>
                              Warning: {selectedPlugin.name} last poll failed — blocks may not execute until the plugin recovers.
                              {selectedPlugin.last_error && <span> Error: {selectedPlugin.last_error}</span>}
                            </p>
                          )}
                        </div>
                      )}
                    </div>
                  )
                })()}
              </CollapsibleSection>

              {/* ── Here Be Dragons ─────────────────────────────────────── */}
              <button
                type="button"
                onClick={() => setDragonsOpen(o => !o)}
                className="w-full flex items-center gap-2 pt-3 pb-1 text-left"
                style={{ color: 'var(--color-text-muted)' }}
              >
                {dragonsOpen ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                <AlertTriangle size={13} style={{ color: '#f59e0b' }} />
                <span className="text-sm font-semibold" style={{ color: '#f59e0b' }}>Here Be Dragons</span>
                <span className="text-xs ml-1" style={{ color: 'var(--color-text-faint)' }}>— advanced probe pipeline controls</span>
              </button>

              {dragonsOpen && (
                <div className="space-y-3">
                  <div className="rounded-lg p-3 text-xs space-y-1"
                    style={{ background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.3)', color: '#d97706' }}>
                    <p className="font-semibold">Warning — these settings affect probe behaviour directly.</p>
                    <p style={{ color: 'var(--color-text-muted)' }}>
                      Changing them can stop device discovery, halt DNS lookups, or reduce network load depending on what you disable.
                      If unexpected devices are appearing or DNS queries are high, check that <strong>Filter Sniffer to Configured Subnet</strong> is on
                      — if disabled, the sniffer will process ARP traffic from every subnet visible on the interface.
                    </p>
                  </div>

                  <p className="text-xs font-semibold" style={{ color: 'var(--color-text-muted)', paddingTop: '4px' }}>Advanced Scanning</p>
                  {settingsByKeys(['sniffer_workers','arp_scan_retry','primary_ip_mode']).map(s => (
                    <SettingRow key={s.key} s={s} dirty={dirty} onchange={handleChange} />
                  ))}

                  <p className="text-xs font-semibold" style={{ color: 'var(--color-text-muted)', paddingTop: '4px' }}>Active ARP Sweep</p>
                  {settingsByKeys(['enable_arp_sweep']).map(s => (
                    <SettingRow key={s.key} s={s} dirty={dirty} onchange={handleChange} />
                  ))}

                  <p className="text-xs font-semibold" style={{ color: 'var(--color-text-muted)', paddingTop: '4px' }}>Passive Sniffer</p>
                  {settingsByKeys(['enable_passive_sniffer','sniffer_subnet_filter']).map(s => (
                    <SettingRow key={s.key} s={s} dirty={dirty} onchange={handleChange} />
                  ))}

                  <p className="text-xs font-semibold" style={{ color: 'var(--color-text-muted)', paddingTop: '4px' }}>Hostname / DNS Resolution</p>
                  {settingsByKeys(['enable_hostname_resolution','hostname_cooldown_hours']).map(s => (
                    <SettingRow key={s.key} s={s} dirty={dirty} onchange={handleChange} />
                  ))}
                  <div className="card p-4 space-y-3">
                    <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                      Re-run the full 6-step hostname resolution chain (dig → gethostbyaddr → host → nslookup → avahi → nmblookup)
                      for every device. Names set manually (custom name) are never overwritten.
                      Plugin-provided names are used only as a last resort by the probe during normal discovery — this button will
                      overwrite any plugin name with a properly resolved hostname if one is found.
                    </p>
                    <div className="flex items-center gap-3 flex-wrap">
                      <button
                        onClick={async () => {
                          setRecheckNames({ running: true, result: null })
                          try {
                            const r = await api.resolveAllNames()
                            setRecheckNames({ running: false, result: r })
                          } catch {
                            setRecheckNames({ running: false, result: { error: true } })
                          }
                        }}
                        disabled={recheckNames.running}
                        className="btn-secondary flex items-center gap-2 text-sm"
                        style={{ opacity: recheckNames.running ? 0.5 : 1 }}>
                        <RotateCcw size={12} />
                        {recheckNames.running ? 'Re-checking…' : 'Re-check all device names'}
                      </button>
                      {recheckNames.result && !recheckNames.result.error && (
                        <span className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
                          Updated {recheckNames.result.updated} of {recheckNames.result.total} devices
                          {recheckNames.result.failed > 0 && ` (${recheckNames.result.failed} probe errors)`}
                        </span>
                      )}
                      {recheckNames.result?.error && (
                        <span className="text-xs" style={{ color: '#ef4444' }}>Failed — check backend logs</span>
                      )}
                    </div>
                  </div>

                  <p className="text-xs font-semibold" style={{ color: 'var(--color-text-muted)', paddingTop: '4px' }}>Port Scanning</p>
                  {settingsByKeys(['enable_port_scanning','port_scan_method','port_scan_workers','gateway_scan_workers','enable_service_fingerprinting']).map(s => (
                    <SettingRow key={s.key} s={s} dirty={dirty} onchange={handleChange} />
                  ))}

                  <p className="text-xs font-semibold" style={{ color: 'var(--color-text-muted)', paddingTop: '4px' }}>Periodic Activity</p>
                  {settingsByKeys(['enable_mdns','enable_nightly_scan','enable_unscanned_retry']).map(s => (
                    <SettingRow key={s.key} s={s} dirty={dirty} onchange={handleChange} />
                  ))}

                  <p className="text-xs font-semibold" style={{ color: 'var(--color-text-muted)', paddingTop: '4px' }}>Device Grouping</p>
                  {settingsByKeys(['auto_group_by_hostname','scan_grouped_members']).map(s => (
                    <SettingRow key={s.key} s={s} dirty={dirty} onchange={handleChange} />
                  ))}

                  <p className="text-xs font-semibold" style={{ color: 'var(--color-text-muted)', paddingTop: '4px' }}>Container Restart</p>
                  <div className="card p-4 space-y-3">
                    <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                      Force-restart individual containers. Docker brings them back immediately.
                      Required after changing Probe Interface or Sniffer Workers.
                    </p>
                    <div className="flex gap-2 flex-wrap">
                      <button onClick={() => handleRestart('probe')} disabled={restarting.probe}
                        className="btn-secondary flex items-center gap-2 text-sm"
                        style={{ opacity: restarting.probe ? 0.5 : 1 }}>
                        <AlertTriangle size={12} style={{ color: '#f59e0b' }} />
                        {restarting.probe ? 'Restarting…' : 'Restart Probe'}
                      </button>
                      <button onClick={() => handleRestart('backend')} disabled={restarting.backend}
                        className="btn-secondary flex items-center gap-2 text-sm"
                        style={{ opacity: restarting.backend ? 0.5 : 1 }}>
                        <AlertTriangle size={12} style={{ color: '#f59e0b' }} />
                        {restarting.backend ? 'Restarting…' : 'Restart Backend'}
                      </button>
                    </div>
                  </div>
                </div>
              )}

            </>
          )}

          {/* ── Notifications tab ───────────────────────────────────────────── */}
          {activeTab === 'notifications' && (
            <NotificationsTab settings={settings} dirty={dirty} onchange={handleChange} />
          )}

          {/* ── Plugins tab ─────────────────────────────────────────────────── */}
          {activeTab === 'plugins' && <PluginsTab />}

          {/* ── Docker tab ──────────────────────────────────────────────────── */}
          {activeTab === 'docker' && (
            <>
              <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                Connect to Docker hosts and Proxmox VE servers to monitor and manage containers.
                Enable individual hosts with their toggle — at least one must be active for the Containers page to work.
              </p>

              <SectionHeader label="Container Hosts" Icon={Box} />
              <HostsManager />

              <CollapsibleSection label="Vulnerability Scanning" Icon={AlertTriangle} defaultOpen={false}>
                {/* Trivy DB management card */}
                <div className="card p-4 space-y-3 mb-2">
                  <div className="flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <p className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>
                        Trivy Vulnerability DB
                      </p>
                      {trivyDbStatus == null ? (
                        <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-faint)' }}>Checking…</p>
                      ) : trivyDbStatus.exists && trivyDbStatus.downloaded_at ? (
                        <p className="text-xs mt-0.5 font-mono" style={{ color: 'var(--color-text-muted)' }}>
                          Downloaded: {new Date(trivyDbStatus.downloaded_at).toLocaleString()}
                        </p>
                      ) : (
                        <p className="text-xs mt-0.5" style={{ color: '#f59e0b' }}>Not downloaded yet</p>
                      )}
                    </div>
                    <button
                      onClick={async () => {
                        if (trivyUpdating) return
                        setTrivyUpdating(true)
                        setTrivyLines([])
                        const ctrl = new AbortController()
                        trivyAbortRef.current = ctrl
                        try {
                          await api.trivyDbUpdate(line => {
                            if (line === 'TRIVY_DB_DONE') {
                              setTrivyUpdating(false)
                              fetchTrivyStatus()
                            } else {
                              setTrivyLines(l => [...l, line])
                            }
                          }, ctrl.signal)
                        } catch {
                          /* aborted or network error */
                        } finally {
                          setTrivyUpdating(false)
                        }
                      }}
                      disabled={trivyUpdating}
                      className="btn-ghost flex items-center gap-1.5 text-xs shrink-0"
                    >
                      <RefreshCw size={12} className={trivyUpdating ? 'animate-spin' : ''} />
                      {trivyUpdating ? 'Updating…' : 'Update Now'}
                    </button>
                  </div>

                  {(trivyLines.length > 0 || trivyUpdating) && (
                    <StreamOutput
                      lines={trivyLines}
                      running={trivyUpdating}
                      onStop={() => { trivyAbortRef.current?.abort(); setTrivyUpdating(false) }}
                      mode="generic"
                    />
                  )}
                </div>

                {settingsByKeys(['trivy_db_update_frequency','docker_scan_on_new','docker_scan_on_update']).map(s => (
                  <SettingRow key={s.key} s={s} dirty={dirty} onchange={handleChange} />
                ))}
              </CollapsibleSection>

              <CollapsibleSection label="Container Updates" Icon={RefreshCw} defaultOpen={false}>
                <p className="text-xs mb-3" style={{ color: 'var(--color-text-faint)' }}>
                  Automatically check registries for newer image versions and optionally update containers.
                  All updates use a blue/green strategy with automatic rollback — the original container
                  is preserved until the new one passes a health check.
                </p>
                <p className="text-xs mb-3 px-3 py-2 rounded" style={{ color: 'var(--color-text-muted)', background: 'var(--color-surface-raised)' }}>
                  Update schedule and auto-update mode are configured in the <strong>Containers</strong> page.
                </p>
                {settingsByKeys([
                  'container_update_block_critical',
                  'container_backup_enabled',
                  'container_update_health_timeout',
                  'container_update_stagger_seconds',
                  'container_update_pin_labels',
                ]).map(s => (
                  <SettingRow key={s.key} s={s} dirty={dirty} onchange={handleChange} />
                ))}
                <div className="mt-3">
                  <button
                    onClick={async () => {
                      try {
                        await api.dockerCheckAllUpdates()
                      } catch (_) {}
                    }}
                    className="btn-ghost flex items-center gap-1.5 text-xs">
                    <RefreshCw size={12} />
                    Check All Containers Now
                  </button>
                </div>
              </CollapsibleSection>
            </>
          )}

          {/* ── Data tab ────────────────────────────────────────────────────── */}
          {activeTab === 'data' && (
            <>
              <CollapsibleSection label="Traffic Monitoring" Icon={Eye} defaultOpen={false}>
                {settingsByKeys(['traffic_enabled','traffic_max_sessions','traffic_retention_days']).map(s => (
                  <SettingRow key={s.key} s={s} dirty={dirty} onchange={handleChange} />
                ))}
              </CollapsibleSection>

              <CollapsibleSection label="Speed Tests" Icon={Globe} defaultOpen={false}>
                {settingsByKeys(['speedtest_schedule']).map(s => (
                  <SettingRow key={s.key} s={s} dirty={dirty} onchange={handleChange} />
                ))}
              </CollapsibleSection>

              <SectionHeader label="Database Backup & Restore" Icon={Database} />
              <div className="card p-4 space-y-3">
                <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                  Full backup of all devices, events, vuln reports, speed test history, settings, users, and fingerprints. Restoring on a fresh install brings everything back exactly as it was.
                </p>

                {/* Optional encryption password */}
                <div>
                  <label className="text-xs block mb-1.5" style={{ color: 'var(--color-text-muted)' }}>
                    Backup password
                    <span className="ml-1" style={{ color: 'var(--color-text-faint)' }}>(optional — leave blank for unencrypted)</span>
                  </label>
                  <div className="flex gap-2 items-center">
                    <input
                      type={showBackupPwd ? 'text' : 'password'}
                      className="input text-sm"
                      style={{ maxWidth: '260px' }}
                      placeholder="Leave blank for no encryption"
                      value={backupPassword}
                      onChange={e => setBackupPassword(e.target.value)}
                    />
                    <button
                      onClick={() => setShowBackupPwd(v => !v)}
                      className="p-1.5 rounded transition-colors"
                      style={{ color: 'var(--color-text-faint)' }}
                      title={showBackupPwd ? 'Hide password' : 'Show password'}
                    >
                      {showBackupPwd ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  </div>
                </div>

                <div className="flex gap-2 flex-wrap">
                  <button onClick={handleBackup} disabled={backingUp}
                    className="btn-secondary flex items-center gap-2 text-sm">
                    <Download size={13} />
                    {backingUp ? 'Exporting…' : backupPassword ? 'Download encrypted backup' : 'Download backup.json'}
                  </button>
                  <button onClick={() => restoreInputRef.current?.click()}
                    className="btn-secondary flex items-center gap-2 text-sm">
                    <Upload size={13} /> Restore from backup
                  </button>
                  <input ref={restoreInputRef} type="file" accept=".json,.ienc,application/json,application/octet-stream"
                    className="sr-only" onChange={handleRestoreBackup} />
                </div>

                {restoreStatus === 'loading' && (
                  <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>Restoring…</p>
                )}
                {restoreStatus === 'needs_password' && (
                  <p className="text-xs" style={{ color: '#f59e0b' }}>
                    This backup is encrypted — enter the password above, then try restoring again.
                  </p>
                )}
                {restoreStatus === 'error' && (
                  <p className="text-xs" style={{ color: '#ef4444' }}>
                    Restore failed — check the file is a valid InSpectre backup, or the password is wrong.
                  </p>
                )}
                {restoreStatus && !['loading', 'error', 'needs_password'].includes(restoreStatus) && (
                  <div className="rounded-lg p-3 text-xs space-y-1"
                    style={{
                      background: 'color-mix(in srgb, var(--color-success) 10%, var(--color-surface-offset))',
                      color: 'var(--color-success)',
                    }}>
                    <p className="font-medium">Restore complete ✓</p>
                    <p>
                      {restoreStatus.devices != null
                        ? `${restoreStatus.devices} devices · ${restoreStatus.settings} settings · ${restoreStatus.device_events} events · ${restoreStatus.speedtest_results ?? 0} speed tests`
                        : JSON.stringify(restoreStatus)}
                    </p>
                  </div>
                )}
              </div>

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

          {/* ── Admin tab (Appearance + Account) ────────────────────────────── */}
          {activeTab === 'admin' && (
            <>
              {systemInfo?.is_appliance && (
                <div className="space-y-3 pb-2">
                  <SectionHeader label="Automatic Updates" Icon={RefreshCw} />
                  <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                    This appliance build can pull the latest InSpectre images and
                    recreate any changed containers on a schedule. Updates are disabled by default.
                  </p>

                  {/* Timezone (also drives log timestamps + the update schedule) */}
                  <div className="space-y-1">
                    <label className="text-xs" style={{ color: 'var(--color-text-muted)' }}>Timezone</label>
                    <select
                      className="w-full rounded-lg px-3 py-2 text-sm"
                      style={{ background: 'var(--color-surface-offset)', border: '1px solid var(--color-border)', color: 'var(--color-text)' }}
                      value={systemInfo?.timezone || 'UTC'}
                      disabled={tzSaving}
                      onChange={e => handleTimezone(e.target.value)}
                    >
                      {(COMMON_TIMEZONES.includes(systemInfo?.timezone) ? COMMON_TIMEZONES : [systemInfo?.timezone, ...COMMON_TIMEZONES].filter(Boolean))
                        .map(tz => <option key={tz} value={tz}>{tz}</option>)}
                    </select>
                    <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                      Used for log timestamps and the update schedule below.
                    </p>
                  </div>

                  {/* Enable toggle */}
                  <label className="flex items-center justify-between gap-3 rounded-lg px-3 py-2"
                    style={{ background: 'var(--color-surface-offset)', border: '1px solid var(--color-border)' }}>
                    <span className="text-sm" style={{ color: 'var(--color-text)' }}>
                      Enable automatic updates
                    </span>
                    <input
                      type="checkbox"
                      checked={!!systemInfo?.auto_update?.enabled}
                      disabled={autoUpdateSaving}
                      onChange={e => {
                        const { hour, days } = curAutoUpdate()
                        handleAutoUpdate(e.target.checked, hour, days)
                      }}
                    />
                  </label>

                  {/* Time of day + days of week */}
                  <div className="space-y-3" style={{ opacity: systemInfo?.auto_update?.enabled ? 1 : 0.5 }}>
                    <div className="space-y-1">
                      <label className="text-xs" style={{ color: 'var(--color-text-muted)' }}>Check for updates at</label>
                      <select
                        className="w-full rounded-lg px-3 py-2 text-sm"
                        style={{ background: 'var(--color-surface-offset)', border: '1px solid var(--color-border)', color: 'var(--color-text)' }}
                        value={curAutoUpdate().hour}
                        disabled={autoUpdateSaving || !systemInfo?.auto_update?.enabled}
                        onChange={e => {
                          const { enabled, days } = curAutoUpdate()
                          handleAutoUpdate(enabled, parseInt(e.target.value, 10), days)
                        }}
                      >
                        {Array.from({ length: 24 }, (_, h) => (
                          <option key={h} value={h}>{String(h).padStart(2, '0')}:00</option>
                        ))}
                      </select>
                      <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                        Appliance local time (24-hour).
                      </p>
                    </div>

                    <div className="space-y-1">
                      <label className="text-xs" style={{ color: 'var(--color-text-muted)' }}>On these days</label>
                      <div className="flex flex-wrap gap-1.5">
                        <button
                          type="button"
                          disabled={autoUpdateSaving || !systemInfo?.auto_update?.enabled}
                          onClick={setAutoUpdateEveryDay}
                          className="px-2.5 py-1 rounded-md text-xs font-medium transition-colors"
                          style={{
                            background: curAutoUpdate().days.length === 0 ? 'var(--color-brand)' : 'var(--color-surface-offset)',
                            color: curAutoUpdate().days.length === 0 ? 'white' : 'var(--color-text-muted)',
                            border: '1px solid var(--color-border)',
                          }}
                        >
                          Every day
                        </button>
                        {[[1,'Mon'],[2,'Tue'],[3,'Wed'],[4,'Thu'],[5,'Fri'],[6,'Sat'],[0,'Sun']].map(([dow, lbl]) => {
                          const active = curAutoUpdate().days.includes(dow)
                          return (
                            <button
                              key={dow}
                              type="button"
                              disabled={autoUpdateSaving || !systemInfo?.auto_update?.enabled}
                              onClick={() => toggleAutoUpdateDay(dow)}
                              className="px-2.5 py-1 rounded-md text-xs font-medium transition-colors"
                              style={{
                                background: active ? 'var(--color-brand)' : 'var(--color-surface-offset)',
                                color: active ? 'white' : 'var(--color-text-muted)',
                                border: '1px solid var(--color-border)',
                              }}
                            >
                              {lbl}
                            </button>
                          )
                        })}
                      </div>
                      <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                        {curAutoUpdate().days.length === 0
                          ? 'Every day. Tap days to limit which days it checks.'
                          : `Selected: ${curAutoUpdate().days.slice().sort((a,b)=>a-b).map(d => ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][d]).join(', ')}.`}
                      </p>
                    </div>

                    <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                      {systemInfo?.auto_update?.enabled
                        ? 'Enabled. The updater checks at the time and on the days selected above.'
                        : 'Turn on automatic updates to choose when to check.'}
                    </p>
                  </div>

                  {/* Manual trigger + last result */}
                  <div className="space-y-2">
                    <button
                      type="button"
                      onClick={handleRunUpdateNow}
                      disabled={updateRunning}
                      className="w-full py-2 rounded-lg text-sm font-medium flex items-center justify-center gap-2"
                      style={{ background: 'var(--color-surface-offset)', border: '1px solid var(--color-border)', color: 'var(--color-text)' }}
                    >
                      <RefreshCw size={14} className={updateRunning ? 'animate-spin' : ''} />
                      {updateRunning ? 'Checking for updates…' : 'Check for updates now'}
                    </button>

                    {systemInfo?.auto_update?.updater?.last_run && (
                      <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                        Last run: {new Date(systemInfo.auto_update.updater.last_run).toLocaleString()}
                        {systemInfo.auto_update.updater.last_status
                          ? ` — ${systemInfo.auto_update.updater.last_status === 'no-change'
                              ? 'already up to date'
                              : systemInfo.auto_update.updater.last_status}`
                          : ''}
                      </p>
                    )}
                    {systemInfo?.auto_update?.updater?.running && (
                      <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                        An update is currently in progress (the app may briefly restart).
                      </p>
                    )}

                    {/* Updater diagnostics — logs from the last helper run */}
                    {systemInfo?.auto_update?.updater?.last_logs && (
                      <details className="rounded-lg" style={{ border: '1px solid var(--color-border)' }}>
                        <summary className="text-xs cursor-pointer px-3 py-2" style={{ color: 'var(--color-text-muted)' }}>
                          Updater logs
                        </summary>
                        <pre className="text-xs overflow-auto px-3 py-2 m-0"
                          style={{ maxHeight: 200, color: 'var(--color-text-faint)', whiteSpace: 'pre-wrap' }}>
                          {systemInfo.auto_update.updater.last_logs}
                        </pre>
                      </details>
                    )}
                  </div>

                  {autoUpdateError && (
                    <p className="text-xs rounded-lg px-3 py-2"
                      style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)', color: '#ef4444' }}>
                      {autoUpdateError}
                    </p>
                  )}
                </div>
              )}

              <SectionHeader label="UI Style" Icon={Paintbrush} />
              <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>
                Choose a UI style. Changes take effect immediately — no reload required.
              </p>

              <div className="grid grid-cols-2 gap-3">
                {/* Spectre card */}
                <button
                  onClick={() => setSkin('spectre')}
                  style={{
                    position: 'relative', padding: '14px', textAlign: 'left', cursor: 'pointer',
                    background: skin === 'spectre'
                      ? 'color-mix(in srgb, var(--color-brand) 8%, var(--color-surface))'
                      : 'var(--color-surface-offset)',
                    border: `2px solid ${skin === 'spectre' ? 'var(--color-brand)' : 'var(--color-border)'}`,
                    borderRadius: '0.75rem', transition: 'border-color 0.15s',
                  }}
                >
                  <div style={{
                    width: '100%', height: '52px', marginBottom: '10px', overflow: 'hidden',
                    background: '#0d0d0f', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '6px',
                    padding: '8px', display: 'flex', flexDirection: 'column', gap: '4px',
                  }}>
                    <div style={{ height: '6px', borderRadius: '9999px', width: '55%', background: '#4fa8b0' }} />
                    <div style={{ height: '4px', borderRadius: '9999px', width: '75%', background: 'rgba(255,255,255,0.12)' }} />
                    <div style={{ height: '4px', borderRadius: '9999px', width: '60%', background: 'rgba(255,255,255,0.08)' }} />
                    <div style={{ height: '4px', borderRadius: '9999px', width: '45%', background: 'rgba(255,255,255,0.06)' }} />
                  </div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-text)', marginBottom: '2px' }}>Spectre</div>
                  <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>Clean · Modern · Rounded</div>
                  {skin === 'spectre' && (
                    <div style={{
                      position: 'absolute', top: '8px', right: '8px',
                      width: '16px', height: '16px', borderRadius: '50%',
                      background: 'var(--color-brand)', display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: '10px', color: 'white', fontWeight: 700,
                    }}>✓</div>
                  )}
                </button>

                {/* Phantom card */}
                <button
                  onClick={() => setSkin('phantom')}
                  style={{
                    position: 'relative', padding: '14px', textAlign: 'left', cursor: 'pointer',
                    background: skin === 'phantom'
                      ? 'color-mix(in srgb, var(--color-brand) 8%, var(--color-surface))'
                      : 'var(--color-surface-offset)',
                    border: `2px solid ${skin === 'phantom' ? 'var(--color-brand)' : 'var(--color-border)'}`,
                    borderRadius: '0.75rem', transition: 'border-color 0.15s',
                  }}
                >
                  <div style={{
                    width: '100%', height: '52px', marginBottom: '10px', overflow: 'hidden',
                    background: isDark ? '#000' : '#f0f7f1',
                    border: `1px solid ${isDark ? 'rgba(0,255,65,0.2)' : 'rgba(0,110,35,0.2)'}`,
                    padding: '8px', display: 'flex', flexDirection: 'column', gap: '4px',
                  }}>
                    <div style={{ height: '6px', width: '55%', background: isDark ? '#00ff41' : '#007a20' }} />
                    <div style={{ height: '4px', width: '75%', background: isDark ? 'rgba(0,255,65,0.25)' : 'rgba(0,110,35,0.2)' }} />
                    <div style={{ height: '4px', width: '60%', background: isDark ? 'rgba(0,255,65,0.15)' : 'rgba(0,110,35,0.12)' }} />
                    <div style={{ height: '4px', width: '45%', background: isDark ? 'rgba(0,255,65,0.1)' : 'rgba(0,110,35,0.08)' }} />
                  </div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-text)', marginBottom: '2px' }}>Phantom</div>
                  <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>Terminal · SOC · Sidebar</div>
                  {skin === 'phantom' && (
                    <div style={{
                      position: 'absolute', top: '8px', right: '8px',
                      width: '16px', height: '16px', borderRadius: '50%',
                      background: 'var(--color-brand)', display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: '10px', color: 'white', fontWeight: 700,
                    }}>✓</div>
                  )}
                </button>
              </div>

              <p className="text-xs mt-2" style={{ color: 'var(--color-text-faint)' }}>
                <strong style={{ color: 'var(--color-text-muted)' }}>Spectre</strong> — top nav bar, rounded cards, teal accent. Follows dark/light mode.<br />
                <strong style={{ color: 'var(--color-text-muted)' }}>Phantom</strong> — fixed left sidebar, JetBrains Mono, sharp corners. Green on black (dark) or green on white (light).
              </p>

              <SectionHeader label="Change Password" Icon={Key} />
              <div className="card p-4">
                <form onSubmit={handleChangePassword} className="space-y-3">
                  <div className="space-y-1">
                    <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Current password</label>
                    <div className="relative">
                      <input
                        type={showCpCurr ? 'text' : 'password'}
                        className="input pr-10 w-full"
                        value={cpCurrent}
                        onChange={e => { setCpCurrent(e.target.value); setCpSuccess(false) }}
                        disabled={cpLoading}
                        autoComplete="current-password"
                      />
                      <button type="button" onClick={() => setShowCpCurr(v => !v)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 opacity-50 hover:opacity-100 transition-opacity"
                        tabIndex={-1}>
                        {showCpCurr ? <EyeOff size={14} /> : <Eye size={14} />}
                      </button>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>New password</label>
                    <div className="relative">
                      <input
                        type={showCpNew ? 'text' : 'password'}
                        className="input pr-10 w-full"
                        value={cpNew}
                        onChange={e => { setCpNew(e.target.value); setCpSuccess(false); setCpError('') }}
                        disabled={cpLoading}
                        autoComplete="new-password"
                      />
                      <button type="button" onClick={() => setShowCpNew(v => !v)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 opacity-50 hover:opacity-100 transition-opacity"
                        tabIndex={-1}>
                        {showCpNew ? <EyeOff size={14} /> : <Eye size={14} />}
                      </button>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Confirm new password</label>
                    <input
                      type="password"
                      className="input w-full"
                      value={cpConfirm}
                      onChange={e => { setCpConfirm(e.target.value); setCpSuccess(false); setCpError('') }}
                      disabled={cpLoading}
                      autoComplete="new-password"
                    />
                  </div>

                  {cpError && (
                    <p className="text-xs" style={{ color: '#ef4444' }}>{cpError}</p>
                  )}
                  {cpSuccess && (
                    <p className="text-xs" style={{ color: '#10b981' }}>Password changed successfully.</p>
                  )}

                  <button
                    type="submit"
                    disabled={cpLoading || !cpCurrent || !cpNew || !cpConfirm}
                    className="btn-primary w-full flex items-center justify-center gap-2"
                    style={{ opacity: cpLoading || !cpCurrent || !cpNew || !cpConfirm ? 0.5 : 1 }}
                  >
                    {cpLoading ? 'Changing…' : 'Change Password'}
                  </button>
                </form>
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

// ---------------------------------------------------------------------------
function SectionHeader({ label, Icon }) {
  return (
    <div className="flex items-center gap-2 pt-1">
      {Icon && <Icon size={13} style={{ color: 'var(--color-text-muted)' }} />}
      <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>{label}</h3>
    </div>
  )
}

function CollapsibleSection({ label, Icon, defaultOpen = true, children }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div>
      <button type="button" onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 pt-1 pb-0.5 text-left group">
        {open ? <ChevronDown size={12} style={{ color: 'var(--color-text-muted)' }} />
               : <ChevronRight size={12} style={{ color: 'var(--color-text-muted)' }} />}
        {Icon && <Icon size={13} style={{ color: 'var(--color-text-muted)' }} />}
        <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>{label}</h3>
      </button>
      {open && <div className="space-y-2 pt-1">{children}</div>}
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

function SettingRow({ s, dirty, onchange, placeholder }) {
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
        placeholder={placeholder || ''}
        onChange={e => onchange(s.key, e.target.value)} />
      {(meta.description || s.description) && (
        <p className="text-xs" style={{ color: 'var(--color-text-faint)' }}>{meta.description || s.description}</p>
      )}
    </div>
  )
}
