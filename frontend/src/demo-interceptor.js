/**
 * Demo mode fetch interceptor.
 * Must be imported BEFORE anything that calls fetch.
 * Intercepts all /api/* calls and returns static demo data.
 */

// ── Demo data ─────────────────────────────────────────────────────────────────
const NOW = new Date()
const ago = (minutes) => new Date(NOW - minutes * 60000).toISOString()

const DEMO_DEVICES = [
  { mac_address:'a4:91:b1:12:34:56', ip_address:'192.168.0.1', hostname:'router', custom_name:'TP-Link Router', display_name:'TP-Link Router', vendor:'TP-Link Technologies', device_type:'router', device_type_override:null, vendor_override:null, vendor_inferred:null, is_online:true, is_important:false, deep_scanned:true, is_ignored:false, is_virtual_interface:false, is_acknowledged:true, location:'Hallway', tags:'network,infrastructure', tags_array:['network','infrastructure'], first_seen:ago(90*24*60), last_seen:ago(2), status_changed_at:ago(5*24*60), scan_results:{open_ports:[{port:22,service:'ssh'},{port:80,service:'http'},{port:443,service:'https'},{port:8080,service:'http-alt'},{port:1900,service:'upnp'}]}, baseline_ports:[22,80,443,8080,1900], vuln_severity:null, zone:null, notes:null, group_members:null },
  { mac_address:'02:c1:11:3e:97:03', ip_address:'192.168.0.2', hostname:'homeserver', custom_name:'Home Server', display_name:'Home Server', vendor:'Dell Technologies', device_type:'server', device_type_override:'server', vendor_override:null, vendor_inferred:null, is_online:true, is_important:true, deep_scanned:true, is_ignored:false, is_virtual_interface:false, is_acknowledged:true, location:'Server Room', tags:'server,critical', tags_array:['server','critical'], first_seen:ago(180*24*60), last_seen:ago(1), status_changed_at:ago(30*24*60), scan_results:{open_ports:[{port:22,service:'ssh'},{port:80,service:'http'},{port:443,service:'https'},{port:3000,service:'grafana'},{port:5432,service:'postgresql'},{port:8080,service:'http'},{port:8443,service:'https'},{port:9000,service:'portainer'},{port:1883,service:'mqtt'},{port:9091,service:'transmission'}]}, baseline_ports:[22,80,443,3000,5432,8080,8443,9000,1883], vuln_severity:'medium', zone:'servers', notes:'Primary homelab server', group_members:null },
  { mac_address:'dc:a6:32:4e:78:11', ip_address:'192.168.0.10', hostname:'raspberrypi', custom_name:'Pi-hole', display_name:'Pi-hole', vendor:'Raspberry Pi Foundation', device_type:'server', device_type_override:null, vendor_override:null, vendor_inferred:null, is_online:true, is_important:true, deep_scanned:true, is_ignored:false, is_virtual_interface:false, is_acknowledged:true, location:'Server Room', tags:'dns,pihole', tags_array:['dns','pihole'], first_seen:ago(60*24*60), last_seen:ago(5), status_changed_at:ago(3*24*60), scan_results:{open_ports:[{port:22,service:'ssh'},{port:53,service:'dns'},{port:80,service:'http'},{port:4711,service:'pihole-api'}]}, baseline_ports:[22,53,80,4711], vuln_severity:null, zone:'servers', notes:null, group_members:null },
  { mac_address:'74:da:38:ab:cd:ef', ip_address:'192.168.0.15', hostname:'DESKTOP-A4F9K', custom_name:null, display_name:'DESKTOP-A4F9K', vendor:'Micro-Star International', device_type:'desktop', device_type_override:null, vendor_override:null, vendor_inferred:null, is_online:true, is_important:false, deep_scanned:true, is_ignored:false, is_virtual_interface:false, is_acknowledged:true, location:null, tags:null, tags_array:[], first_seen:ago(45*24*60), last_seen:ago(15), status_changed_at:ago(45*24*60), scan_results:{open_ports:[{port:135,service:'msrpc'},{port:139,service:'netbios'},{port:445,service:'smb'},{port:3389,service:'rdp'},{port:5900,service:'vnc'}]}, baseline_ports:[135,139,445,3389], vuln_severity:'low', zone:null, notes:null, group_members:null },
  { mac_address:'f0:18:98:bc:de:01', ip_address:'192.168.0.20', hostname:'MacBook-Pro', custom_name:"Sarah's MacBook", display_name:"Sarah's MacBook", vendor:'Apple', device_type:'laptop', device_type_override:null, vendor_override:null, vendor_inferred:null, is_online:true, is_important:false, deep_scanned:false, is_ignored:false, is_virtual_interface:false, is_acknowledged:true, location:'Living Room', tags:null, tags_array:[], first_seen:ago(7*24*60), last_seen:ago(8), status_changed_at:ago(7*24*60), scan_results:null, baseline_ports:null, vuln_severity:null, zone:null, notes:null, group_members:null },
  { mac_address:'68:c6:3a:81:6c:c4', ip_address:'192.168.0.25', hostname:null, custom_name:'Living Room TV', display_name:'Living Room TV', vendor:'Samsung Electronics', device_type:'tv', device_type_override:null, vendor_override:null, vendor_inferred:null, is_online:true, is_important:false, deep_scanned:true, is_ignored:false, is_virtual_interface:false, is_acknowledged:true, location:'Living Room', tags:'tv,media', tags_array:['tv','media'], first_seen:ago(120*24*60), last_seen:ago(3), status_changed_at:ago(10*24*60), scan_results:{open_ports:[{port:8001,service:'samsung-tv'},{port:9197,service:'http'},{port:7676,service:'http'}]}, baseline_ports:[8001,9197,7676], vuln_severity:null, zone:null, notes:null, group_members:null },
  { mac_address:'b0:2a:43:55:66:77', ip_address:'192.168.0.30', hostname:null, custom_name:'Ring Doorbell', display_name:'Ring Doorbell', vendor:'Ring (Amazon)', device_type:'camera', device_type_override:null, vendor_override:null, vendor_inferred:null, is_online:true, is_important:true, deep_scanned:true, is_ignored:false, is_virtual_interface:false, is_acknowledged:true, location:'Front Door', tags:'security,camera', tags_array:['security','camera'], first_seen:ago(200*24*60), last_seen:ago(1), status_changed_at:ago(200*24*60), scan_results:{open_ports:[{port:443,service:'https'},{port:8443,service:'https'}]}, baseline_ports:[443,8443], vuln_severity:null, zone:'iot', notes:null, group_members:null },
  { mac_address:'68:c6:3a:81:6c:c5', ip_address:'192.168.0.35', hostname:'ESP_816CC5', custom_name:'Garden Sensor', display_name:'Garden Sensor', vendor:'Espressif', device_type:'iot', device_type_override:null, vendor_override:null, vendor_inferred:null, is_online:true, is_important:false, deep_scanned:true, is_ignored:false, is_virtual_interface:false, is_acknowledged:true, location:'Garden', tags:'iot,sensor', tags_array:['iot','sensor'], first_seen:ago(30*24*60), last_seen:ago(4), status_changed_at:ago(30*24*60), scan_results:{open_ports:[{port:80,service:'http'},{port:1883,service:'mqtt'}]}, baseline_ports:[80,1883], vuln_severity:null, zone:'iot', notes:null, group_members:null },
  { mac_address:'40:9f:38:cc:dd:ee', ip_address:'192.168.0.42', hostname:null, custom_name:'Fire TV Stick', display_name:'Fire TV Stick', vendor:'Amazon Technologies', device_type:'streamer', device_type_override:null, vendor_override:null, vendor_inferred:null, is_online:true, is_important:false, deep_scanned:false, is_ignored:false, is_virtual_interface:false, is_acknowledged:true, location:'Bedroom', tags:'media', tags_array:['media'], first_seen:ago(150*24*60), last_seen:ago(20), status_changed_at:ago(150*24*60), scan_results:null, baseline_ports:null, vuln_severity:null, zone:null, notes:null, group_members:null },
  { mac_address:'00:d9:e5:11:22:33', ip_address:'192.168.0.50', hostname:null, custom_name:'PlayStation 5', display_name:'PlayStation 5', vendor:'Sony Interactive Entertainment', device_type:'console', device_type_override:null, vendor_override:null, vendor_inferred:null, is_online:true, is_important:false, deep_scanned:false, is_ignored:false, is_virtual_interface:false, is_acknowledged:true, location:'Living Room', tags:null, tags_array:[], first_seen:ago(60*24*60), last_seen:ago(35), status_changed_at:ago(60*24*60), scan_results:null, baseline_ports:null, vuln_severity:null, zone:null, notes:null, group_members:null },
  { mac_address:'a8:51:ab:cd:12:34', ip_address:'192.168.0.55', hostname:null, custom_name:'Synology NAS', display_name:'Synology NAS', vendor:'Synology', device_type:'nas', device_type_override:null, vendor_override:null, vendor_inferred:null, is_online:true, is_important:true, deep_scanned:true, is_ignored:false, is_virtual_interface:false, is_acknowledged:true, location:'Server Room', tags:'storage,nas', tags_array:['storage','nas'], first_seen:ago(240*24*60), last_seen:ago(2), status_changed_at:ago(30*24*60), scan_results:{open_ports:[{port:22,service:'ssh'},{port:80,service:'http'},{port:443,service:'https'},{port:5000,service:'synology-dsm'},{port:5001,service:'synology-dsm-ssl'},{port:6690,service:'synology-drive'}]}, baseline_ports:[22,80,443,5000,5001,6690], vuln_severity:null, zone:'servers', notes:null, group_members:null },
  { mac_address:'c8:3a:35:44:55:66', ip_address:'192.168.0.65', hostname:null, custom_name:null, display_name:'192.168.0.65', vendor:'Brother Industries', device_type:'printer', device_type_override:null, vendor_override:null, vendor_inferred:null, is_online:false, is_important:false, deep_scanned:true, is_ignored:false, is_virtual_interface:false, is_acknowledged:true, location:'Office', tags:null, tags_array:[], first_seen:ago(300*24*60), last_seen:ago(26*60), status_changed_at:ago(26*60), scan_results:{open_ports:[{port:9100,service:'jetdirect'},{port:80,service:'http'},{port:443,service:'https'}]}, baseline_ports:[9100,80,443], vuln_severity:null, zone:null, notes:null, group_members:null },
  { mac_address:'3c:67:8c:77:88:99', ip_address:'192.168.0.72', hostname:'Jacks-iPhone', custom_name:"Jack's iPhone", display_name:"Jack's iPhone", vendor:'Apple', device_type:'phone', device_type_override:null, vendor_override:null, vendor_inferred:null, is_online:true, is_important:false, deep_scanned:false, is_ignored:false, is_virtual_interface:false, is_acknowledged:true, location:null, tags:null, tags_array:[], first_seen:ago(15*24*60), last_seen:ago(10), status_changed_at:ago(15*24*60), scan_results:null, baseline_ports:null, vuln_severity:null, zone:null, notes:null, group_members:null },
  { mac_address:'6c:19:8f:88:99:aa', ip_address:'192.168.0.80', hostname:null, custom_name:'Nest Hub', display_name:'Nest Hub', vendor:'Google', device_type:'iot', device_type_override:null, vendor_override:null, vendor_inferred:null, is_online:true, is_important:false, deep_scanned:false, is_ignored:false, is_virtual_interface:false, is_acknowledged:false, location:'Kitchen', tags:'smart-home', tags_array:['smart-home'], first_seen:ago(2*24*60), last_seen:ago(6), status_changed_at:ago(2*24*60), scan_results:null, baseline_ports:null, vuln_severity:null, zone:'iot', notes:null, group_members:null },
  { mac_address:'e8:48:b8:aa:bb:cc', ip_address:'192.168.0.90', hostname:'android-tv-bedroom', custom_name:'Bedroom Android TV', display_name:'Bedroom Android TV', vendor:'Xiaomi Communications', device_type:'tv', device_type_override:null, vendor_override:null, vendor_inferred:null, is_online:false, is_important:false, deep_scanned:false, is_ignored:false, is_virtual_interface:false, is_acknowledged:true, location:'Bedroom', tags:null, tags_array:[], first_seen:ago(100*24*60), last_seen:ago(48*60), status_changed_at:ago(48*60), scan_results:null, baseline_ports:null, vuln_severity:null, zone:null, notes:null, group_members:null },
  { mac_address:'28:e6:a9:bb:68:03', ip_address:'192.168.0.100', hostname:null, custom_name:'Hue Bridge', display_name:'Hue Bridge', vendor:'Philips Hue', device_type:'iot', device_type_override:null, vendor_override:null, vendor_inferred:null, is_online:true, is_important:false, deep_scanned:true, is_ignored:false, is_virtual_interface:false, is_acknowledged:true, location:'Hallway', tags:'smart-home,lighting', tags_array:['smart-home','lighting'], first_seen:ago(365*24*60), last_seen:ago(3), status_changed_at:ago(365*24*60), scan_results:{open_ports:[{port:80,service:'http'},{port:443,service:'https'},{port:1900,service:'upnp'}]}, baseline_ports:[80,443,1900], vuln_severity:null, zone:'iot', notes:null, group_members:null },
]

const DEMO_STATS = {
  total_devices: DEMO_DEVICES.length,
  online: DEMO_DEVICES.filter(d => d.is_online).length,
  offline: DEMO_DEVICES.filter(d => !d.is_online).length,
  important: DEMO_DEVICES.filter(d => d.is_important).length,
  scanned: DEMO_DEVICES.filter(d => d.deep_scanned).length,
  new_this_week: 2,
}

const DEMO_CONTAINERS = [
  { id:'abc1abc1abc1abc1abc1abc1abc1abc1abc1abc1abc1abc1abc1abc1abc1abc1', name:'inspectre-web', status:'running', image:'thefunkygibbon/inspectre-web:latest', created:ago(14*24*60), state:{status:'running', started_at:ago(2*24*60), finished_at:null}, ports:[{container_port:'8000/tcp',host_port:'8000',protocol:'tcp'}], labels:{'com.docker.compose.service':'web'}, networks:['inspectre_network'], restart_policy:'unless-stopped' },
  { id:'bcd2bcd2bcd2bcd2bcd2bcd2bcd2bcd2bcd2bcd2bcd2bcd2bcd2bcd2bcd2bcd2', name:'inspectre-db', status:'running', image:'postgres:15-alpine', created:ago(14*24*60), state:{status:'running', started_at:ago(2*24*60), finished_at:null}, ports:[{container_port:'5432/tcp',host_port:null,protocol:'tcp'}], labels:{'com.docker.compose.service':'db'}, networks:['inspectre_network'], restart_policy:'unless-stopped' },
  { id:'cde3cde3cde3cde3cde3cde3cde3cde3cde3cde3cde3cde3cde3cde3cde3cde3', name:'inspectre-probe', status:'running', image:'thefunkygibbon/inspectre-probe:latest', created:ago(14*24*60), state:{status:'running', started_at:ago(2*24*60), finished_at:null}, ports:[{container_port:'8666/tcp',host_port:'8666',protocol:'tcp'}], labels:{'com.docker.compose.service':'probe'}, networks:['host'], restart_policy:'unless-stopped' },
  { id:'def4def4def4def4def4def4def4def4def4def4def4def4def4def4def4def4', name:'portainer', status:'running', image:'portainer/portainer-ce:latest', created:ago(30*24*60), state:{status:'running', started_at:ago(5*24*60), finished_at:null}, ports:[{container_port:'9000/tcp',host_port:'9000',protocol:'tcp'}], labels:{}, networks:['bridge'], restart_policy:'unless-stopped' },
  { id:'efa5efa5efa5efa5efa5efa5efa5efa5efa5efa5efa5efa5efa5efa5efa5efa5', name:'homeassistant', status:'running', image:'homeassistant/home-assistant:stable', created:ago(90*24*60), state:{status:'running', started_at:ago(3*24*60), finished_at:null}, ports:[{container_port:'8123/tcp',host_port:'8123',protocol:'tcp'}], labels:{}, networks:['host'], restart_policy:'unless-stopped' },
  { id:'fab6fab6fab6fab6fab6fab6fab6fab6fab6fab6fab6fab6fab6fab6fab6fab6', name:'plex', status:'exited', image:'plexinc/pms-docker:public', created:ago(60*24*60), state:{status:'exited', started_at:null, finished_at:ago(3*24*60)}, ports:[{container_port:'32400/tcp',host_port:'32400',protocol:'tcp'}], labels:{}, networks:['bridge'], restart_policy:'unless-stopped' },
  { id:'gab7gab7gab7gab7gab7gab7gab7gab7gab7gab7gab7gab7gab7gab7gab7gab7', name:'nginx-proxy', status:'running', image:'jc21/nginx-proxy-manager:latest', created:ago(45*24*60), state:{status:'running', started_at:ago(2*24*60), finished_at:null}, ports:[{container_port:'80/tcp',host_port:'80',protocol:'tcp'},{container_port:'443/tcp',host_port:'443',protocol:'tcp'},{container_port:'81/tcp',host_port:'81',protocol:'tcp'}], labels:{}, networks:['bridge'], restart_policy:'unless-stopped' },
  { id:'hbc8hbc8hbc8hbc8hbc8hbc8hbc8hbc8hbc8hbc8hbc8hbc8hbc8hbc8hbc8hbc8', name:'mqtt-broker', status:'running', image:'eclipse-mosquitto:2', created:ago(20*24*60), state:{status:'running', started_at:ago(2*24*60), finished_at:null}, ports:[{container_port:'1883/tcp',host_port:'1883',protocol:'tcp'},{container_port:'9001/tcp',host_port:'9001',protocol:'tcp'}], labels:{}, networks:['bridge'], restart_policy:'unless-stopped' },
]

const DEMO_SETTINGS = [
  {key:'scan_interval',value:'120'},{key:'scan_range',value:'192.168.0.0/24'},
  {key:'notifications_enabled',value:'true'},{key:'alert_on_new_device',value:'true'},
  {key:'alert_on_offline',value:'true'},{key:'float_new_to_top',value:'true'},
  {key:'auto_update_enabled',value:'false'},{key:'auto_update_hour',value:'3'},
  {key:'auto_update_days',value:'1'},{key:'timezone',value:'Europe/London'},
  {key:'skin',value:'phantom'},{key:'theme',value:'dark'},
]

const DEMO_EVENTS = [
  {id:1, mac_address:'6c:19:8f:88:99:aa', event_type:'joined', detail:'First seen on network', timestamp:ago(2*24*60)},
  {id:2, mac_address:'02:c1:11:3e:97:03', event_type:'port_change', detail:'New port 1883 (MQTT) detected', timestamp:ago(5*24*60)},
  {id:3, mac_address:'c8:3a:35:44:55:66', event_type:'offline', detail:'3 missed sweeps + ping fail', timestamp:ago(26*60)},
  {id:4, mac_address:'74:da:38:ab:cd:ef', event_type:'online', detail:'Device came back online', timestamp:ago(15)},
  {id:5, mac_address:'28:e6:a9:bb:68:03', event_type:'scan_complete', detail:'3 open ports found', timestamp:ago(7*24*60)},
]

// ── Route matcher ─────────────────────────────────────────────────────────────
function mockResponse(data, status = 200) {
  const body = JSON.stringify(data)
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function deviceByMac(mac) {
  return DEMO_DEVICES.find(d => d.mac_address === mac) || null
}

function handleMockRequest(url, method, body) {
  const path = url.replace(/^.*\/api/, '')

  // Auth
  if (path === '/auth/login' && method === 'POST')
    return mockResponse({ access_token: 'demo-token', token_type: 'bearer', must_change_password: false })
  if (path === '/auth/me')
    return mockResponse({ username: 'demo', must_change_password: false })

  // Setup
  if (path === '/setup/status')
    return mockResponse({ setup_complete: true, is_appliance: false })

  // Devices
  if (path === '/devices' || path.startsWith('/devices?'))
    return mockResponse(DEMO_DEVICES)
  if (path === '/stats')
    return mockResponse(DEMO_STATS)
  if (path.match(/^\/devices\/[^/]+$/) && method === 'GET') {
    const mac = path.split('/')[2]
    const dev = deviceByMac(decodeURIComponent(mac))
    return dev ? mockResponse(dev) : mockResponse({detail:'Not found'}, 404)
  }
  if (path.match(/^\/devices\/[^/]+\/ip-history/)) {
    const mac = path.split('/')[2]
    const dev = deviceByMac(decodeURIComponent(mac))
    if (mac === '02:c1:11:3e:97:03') return mockResponse([
      {ip:'192.168.0.2', mac_address:mac, first_seen:ago(180*24*60), last_seen:ago(1), is_primary:true, locked:true},
      {ip:'192.168.0.6', mac_address:mac, first_seen:ago(365*24*60), last_seen:ago(180*24*60), is_primary:false, locked:false},
    ])
    return mockResponse(dev ? [{ip:dev.ip_address, mac_address:mac, first_seen:dev.first_seen, last_seen:dev.last_seen, is_primary:true, locked:false}] : [])
  }
  if (path.match(/^\/devices\/[^/]+\/events/))
    return mockResponse({ events: DEMO_EVENTS.filter(e => path.includes(e.mac_address)), total: 0, has_more: false })
  if (path.match(/^\/devices\/[^/]+\/vuln-reports/)) {
    const mac = path.split('/')[2]
    if (mac === '02:c1:11:3e:97:03') return mockResponse([{
      id:1, mac_address:mac, severity:'medium', scan_date:ago(30), findings:[
        {cve:'CVE-2024-1234', severity:'medium', port:22, service:'OpenSSH 8.4', description:'Authentication bypass in some edge-case configurations.'},
        {cve:'CVE-2023-5678', severity:'low', port:5432, service:'PostgreSQL 14.5', description:'Privilege escalation via crafted SQL query.'},
      ], raw_output:'nmap vuln scan output...'
    }])
    if (mac === '74:da:38:ab:cd:ef') return mockResponse([{
      id:2, mac_address:mac, severity:'low', scan_date:ago(7*24*60), findings:[
        {cve:'CVE-2024-3456', severity:'low', port:445, service:'SMBv1', description:'SMBv1 protocol enabled — legacy exploit risk.'},
      ], raw_output:'nmap vuln scan output...'
    }])
    return mockResponse([])
  }
  if (path.match(/^\/devices\/[^/]+\/services/))
    return mockResponse([])
  if (path.match(/^\/devices\/[^/]+\/group/))
    return mockResponse(null)
  if (path.match(/^\/devices\/[^/]+\//)) {
    // PATCH/POST mutations — return success with updated device
    const mac = path.split('/')[2]
    const dev = deviceByMac(decodeURIComponent(mac))
    return mockResponse(dev || {})
  }

  // Settings
  if (path === '/settings' && method === 'GET')
    return mockResponse(DEMO_SETTINGS)
  if (path.startsWith('/settings/') && method === 'PUT')
    return mockResponse({ key: path.split('/')[2], value: body?.value || '' })

  // Docker
  if (path === '/docker/containers' && method === 'GET')
    return mockResponse(DEMO_CONTAINERS)
  if (path === '/docker/stats')
    return mockResponse({ total: DEMO_CONTAINERS.length, running: DEMO_CONTAINERS.filter(c=>c.status==='running').length, stopped: DEMO_CONTAINERS.filter(c=>c.status!=='running').length })
  if (path === '/docker/update-status')
    return mockResponse({ last_checked: ago(60), containers: {} })
  if (path === '/docker/vuln-summary')
    return mockResponse({ total_scanned: 0, critical: 0, high: 0, medium: 0, low: 0 })
  if (path.match(/^\/docker\/containers\/[^/]+$/) && method === 'GET') {
    const id = path.split('/')[3]
    const c = DEMO_CONTAINERS.find(c => c.id.startsWith(id))
    return c ? mockResponse(c) : mockResponse({detail:'Not found'}, 404)
  }
  if (path.match(/^\/docker\/containers\/[^/]+\/update-status/))
    return mockResponse({ has_update: false, update_in_progress: false, pinned: false })
  if (path.match(/^\/docker\/containers\/[^/]+\/compose/))
    return mockResponse({ compose: '# Demo compose file\nversion: "3"\nservices:\n  demo:\n    image: demo:latest\n' })
  if (path.match(/^\/docker\/containers\/[^/]+\/networks/))
    return mockResponse(['bridge'])
  if (path.match(/^\/docker\/containers\/[^/]+\//))
    return mockResponse({ success: true })
  if (path.startsWith('/docker/'))
    return mockResponse({ success: true })

  // Notifications
  if (path === '/notifications/pending')
    return mockResponse({ notifications: [] })

  // Network events
  if (path.startsWith('/network/events') || path === '/network/timeline')
    return mockResponse({ events: DEMO_EVENTS, total: DEMO_EVENTS.length })

  // Zones
  if (path === '/devices/meta/zones')
    return mockResponse(['servers', 'iot', 'trusted', 'guest'])
  if (path === '/zones')
    return mockResponse([])

  // System / misc
  if (path === '/system/info')
    return mockResponse({ version: '1.0.0-demo', is_appliance: false, timezone: 'Europe/London', auto_update: { enabled: false } })
  if (path.startsWith('/system/'))
    return mockResponse({ success: true })
  if (path === '/hosts')
    return mockResponse([])
  if (path.startsWith('/fingerprints'))
    return mockResponse([])
  if (path === '/devices/ip-management')
    return mockResponse({ devices: [] })

  // Network status / blocking
  if (path === '/network/status')
    return mockResponse({ blocked: false, paused: false, blocked_count: 0 })
  if (path === '/block-schedules')
    return mockResponse([])
  if (path.match(/^\/block-schedules\//))
    return mockResponse({ success: true })
  if (path.match(/^\/devices\/[^/]+\/block/) || path.match(/^\/devices\/[^/]+\/unblock/))
    return mockResponse({ success: true })

  // Persons / presence
  if (path === '/persons')
    return mockResponse([
      { id:1, name:'Sarah', notes:'Family', primary_mac:'f0:18:98:bc:de:01', photo:null, is_home:true, last_seen:ago(8),  schedules:[], devices:[{mac_address:'f0:18:98:bc:de:01',display_name:"Sarah's MacBook",is_online:true}] },
      { id:2, name:'Jack',  notes:'Family', primary_mac:'3c:67:8c:77:88:99', photo:null, is_home:true, last_seen:ago(10), schedules:[], devices:[{mac_address:'3c:67:8c:77:88:99',display_name:"Jack's iPhone",is_online:true}] },
    ])
  if (path.startsWith('/persons/timeline')) {
    const now = new Date()
    const windowStart = new Date(now - 7*24*60*60*1000)
    const persons = [
      { id:1, name:'Sarah', at_home_pct:72, segments:[
        { from: new Date(now - 7*24*60*60*1000).toISOString(), to: new Date(now - 6.5*24*60*60*1000).toISOString(), status:'home' },
        { from: new Date(now - 6.5*24*60*60*1000).toISOString(), to: new Date(now - 6*24*60*60*1000).toISOString(), status:'away' },
        { from: new Date(now - 6*24*60*60*1000).toISOString(), to: new Date(now - 5*24*60*60*1000).toISOString(), status:'home' },
        { from: new Date(now - 4*24*60*60*1000).toISOString(), to: new Date(now - 3*24*60*60*1000).toISOString(), status:'home' },
        { from: new Date(now - 2*24*60*60*1000).toISOString(), to: new Date(now - 1*24*60*60*1000).toISOString(), status:'home' },
        { from: new Date(now - 1*24*60*60*1000).toISOString(), to: now.toISOString(), status:'home' },
      ]},
      { id:2, name:'Jack', at_home_pct:45, segments:[
        { from: new Date(now - 7*24*60*60*1000).toISOString(), to: new Date(now - 5*24*60*60*1000).toISOString(), status:'away' },
        { from: new Date(now - 5*24*60*60*1000).toISOString(), to: new Date(now - 4*24*60*60*1000).toISOString(), status:'home' },
        { from: new Date(now - 3*24*60*60*1000).toISOString(), to: new Date(now - 2*24*60*60*1000).toISOString(), status:'home' },
        { from: new Date(now - 2*24*60*60*1000).toISOString(), to: now.toISOString(), status:'home' },
      ]},
    ]
    return mockResponse({ window_start: windowStart.toISOString(), window_end: now.toISOString(), persons })
  }
  if (path.match(/^\/persons\/[^/]+\//))
    return mockResponse({ success: true })
  if (path.match(/^\/persons\/[^/]+$/))
    return mockResponse({ success: true })

  // Timeline / events
  if (path.startsWith('/timeline'))
    return mockResponse({ days: [
      { date: ago(0), events: [
        { mac_address:'6c:19:8f:88:99:aa', event_type:'joined',   display_name:'Nest Hub',      ip_address:'192.168.0.80',  timestamp: ago(2*24*60) },
        { mac_address:'c8:3a:35:44:55:66', event_type:'offline',  display_name:'Brother Printer',ip_address:'192.168.0.65', timestamp: ago(26*60) },
        { mac_address:'74:da:38:ab:cd:ef', event_type:'online',   display_name:'DESKTOP-A4F9K', ip_address:'192.168.0.15',  timestamp: ago(15) },
        { mac_address:'02:c1:11:3e:97:03', event_type:'port_change',display_name:'Home Server', ip_address:'192.168.0.2',   timestamp: ago(5*24*60) },
      ]},
    ]})
  if (path.match(/^\/devices\/[^/]+\/timeline/)) {
    const mac = decodeURIComponent(path.split('/')[2])
    return mockResponse([
      { event_type:'online',       timestamp: ago(1),         detail:'Sighting via ARP' },
      { event_type:'scan_complete',timestamp: ago(60),        detail:'Ports found' },
      { event_type:'joined',       timestamp: ago(30*24*60),  detail:'First seen on network' },
    ])
  }

  // Device events (timeline tab uses this too)
  if (path.match(/^\/devices\/[^/]+\/events/))
    return mockResponse({ events:[
      { id:1, event_type:'online',       timestamp: ago(1),        detail:'Sighting via ARP' },
      { id:2, event_type:'scan_complete',timestamp: ago(60),       detail:'Portscan complete' },
      { id:3, event_type:'joined',       timestamp: ago(30*24*60), detail:'First seen' },
    ], total:3, has_more:false })

  // Vuln scan status
  if (path.match(/^\/devices\/[^/]+\/vuln-scan-status/))
    return mockResponse({ scanning: false, last_scan: ago(24*60), status: 'idle' })

  // Traffic
  if (path === '/traffic/active')
    return mockResponse({ active: [] })
  if (path === '/traffic/summary')
    return mockResponse({ devices: [], total_bytes: 0, period_seconds: 60 })
  if (path.match(/^\/traffic\/live\//))
    return mockResponse({ packets: [], bytes_in: 0, bytes_out: 0 })
  if (path.match(/^\/traffic\//))
    return mockResponse({ success: true })

  // Speedtest
  if (path === '/speedtest/results')
    return mockResponse([
      { id:1, timestamp: ago(24*60), download_mbps: 450.2, upload_mbps: 38.7, ping_ms: 12, server: 'London, UK' },
      { id:2, timestamp: ago(7*24*60), download_mbps: 442.1, upload_mbps: 37.9, ping_ms: 14, server: 'London, UK' },
    ])
  if (path === '/tools/speedtest-servers')
    return mockResponse([{ id:'1234', name:'London, UK', host:'speedtest.example.com', country:'UK' }])
  if (path.match(/^\/speedtest\//))
    return mockResponse({ success: true })

  // Tools (all return demo result)
  if (path.startsWith('/tools/')) {
    const tool = path.split('/')[2].split('?')[0]
    return mockResponse({ result: `[Demo] Tool "${tool}" — results not available in demo mode.`, success: true })
  }

  // Suppressions
  if (path.startsWith('/suppressions'))
    return mockResponse([])

  // Vendors
  if (path === '/vendors')
    return mockResponse(['Dell Technologies','Apple','Samsung Electronics','TP-Link Technologies','Synology','Google','Amazon','Sony'])

  // Fingerprints
  if (path.startsWith('/fingerprints'))
    return mockResponse([])

  // Status events (network events page)
  if (path.startsWith('/network/events'))
    return mockResponse([
      { id:1, mac_address:'6c:19:8f:88:99:aa', event_type:'joined',    display_name:'Nest Hub',       ip_address:'192.168.0.80',  timestamp: ago(2*24*60), detail:'First seen on network' },
      { id:2, mac_address:'02:c1:11:3e:97:03', event_type:'port_change',display_name:'Home Server',   ip_address:'192.168.0.2',   timestamp: ago(5*24*60), detail:'New port 1883 (MQTT)' },
      { id:3, mac_address:'c8:3a:35:44:55:66', event_type:'offline',   display_name:'Brother Printer',ip_address:'192.168.0.65',  timestamp: ago(26*60),   detail:'Missed 3 sweeps' },
      { id:4, mac_address:'74:da:38:ab:cd:ef', event_type:'online',    display_name:'DESKTOP-A4F9K',  ip_address:'192.168.0.15',  timestamp: ago(15),      detail:'Back online via ARP' },
      { id:5, mac_address:'a4:91:b1:12:34:56', event_type:'scan_complete',display_name:'TP-Link Router',ip_address:'192.168.0.1', timestamp: ago(90*60),   detail:'5 open ports found' },
    ])

  // Zones
  if (path === '/zones')
    return mockResponse([
      { name:'servers', device_count:3 }, { name:'iot', device_count:4 },
      { name:'trusted', device_count:5 }, { name:'guest', device_count:2 },
    ])
  if (path === '/zones/assign' || path.match(/^\/zones\//))
    return mockResponse({ success: true })

  // Status events used by NetworkEventLog
  if (path.startsWith("/events/status"))
    return mockResponse([
      { id:1, mac_address:"6c:19:8f:88:99:aa", event_type:"joined",     display_name:"Nest Hub",       ip_address:"192.168.0.80", timestamp:ago(2*24*60),  detail:"First seen on network" },
      { id:2, mac_address:"02:c1:11:3e:97:03", event_type:"port_change",display_name:"Home Server",   ip_address:"192.168.0.2",  timestamp:ago(5*24*60),  detail:"New port 1883 (MQTT)" },
      { id:3, mac_address:"c8:3a:35:44:55:66", event_type:"offline",    display_name:"Brother Printer",ip_address:"192.168.0.65",timestamp:ago(26*60),    detail:"Missed 3 sweeps" },
      { id:4, mac_address:"74:da:38:ab:cd:ef", event_type:"online",     display_name:"DESKTOP-A4F9K", ip_address:"192.168.0.15", timestamp:ago(15),       detail:"Back online" },
      { id:5, mac_address:"28:e6:a9:bb:68:03", event_type:"scan_complete",display_name:"Hue Bridge",  ip_address:"192.168.0.100",timestamp:ago(7*24*60),  detail:"3 open ports found" },
    ])

  // Catch-all — return empty success
  return mockResponse({ success: true, results: [], data: [] })
}

// ── Patch fetch ───────────────────────────────────────────────────────────────
const _realFetch = window.fetch.bind(window)

window.fetch = function demoFetch(input, init = {}) {
  const url = typeof input === 'string' ? input : input.url
  const method = (init.method || 'GET').toUpperCase()

  if (url.includes('/api/')) {
    let bodyData = null
    if (init.body) {
      try { bodyData = JSON.parse(init.body) } catch (_) {}
    }

    // SSE endpoints — return a minimal readable stream that closes immediately
    const sseEndpoints = ['/ping', '/traceroute', '/logs', '/trivy-scan', '/vuln-scan', '/scan-new-image', '/safe-update']
    if (sseEndpoints.some(ep => url.includes(ep))) {
      const stream = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('data: {"line":"[demo] Command output not available in demo mode."}\n\n'))
          controller.enqueue(new TextEncoder().encode('data: {"done":true}\n\n'))
          controller.close()
        }
      })
      return Promise.resolve(new Response(stream, {
        status: 200,
        headers: { 'Content-Type': 'text/event-stream' },
      }))
    }

    const response = handleMockRequest(url, method, bodyData)
    return Promise.resolve(response)
  }

  return _realFetch(input, init)
}

// Inject a fake auth token so the app skips the login screen
if (!localStorage.getItem('inspectre_token')) {
  localStorage.setItem('inspectre_token', 'demo-token')
}

console.log('[InSpectre Demo] Fetch interceptor active — all API calls mocked')
