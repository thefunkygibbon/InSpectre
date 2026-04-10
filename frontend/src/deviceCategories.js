/**
 * deviceCategories.js
 * Multi-signal, weighted scoring categorisation engine.
 *
 * Each device is tested against every category. Signals from multiple sources
 * (MAC OUI prefix, vendor string, hostname, open ports, OS string) each add
 * confidence points. The category with the highest total score wins.
 * A minimum threshold must be met before a category is assigned; otherwise
 * the device falls back to 'unknown'.
 *
 * This approach avoids the single-regex-match fragility that causes
 * miscategorisation — a device needs multiple matching signals to be
 * confidently placed in a category.
 */

export const CATEGORIES = {
  router:      { label: 'Network Infrastructure', icon: 'router',   color: '#6366f1', bgColor: 'rgba(99,102,241,0.12)'  },
  switch:      { label: 'Network Infrastructure', icon: 'router',   color: '#6366f1', bgColor: 'rgba(99,102,241,0.12)'  },
  ap:          { label: 'Network Infrastructure', icon: 'router',   color: '#6366f1', bgColor: 'rgba(99,102,241,0.12)'  },
  server:      { label: 'Servers & NAS',          icon: 'server',   color: '#f59e0b', bgColor: 'rgba(245,158,11,0.12)'  },
  nas:         { label: 'Servers & NAS',          icon: 'server',   color: '#f59e0b', bgColor: 'rgba(245,158,11,0.12)'  },
  desktop:     { label: 'PCs & Laptops',          icon: 'monitor',  color: '#3b82f6', bgColor: 'rgba(59,130,246,0.12)'  },
  laptop:      { label: 'PCs & Laptops',          icon: 'laptop',   color: '#3b82f6', bgColor: 'rgba(59,130,246,0.12)'  },
  phone:       { label: 'Mobile Devices',         icon: 'phone',    color: '#10b981', bgColor: 'rgba(16,185,129,0.12)'  },
  tablet:      { label: 'Mobile Devices',         icon: 'phone',    color: '#10b981', bgColor: 'rgba(16,185,129,0.12)'  },
  tv:          { label: 'TVs & Streaming',        icon: 'tv',       color: '#ec4899', bgColor: 'rgba(236,72,153,0.12)'  },
  streamer:    { label: 'TVs & Streaming',        icon: 'tv',       color: '#ec4899', bgColor: 'rgba(236,72,153,0.12)'  },
  console:     { label: 'Games Consoles',         icon: 'gamepad',  color: '#8b5cf6', bgColor: 'rgba(139,92,246,0.12)'  },
  camera:      { label: 'Cameras & Security',     icon: 'camera',   color: '#ef4444', bgColor: 'rgba(239,68,68,0.12)'   },
  printer:     { label: 'Printers',               icon: 'printer',  color: '#64748b', bgColor: 'rgba(100,116,139,0.12)' },
  iot:         { label: 'IoT Devices',            icon: 'cpu',      color: '#14b8a6', bgColor: 'rgba(20,184,166,0.12)'  },
  voip:        { label: 'VoIP & Phones',          icon: 'phone',    color: '#f97316', bgColor: 'rgba(249,115,22,0.12)'  },
  unknown:     { label: 'Unknown',                icon: 'help',     color: '#6b7280', bgColor: 'rgba(107,114,128,0.12)' },
}

// Canonical group ordering for the category view
export const CATEGORY_GROUP_ORDER = [
  'Network Infrastructure',
  'Servers & NAS',
  'PCs & Laptops',
  'Mobile Devices',
  'Games Consoles',
  'TVs & Streaming',
  'Cameras & Security',
  'IoT Devices',
  'Printers',
  'VoIP & Phones',
  'Unknown',
]

/**
 * MAC OUI prefix → category type + confidence score.
 * Source: curated from the IEEE OUI database, focusing on the most common
 * consumer and prosumer vendors seen on home/SMB networks.
 * Format: [ ouiPrefix6chars, categoryKey, score ]
 * Higher score = stronger signal (unique OUIs score higher than shared ones).
 */
const OUI_MAP = [
  // ── Network Infrastructure ──────────────────────────────────────
  ['00105a', 'router', 90], // 3Com
  ['001018', 'router', 90], // Cisco
  ['0015fa', 'router', 90], // Cisco
  ['001e13', 'router', 90], // Cisco
  ['002155', 'router', 90], // Ubiquiti
  ['0418d6', 'ap',     90], // Ubiquiti
  ['044bff', 'ap',     90], // Ubiquiti
  ['0418d6', 'ap',     90], // Ubiquiti
  ['24a43c', 'ap',     90], // Ubiquiti
  ['b4fbe4', 'ap',     90], // Ubiquiti
  ['dc9fdb', 'ap',     90], // Ubiquiti
  ['f09fc2', 'ap',     90], // Ubiquiti
  ['788a20', 'ap',     90], // Ubiquiti
  ['e063da', 'ap',     90], // Ubiquiti
  ['00e04c', 'router', 80], // Realtek (embedded)
  ['001a2b', 'router', 85], // Cisco-Linksys
  ['001cedfe', 'router', 90],
  ['c025e9', 'router', 85], // TP-Link
  ['50c7bf', 'router', 85], // TP-Link
  ['f4f26d', 'router', 85], // TP-Link
  ['ac84c6', 'router', 85], // TP-Link
  ['b0be76', 'router', 85], // TP-Link
  ['30de4b', 'ap',     85], // TP-Link (EAP)
  ['1c61b4', 'router', 85], // Netgear
  ['a040a0', 'router', 85], // Netgear
  ['84167f', 'router', 85], // Netgear
  ['c04a00', 'router', 85], // Netgear
  ['e091f5', 'router', 85], // Asus
  ['107b44', 'router', 85], // Asus
  ['0050ba', 'router', 80], // D-Link
  ['1caf05', 'router', 85], // MikroTik
  ['b8690e', 'router', 85], // MikroTik
  ['4c5e0c', 'router', 85], // MikroTik
  ['e4008d', 'router', 85], // MikroTik
  ['000c29', 'server', 70], // VMware (also server)
  ['005056', 'server', 70], // VMware

  // ── Games Consoles ──────────────────────────────────────────────
  ['001315', 'console', 95], // Nintendo
  ['0009bf', 'console', 95], // Nintendo
  ['002709', 'console', 95], // Nintendo
  ['00197d', 'console', 95], // Nintendo
  ['00212f', 'console', 95], // Nintendo
  ['00224c', 'console', 95], // Nintendo
  ['0025a0', 'console', 95], // Nintendo Switch
  ['7cb5ab', 'console', 95], // Nintendo Switch
  ['98b6e9', 'console', 95], // Nintendo
  ['e84e84', 'console', 95], // Nintendo
  ['a438cc', 'console', 95], // Nintendo Switch Lite
  ['0019c5', 'console', 95], // Sony PlayStation
  ['001d0d', 'console', 95], // Sony PS3
  ['00041f', 'console', 95], // Sony PS3
  ['0050f2', 'console', 80], // Sony (shared)
  ['70662a', 'console', 95], // Sony PS4
  ['bc60a7', 'console', 95], // Sony PS4
  ['c863f1', 'console', 95], // Sony PS4
  ['28ed6a', 'console', 95], // Sony PS4
  ['fc0fe6', 'console', 95], // Sony PS5
  ['042e73', 'console', 95], // Sony PS5
  ['001dd8', 'console', 95], // Microsoft Xbox
  ['7c1e52', 'console', 95], // Microsoft Xbox One
  ['60451d', 'console', 95], // Microsoft Xbox
  ['98520c', 'console', 95], // Microsoft Xbox
  ['20a548', 'console', 95], // Microsoft Xbox One S
  ['28cdc1', 'console', 95], // Microsoft Xbox Series
  ['30107b', 'console', 95], // Microsoft Xbox Series
  ['6045bd', 'console', 95], // Microsoft Xbox Series X
  ['985aeb', 'console', 90], // Valve Steam Deck
  ['d85d4c', 'console', 90], // Valve

  // ── TVs & Streaming ─────────────────────────────────────────────
  ['f0ef86', 'tv', 90], // Samsung Smart TV
  ['8c711c', 'tv', 90], // Samsung Smart TV
  ['b827eb', 'tv', 80], // Raspberry Pi (shared, lower)
  ['dc:a6:32', 'server', 60], // Pi 4 (more likely server)
  ['dc4a3e', 'streamer', 95], // Amazon Fire TV
  ['f0272d', 'streamer', 95], // Amazon Fire TV
  ['74c246', 'streamer', 95], // Amazon Fire TV Stick
  ['a002dc', 'streamer', 95], // Amazon Echo/Fire
  ['0c2758', 'streamer', 95], // Amazon Fire TV
  ['68d93c', 'streamer', 95], // Amazon (Alexa/Echo)
  ['18742e', 'streamer', 95], // Amazon Echo
  ['4c:ef:c0', 'streamer', 95], // Roku
  ['b86ce5', 'streamer', 95], // Roku
  ['cc:6d:a0', 'streamer', 95], // Roku
  ['d0:4d:2c', 'streamer', 95], // Roku
  ['28ef01', 'streamer', 95], // Google Chromecast
  ['54600a', 'streamer', 95], // Google Chromecast
  ['6c:ad:f8', 'streamer', 95], // Google Chromecast
  ['f4f5d8', 'tv', 90],  // LG Smart TV
  ['8875d0', 'tv', 90],  // LG
  ['a8bb50', 'tv', 90],  // Sony Bravia
  ['ac9b0a', 'tv', 90],  // Sony Bravia
  ['0019e3', 'tv', 90],  // Sony Bravia
  ['3422fb', 'tv', 90],  // Nvidia Shield
  ['f4:f5:d8', 'tv', 90], // LG

  // ── Cameras & Security ──────────────────────────────────────────
  ['000f0d', 'camera', 95], // Hikvision
  ['283b96', 'camera', 95], // Hikvision
  ['4c11ae', 'camera', 95], // Hikvision
  ['c87f54', 'camera', 95], // Hikvision
  ['546402', 'camera', 95], // Hikvision
  ['d02789', 'camera', 95], // Dahua
  ['101ba9', 'camera', 95], // Dahua
  ['30e283', 'camera', 95], // Dahua
  ['e0501e', 'camera', 90], // Axis
  ['00408c', 'camera', 90], // Axis
  ['34e6d7', 'camera', 90], // Reolink
  ['ec713d', 'camera', 90], // Reolink
  ['9094e4', 'camera', 90], // Amcrest
  ['d4e0b3', 'camera', 90], // Amcrest/Foscam
  ['9cfc01', 'camera', 90], // Foscam
  ['000c43', 'camera', 85], // Ralink (doorbell/cam chipset)

  // ── Printers ────────────────────────────────────────────────────
  ['000208', 'printer', 95], // Canon
  ['001c62', 'printer', 95], // Canon
  ['00:17:c8', 'printer', 95], // Canon
  ['00004c', 'printer', 90], // HP
  ['001083', 'printer', 90], // HP
  ['3c2af4', 'printer', 90], // HP
  ['784b87', 'printer', 90], // HP
  ['001b78', 'printer', 95], // Epson
  ['647154', 'printer', 95], // Epson
  ['ac18a5', 'printer', 95], // Epson
  ['00809d', 'printer', 95], // Ricoh
  ['0080c8', 'printer', 95], // Ricoh/Lexmark
  ['000a5e', 'printer', 90], // Brother
  ['001ba9', 'printer', 90], // Brother
  ['002477', 'printer', 90], // Brother
  ['0000f0', 'printer', 85], // Samsung printer
  ['00c0ee', 'printer', 85], // Xerox

  // ── Mobile Devices ──────────────────────────────────────────────
  ['f8a9d0', 'phone', 90], // Apple iPhone (various)
  ['3c5282', 'phone', 90], // Apple
  ['a4c361', 'phone', 90], // Apple iPhone
  ['d8bb2c', 'tablet', 90], // Apple iPad
  ['405d82', 'phone', 90], // Apple
  ['8c8590', 'phone', 85], // Samsung mobile
  ['0024e9', 'phone', 85], // Samsung mobile
  ['28988b', 'phone', 85], // Samsung
  ['acee9e', 'phone', 90], // Google Pixel
  ['f88fca', 'phone', 90], // Google Pixel
  ['3ce9f7', 'phone', 85], // OnePlus
  ['40b0fa', 'phone', 85], // Xiaomi
  ['28d1278', 'phone', 85],// Xiaomi
  ['748484', 'phone', 85], // Huawei
  ['7c1f00', 'phone', 85], // Oppo

  // ── IoT Devices ─────────────────────────────────────────────────
  ['68a40e', 'iot', 90], // Tuya Smart (huge IoT chipset vendor)
  ['50d4f7', 'iot', 90], // Tuya
  ['a8032a', 'iot', 90], // Espressif / ESP8266/ESP32
  ['2462ab', 'iot', 90], // Espressif
  ['3c61054', 'iot', 90],// Espressif
  ['2cf432', 'iot', 90], // Espressif
  ['84cca8', 'iot', 90], // Espressif
  ['e89f6d', 'iot', 90], // Espressif
  ['d8bfc0', 'iot', 90], // Espressif
  ['3c71bf', 'iot', 90], // Espressif
  ['445566', 'iot', 85], // Belkin/Wemo
  ['94103e', 'iot', 85], // Belkin
  ['e8ba70', 'iot', 85], // Belkin Wemo
  ['c0c1c0', 'iot', 85], // Philips Hue bridge
  ['001788', 'iot', 90], // Philips Hue
  ['ecb5fa', 'iot', 85], // Philips
  ['b00413', 'iot', 85], // Shelly
  ['c45bbe', 'iot', 85], // Shelly
  ['3494b3', 'iot', 85], // Sonos (often counts as IoT)
  ['78281b', 'iot', 85], // Sonos
  ['5caafd', 'iot', 90], // Nest/Google Home
  ['80927f', 'iot', 90], // Google Home / Nest
  ['1c:56:fe', 'iot', 90], // Google Nest
  ['a88664', 'iot', 85], // Wemo / IoT bridge
  ['d46e5c', 'iot', 90], // Meross
  ['48e1e9', 'iot', 85], // TP-Link Kasa smart plug
  ['50c7bf', 'iot', 80], // TP-Link (shared w/ router, lower)
  ['b8:27:eb', 'iot', 60], // Raspberry Pi (can be IoT too)

  // ── Servers & NAS ───────────────────────────────────────────────
  ['001517', 'nas', 90], // Synology
  ['0011326', 'nas', 90],// QNAP
  ['24:5e:be', 'nas', 90], // QNAP
  ['000d93', 'nas', 90], // Apple Xserve / older Apple
  ['001d09', 'server', 90], // IBM
  ['d4ae52', 'server', 85], // Dell iDRAC
  ['001a4b', 'server', 85], // Supermicro
  ['ac1f6b', 'server', 85], // Supermicro
  ['3cecef', 'server', 85], // HP iLO
  ['9c8e99', 'server', 85], // HP ProLiant

  // ── VoIP ─────────────────────────────────────────────────────────
  ['000413', 'voip', 90], // Polycom
  ['00:90:7a', 'voip', 90], // Snom
  ['001fc5', 'voip', 90], // Cisco IP Phone
  ['8838b4', 'voip', 90], // Yealink
  ['805ec0', 'voip', 90], // Yealink
  ['541efe', 'voip', 90], // Yealink
  ['00085d', 'voip', 90], // Cisco 7900 series
]

/** Keyword rules applied to vendor + hostname + OS strings combined.
 *  Format: [ regex, categoryKey, score ]
 *  Order doesn't matter — all matching rules contribute their score.
 */
const KEYWORD_RULES = [
  // ── Network Infrastructure ────────────────────────────────────
  [/\b(router|gateway|openwrt|dd-wrt|tomato)\b/i,                 'router',  70],
  [/\b(cisco|juniper|aruba|brocade|extreme networks)\b/i,          'router',  75],
  [/\b(netgear|zyxel|draytek|edgerouter|edgeswitch)\b/i,           'router',  70],
  [/\b(unifi|ubiquiti|mikrotik|routeros)\b/i,                      'router',  80],
  [/\b(tp-?link|tplink)\b/i,                                       'router',  55],  // also makes IoT stuff
  [/\b(switch|vlan|poe\s*switch|managed switch)\b/i,               'switch',  70],
  [/\b(access.?point|WAP|wifi.?ap|eap[0-9])\b/i,                  'ap',      75],
  [/\b(asus.?rt|rt-[a-z]{2}[0-9])\b/i,                            'router',  80],
  [/\b(pfSense|opnsense|vyos|firewall)\b/i,                        'router',  85],

  // ── Games Consoles ───────────────────────────────────────────
  [/\b(playstation|PS[345]|PS\s*[345])\b/i,                        'console', 90],
  [/\b(xbox|xbox.?one|xbox.?series|xbox.?360)\b/i,                 'console', 90],
  [/\b(nintendo|switch|wii|wii.?u|3ds|game.?boy|gameboy)\b/i,     'console', 90],
  [/\b(steam.?deck|steamdeck|valve)\b/i,                           'console', 85],
  [/\b(retropie|recalbox|batocera)\b/i,                            'console', 85],

  // ── TVs & Streaming ──────────────────────────────────────────
  [/\b(smart.?tv|bravia|qled|oled.?tv|androidtv|google.?tv)\b/i,  'tv',      85],
  [/\b(samsung.*tv|lg.*tv|hisense|tcl|philips.*tv)\b/i,           'tv',      80],
  [/\b(fire.?tv|firetv|firestick|fire.?stick)\b/i,                'streamer',90],
  [/\b(roku|chromecast|apple.?tv|appletv|shield.?tv)\b/i,         'streamer',90],
  [/\b(plex|kodi|libreelec|osmc|emby)\b/i,                        'streamer',75],

  // ── Cameras & Security ───────────────────────────────────────
  [/\b(hikvision|dahua|axis|foscam|reolink|amcrest|wyze)\b/i,     'camera',  90],
  [/\b(ipcam|ip.cam|nvr|dvr|cctv|doorbell|ring\b|arlo)\b/i,      'camera',  85],
  [/\b(camera|cam\b|surveillance|onvif)\b/i,                      'camera',  70],
  [/\b(blink|eufy.?cam|lorex|swann|annke)\b/i,                    'camera',  90],

  // ── Printers ─────────────────────────────────────────────────
  [/\b(printer|print.?server|MFC-|LaserJet|DeskJet|OfficeJet|inkjet)\b/i, 'printer', 90],
  [/\b(epson|canon|brother|lexmark|ricoh|xerox|konica|kyocera)\b/i,       'printer', 80],
  [/\b(cups|ipp|lpd|jetdirect)\b/i,                                        'printer', 75],

  // ── Mobile Devices ───────────────────────────────────────────
  [/\b(iphone|ipad|ipod)\b/i,                                      'phone',   90],
  [/\b(android|samsung.?(galaxy|a[0-9]|s[0-9])|pixel)\b/i,        'phone',   85],
  [/\b(oneplus|xiaomi|redmi|huawei|oppo|vivo|realme)\b/i,          'phone',   85],
  [/\b(mobile|smartphone|handset)\b/i,                             'phone',   65],
  [/\b(ipad|galaxy.?tab|surface.?go|kindle)\b/i,                  'tablet',  90],

  // ── Servers & NAS ────────────────────────────────────────────
  [/\b(synology|qnap|freenas|truenas|openmediavault|unraid)\b/i,  'nas',     90],
  [/\b(proxmox|esxi|vmware|hyperv|hyper-v|xen|virtualbox)\b/i,   'server',  90],
  [/\b(ubuntu.?server|debian|centos|fedora.?server|rhel|rocky)\b/i,'server', 80],
  [/\b(raspberry.?pi|raspbian|raspberrypi)\b/i,                    'server',  55],  // Pi can be many things
  [/\b(nas\b|network.?attached|file.?server)\b/i,                  'nas',     80],
  [/\b(docker|container|k8s|kubernetes)\b/i,                       'server',  70],
  [/\b(server|srv\b|host\b)\b/i,                                   'server',  50],

  // ── PCs & Laptops ────────────────────────────────────────────
  [/\b(macbook|imac|mac.?mini|mac.?pro|mac.?studio)\b/i,          'laptop',  90],
  [/\b(thinkpad|ideapad|lenovo.?laptop)\b/i,                       'laptop',  90],
  [/\b(dell.?(xps|latitude|inspiron|precision))\b/i,               'laptop',  85],
  [/\b(hp.?(pavilion|spectre|envy|elitebook|probook|omen))\b/i,    'laptop',  85],
  [/\b(surface.?(pro|book|laptop))\b/i,                            'laptop',  90],
  [/\b(laptop|notebook|chromebook|ultrabook)\b/i,                  'laptop',  80],
  [/\b(desktop|workstation|tower|gaming.?pc|gaming.?rig)\b/i,      'desktop', 80],
  [/\b(windows.?(10|11)|win10|win11)\b/i,                          'desktop', 60],
  [/\b(macos|mac.?os|osx|os.?x)\b/i,                              'laptop',  65],

  // ── IoT Devices ──────────────────────────────────────────────
  [/\b(esp[0-9]+|esp32|esp8266|arduino|micropython|tasmota)\b/i,   'iot',     90],
  [/\b(tuya|smart.?plug|smart.?switch|smart.?bulb|smart.?light)\b/i,'iot',   85],
  [/\b(hue|lifx|wemo|belkin|tradfri|zigbee|z-wave|thread)\b/i,    'iot',     85],
  [/\b(alexa|echo\b|google.?home|nest.?(hub|mini)|homepod)\b/i,   'iot',     85],
  [/\b(thermostat|tado|ecobee|honeywell|hive\b)\b/i,              'iot',     85],
  [/\b(sonos|denon|yamaha.?amp|bluesound|audio)\b/i,              'iot',     70],
  [/\b(shelly|meross|kasa|govee|tp-?link.?kasa)\b/i,             'iot',     90],
  [/\b(iot|home.?automation|smart.?home|homekit)\b/i,             'iot',     75],
  [/\b(sensor|hub\b|bridge\b|controller\b)\b/i,                   'iot',     50],

  // ── VoIP ─────────────────────────────────────────────────────
  [/\b(voip|sip|polycom|yealink|snom|grandstream|cisco.?phone)\b/i,'voip',   90],
  [/\b(ip.?phone|desk.?phone|pbx|asterisk)\b/i,                   'voip',   85],
]

/** Port-based hints. Open ports give clues about device role.
 *  Format: [ portNumber, categoryKey, score ]
 */
const PORT_RULES = [
  [80,   'server',  20], [443,  'server',  20], // generic web → weak server signal
  [22,   'server',  25], // SSH → more likely server/NAS/router
  [21,   'server',  20], // FTP
  [23,   'router',  30], // Telnet → often network gear
  [53,   'router',  35], // DNS → router/server
  [67,   'router',  40], // DHCP server
  [179,  'router',  40], // BGP
  [8291, 'router',  50], // MikroTik Winbox
  [8728, 'router',  50], // MikroTik API
  [2601, 'router',  45], // Quagga/Zebra
  [443,  'camera',   5], // cameras often run HTTPS but score is low (shared)
  [554,  'camera',  50], // RTSP — strong camera signal
  [8000, 'camera',  20], // Hikvision default
  [34567,'camera',  45], // Dahua DVR port
  [9527, 'camera',  45], // common IP cam port
  [5353, 'iot',     20], // mDNS — IoT devices use this a lot
  [1900, 'iot',     20], // SSDP / UPnP
  [8883, 'iot',     35], // MQTT over TLS
  [1883, 'iot',     35], // MQTT
  [9100, 'printer', 55], // JetDirect printing
  [515,  'printer', 55], // LPD printing
  [631,  'printer', 50], // IPP (CUPS)
  [5060, 'voip',    55], // SIP
  [5061, 'voip',    55], // SIP/TLS
  [3478, 'console', 30], // STUN (Xbox/PS often probe this)
  [3074, 'console', 40], // Xbox Live
  [3478, 'console', 40], // PS Network
  [9295, 'console', 50], // PS Remote Play
  [2049, 'nas',     50], // NFS
  [445,  'nas',     40], // SMB/CIFS
  [548,  'nas',     50], // AFP (Mac file sharing)
  [5000, 'nas',     30], // Synology DSM
  [5001, 'nas',     35], // Synology DSM HTTPS
  [8080, 'server',  15], // generic web
]

// ── Scoring engine ───────────────────────────────────────────────────────────

/**
 * Normalise a MAC address to a plain 12-char hex string (lowercase, no colons).
 */
function normaliseMac(mac) {
  return (mac || '').toLowerCase().replace(/[^0-9a-f]/g, '')
}

/**
 * Score a device against all signals and return the winning category key.
 * @param {object} device  — device object from the API
 * @returns {string}       — category key (e.g. 'router', 'console', 'unknown')
 */
export function classifyDevice(device) {
  // If user has manually overridden the type, always respect that.
  if (device.device_type_override) return device.device_type_override

  const scores = {}
  function add(key, points) {
    scores[key] = (scores[key] || 0) + points
  }

  const mac      = normaliseMac(device.mac_address)
  const vendor   = (device.vendor_override || device.vendor || '').toLowerCase()
  const hostname = (device.hostname || device.custom_name || '').toLowerCase()
  const os       = ((device.scan_results?.os_matches || []).map(m => m.name).join(' ')).toLowerCase()
  const combined = `${vendor} ${hostname} ${os}`

  // 1. OUI prefix lookup
  for (const [oui, cat, score] of OUI_MAP) {
    const normOui = oui.toLowerCase().replace(/[^0-9a-f]/g, '')
    if (mac.startsWith(normOui)) {
      add(cat, score)
    }
  }

  // 2. Keyword rules against combined string
  for (const [regex, cat, score] of KEYWORD_RULES) {
    if (regex.test(combined)) {
      add(cat, score)
    }
  }

  // 3. Open port hints
  const ports = device.scan_results?.open_ports
  if (Array.isArray(ports)) {
    for (const portObj of ports) {
      for (const [portNum, cat, score] of PORT_RULES) {
        if (portObj.port === portNum) {
          add(cat, score)
        }
      }
    }
  }

  // 4. Normalise: 'router', 'switch', 'ap' all belong to the same display group
  //    but keep them separate so we can pick the right icon later.

  // Find winner
  const entries = Object.entries(scores)
  if (!entries.length) return 'unknown'

  entries.sort((a, b) => b[1] - a[1])
  const [bestKey, bestScore] = entries[0]

  // Minimum confidence threshold — below this we say 'unknown'
  if (bestScore < 40) return 'unknown'

  return bestKey
}

/**
 * Return the CATEGORIES entry for a device, resolving the type first.
 */
export function getDeviceCategory(device) {
  const type = classifyDevice(device)
  return { type, ...( CATEGORIES[type] || CATEGORIES.unknown) }
}

/**
 * Group an array of devices by their display label (e.g. 'Network Infrastructure').
 * Returns a Map keyed by label, in canonical display order.
 */
export function groupDevicesByCategory(devices) {
  const groups = new Map()

  for (const device of devices) {
    const { label } = getDeviceCategory(device)
    if (!groups.has(label)) groups.set(label, [])
    groups.get(label).push(device)
  }

  // Sort groups in canonical order; anything else goes at end
  const ordered = new Map()
  for (const groupLabel of CATEGORY_GROUP_ORDER) {
    if (groups.has(groupLabel)) ordered.set(groupLabel, groups.get(groupLabel))
  }
  // append any unrecognised groups
  for (const [k, v] of groups) {
    if (!ordered.has(k)) ordered.set(k, v)
  }
  return ordered
}

/** All valid category type keys that can be used as manual overrides. */
export const OVERRIDE_OPTIONS = [
  { value: '',         label: '— Auto-detect —'        },
  { value: 'router',   label: 'Router / Gateway'        },
  { value: 'switch',   label: 'Network Switch'          },
  { value: 'ap',       label: 'Access Point'            },
  { value: 'server',   label: 'Server'                  },
  { value: 'nas',      label: 'NAS'                     },
  { value: 'desktop',  label: 'Desktop PC'              },
  { value: 'laptop',   label: 'Laptop'                  },
  { value: 'phone',    label: 'Mobile Phone'            },
  { value: 'tablet',   label: 'Tablet'                  },
  { value: 'tv',       label: 'Smart TV'                },
  { value: 'streamer', label: 'Streaming Stick / Box'   },
  { value: 'console',  label: 'Games Console'           },
  { value: 'camera',   label: 'Camera / Security'       },
  { value: 'printer',  label: 'Printer'                 },
  { value: 'iot',      label: 'IoT Device'              },
  { value: 'voip',     label: 'VoIP / IP Phone'         },
  { value: 'unknown',  label: 'Unknown'                 },
]
