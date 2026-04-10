/**
 * deviceCategories.js
 * Multi-signal, tiered confidence-scored categorisation engine.
 *
 * Tier 1 — Explicit protocol / OUI fingerprints:  high confidence (80-95 pts)
 * Tier 2 — Hostname / OS keyword patterns:        medium confidence (55-90 pts)
 * Tier 3 — OUI for ambiguous mega-vendors:        LOW prior only  (25-35 pts)
 * Tier 4 — Port/service hints:                    supplementary   (15-55 pts)
 *
 * A category is only assigned when a device's best score reaches the
 * CONFIDENCE_THRESHOLD.  Devices below the threshold stay 'unknown' rather
 * than receiving a guess based on weak evidence.
 *
 * AMBIGUOUS MEGA-VENDOR RULE
 * Brands like Samsung, Apple, LG, Sony, TP-Link, Xiaomi, Huawei manufacture
 * everything from phones to TVs to routers.  Their OUI alone is not enough
 * to assign a category.  These entries are given a LOW score (25-35) so they
 * only tip the balance when keyword or port evidence agrees.  Without that
 * corroboration the device remains 'unknown'.
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

// Minimum score needed before we commit to a category.
// Raised from 40 → 60 so that a single weak-prior OUI hit is never enough.
const CONFIDENCE_THRESHOLD = 60

/**
 * MAC OUI prefix → category type + confidence score.
 *
 * HIGH scores (80-95): OUI uniquely identifies device type (Nintendo, Hikvision,
 *   PS/Xbox OUIs, dedicated NIC vendors for consoles/cameras etc.).
 * LOW scores (25-35):  Ambiguous mega-vendors (Samsung, Apple, LG, Sony, TP-Link,
 *   Xiaomi, Huawei, Realtek) — act as a weak prior only.
 *
 * Format: [ ouiPrefix, categoryKey, score ]
 */
const OUI_MAP = [
  // ── Network Infrastructure — SPECIFIC vendors ─────────────────────────
  ['00105a', 'router', 90], // 3Com
  ['001018', 'router', 90], // Cisco
  ['0015fa', 'router', 90], // Cisco
  ['001e13', 'router', 90], // Cisco
  ['001fc5', 'voip',   90], // Cisco IP Phone
  ['00085d', 'voip',   90], // Cisco 7900 series
  ['001a2b', 'router', 85], // Cisco-Linksys
  ['002155', 'ap',     90], // Ubiquiti
  ['0418d6', 'ap',     90], // Ubiquiti
  ['044bff', 'ap',     90], // Ubiquiti
  ['24a43c', 'ap',     90], // Ubiquiti
  ['b4fbe4', 'ap',     90], // Ubiquiti
  ['dc9fdb', 'ap',     90], // Ubiquiti
  ['f09fc2', 'ap',     90], // Ubiquiti
  ['788a20', 'ap',     90], // Ubiquiti
  ['e063da', 'ap',     90], // Ubiquiti
  ['1caf05', 'router', 85], // MikroTik
  ['b8690e', 'router', 85], // MikroTik
  ['4c5e0c', 'router', 85], // MikroTik
  ['e4008d', 'router', 85], // MikroTik
  ['1c61b4', 'router', 85], // Netgear
  ['a040a0', 'router', 85], // Netgear
  ['84167f', 'router', 85], // Netgear
  ['c04a00', 'router', 85], // Netgear
  ['0050ba', 'router', 80], // D-Link
  ['30de4b', 'ap',     85], // TP-Link EAP (access points — specific)

  // ── TP-Link / Asus / Realtek — AMBIGUOUS (also make phones, IoT, TVs) ──
  ['c025e9', 'router', 30], // TP-Link — low prior
  ['50c7bf', 'router', 30], // TP-Link — low prior
  ['f4f26d', 'router', 30], // TP-Link — low prior
  ['ac84c6', 'router', 30], // TP-Link — low prior
  ['b0be76', 'router', 30], // TP-Link — low prior
  ['48e1e9', 'iot',    30], // TP-Link Kasa smart plug — low prior
  ['e091f5', 'router', 30], // Asus — low prior
  ['107b44', 'router', 30], // Asus — low prior
  ['00e04c', 'router', 25], // Realtek embedded — very weak

  // ── VMware ────────────────────────────────────────────────────────────
  ['000c29', 'server', 70], // VMware
  ['005056', 'server', 70], // VMware

  // ── Games Consoles — SPECIFIC OUIs ───────────────────────────────────
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

  // ── TVs & Streaming — SPECIFIC OUIs ──────────────────────────────────
  // Samsung Smart TV OUIs known to be TV-only
  ['f0ef86', 'tv', 90], // Samsung Smart TV
  ['8c711c', 'tv', 90], // Samsung Smart TV
  // Samsung generic — AMBIGUOUS (phones, tablets, TVs, printers)
  ['8c8590', 'phone', 30], // Samsung — weak phone prior
  ['0024e9', 'phone', 30], // Samsung — weak phone prior
  ['28988b', 'phone', 30], // Samsung — weak phone prior
  ['0000f0', 'printer',25], // Samsung printer chipset — weak
  // Streaming boxes — SPECIFIC
  ['dc4a3e', 'streamer', 95], // Amazon Fire TV
  ['f0272d', 'streamer', 95], // Amazon Fire TV
  ['74c246', 'streamer', 95], // Amazon Fire TV Stick
  ['a002dc', 'streamer', 95], // Amazon Echo/Fire
  ['0c2758', 'streamer', 95], // Amazon Fire TV
  ['68d93c', 'streamer', 95], // Amazon Alexa/Echo
  ['18742e', 'streamer', 95], // Amazon Echo
  ['4cefc0', 'streamer', 95], // Roku
  ['b86ce5', 'streamer', 95], // Roku
  ['cc6da0', 'streamer', 95], // Roku
  ['d04d2c', 'streamer', 95], // Roku
  ['28ef01', 'streamer', 95], // Google Chromecast
  ['54600a', 'streamer', 95], // Google Chromecast
  ['6cadf8', 'streamer', 95], // Google Chromecast
  // LG — AMBIGUOUS (TVs, phones, monitors)
  ['f4f5d8', 'tv', 30],  // LG — weak TV prior
  ['8875d0', 'tv', 30],  // LG — weak TV prior
  // Sony Bravia — SPECIFIC
  ['a8bb50', 'tv', 90],  // Sony Bravia
  ['ac9b0a', 'tv', 90],  // Sony Bravia
  ['0019e3', 'tv', 90],  // Sony Bravia
  // Sony generic — AMBIGUOUS
  ['0050f2', 'phone', 25], // Sony generic — very weak
  // Nvidia Shield — SPECIFIC
  ['3422fb', 'tv', 90],  // Nvidia Shield
  // Raspberry Pi — multi-purpose, use only as faint prior
  ['b827eb', 'server', 30], // Raspberry Pi — weak server prior
  ['dca632', 'server', 30], // Raspberry Pi 4

  // ── Cameras & Security — SPECIFIC OUIs ───────────────────────────────
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

  // ── Printers — SPECIFIC OUIs ─────────────────────────────────────────
  ['000208', 'printer', 95], // Canon
  ['001c62', 'printer', 95], // Canon
  ['0017c8', 'printer', 95], // Canon
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
  ['00c0ee', 'printer', 85], // Xerox

  // ── Mobile Devices — SPECIFIC Apple OUIs ─────────────────────────────
  // Apple generic OUIs are AMBIGUOUS (iPhone, iPad, Mac, Watch, TV)
  // Only mark known phone-heavy OUI ranges with a LOW prior
  ['f8a9d0', 'phone', 30], // Apple — weak phone prior
  ['3c5282', 'phone', 30], // Apple — weak phone prior
  ['a4c361', 'phone', 30], // Apple — weak phone prior
  ['d8bb2c', 'tablet', 30], // Apple — weak tablet prior
  ['405d82', 'phone', 30], // Apple — weak phone prior
  // Google Pixel — SPECIFIC
  ['acee9e', 'phone', 90], // Google Pixel
  ['f88fca', 'phone', 90], // Google Pixel
  // OnePlus — SPECIFIC
  ['3ce9f7', 'phone', 85], // OnePlus
  // Xiaomi / Huawei / Oppo — AMBIGUOUS
  ['40b0fa', 'phone', 30], // Xiaomi — weak prior
  ['748484', 'phone', 30], // Huawei — weak prior
  ['7c1f00', 'phone', 30], // Oppo — weak prior

  // ── IoT Devices — SPECIFIC chipset vendors ────────────────────────────
  ['68a40e', 'iot', 90], // Tuya Smart
  ['50d4f7', 'iot', 90], // Tuya
  ['a8032a', 'iot', 90], // Espressif ESP8266/ESP32
  ['2462ab', 'iot', 90], // Espressif
  ['3c6105', 'iot', 90], // Espressif
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
  ['3494b3', 'iot', 85], // Sonos
  ['78281b', 'iot', 85], // Sonos
  ['5caafd', 'iot', 90], // Nest/Google Home
  ['80927f', 'iot', 90], // Google Home / Nest
  ['1c56fe', 'iot', 90], // Google Nest
  ['a88664', 'iot', 85], // Wemo / IoT bridge
  ['d46e5c', 'iot', 90], // Meross
  ['b827eb', 'iot',  25], // Raspberry Pi — also IoT, very weak

  // ── Servers & NAS — SPECIFIC ──────────────────────────────────────────
  ['001517', 'nas',    90], // Synology
  ['001132', 'nas',    90], // QNAP
  ['245ebe', 'nas',    90], // QNAP
  ['000d93', 'nas',    90], // Apple Xserve / older Apple server
  ['001d09', 'server', 90], // IBM
  ['d4ae52', 'server', 85], // Dell iDRAC
  ['001a4b', 'server', 85], // Supermicro
  ['ac1f6b', 'server', 85], // Supermicro
  ['3cecef', 'server', 85], // HP iLO
  ['9c8e99', 'server', 85], // HP ProLiant

  // ── VoIP — SPECIFIC ──────────────────────────────────────────────────
  ['000413', 'voip', 90], // Polycom
  ['00907a', 'voip', 90], // Snom
  ['8838b4', 'voip', 90], // Yealink
  ['805ec0', 'voip', 90], // Yealink
  ['541efe', 'voip', 90], // Yealink
]

/** Keyword rules applied to vendor + hostname + OS strings combined.
 *  Format: [ regex, categoryKey, score ]
 *  All matching rules contribute their score.
 */
const KEYWORD_RULES = [
  // ── Network Infrastructure ────────────────────────────────────
  [/\b(router|gateway|openwrt|dd-wrt|tomato)\b/i,                 'router',  70],
  [/\b(cisco|juniper|aruba|brocade|extreme networks)\b/i,          'router',  75],
  [/\b(netgear|zyxel|draytek|edgerouter|edgeswitch)\b/i,           'router',  70],
  [/\b(unifi|ubiquiti|mikrotik|routeros)\b/i,                      'router',  80],
  [/\b(tp-?link|tplink)\b/i,                                       'router',  40],  // ambiguous — also makes IoT/phones
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
  [/\b(raspberry.?pi|raspbian|raspberrypi)\b/i,                    'server',  55],
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
  [80,   'server',  20], [443,  'server',  20],
  [22,   'server',  25],
  [21,   'server',  20],
  [23,   'router',  30],
  [53,   'router',  35],
  [67,   'router',  40],
  [179,  'router',  40],
  [8291, 'router',  50], // MikroTik Winbox
  [8728, 'router',  50], // MikroTik API
  [2601, 'router',  45], // Quagga/Zebra
  [554,  'camera',  50], // RTSP — strong camera signal
  [8000, 'camera',  20], // Hikvision default
  [34567,'camera',  45], // Dahua DVR
  [9527, 'camera',  45], // common IP cam
  [5353, 'iot',     20], // mDNS
  [1900, 'iot',     20], // SSDP/UPnP
  [8883, 'iot',     35], // MQTT/TLS
  [1883, 'iot',     35], // MQTT
  [9100, 'printer', 55], // JetDirect
  [515,  'printer', 55], // LPD
  [631,  'printer', 50], // IPP/CUPS
  [5060, 'voip',    55], // SIP
  [5061, 'voip',    55], // SIP/TLS
  [3074, 'console', 40], // Xbox Live
  [3478, 'console', 40], // PS Network / STUN
  [9295, 'console', 50], // PS Remote Play
  [2049, 'nas',     50], // NFS
  [445,  'nas',     40], // SMB/CIFS
  [548,  'nas',     50], // AFP
  [5000, 'nas',     30], // Synology DSM
  [5001, 'nas',     35], // Synology DSM HTTPS
  [8080, 'server',  15],
]

// ── Scoring engine ───────────────────────────────────────────────────────────

function normaliseMac(mac) {
  return (mac || '').toLowerCase().replace(/[^0-9a-f]/g, '')
}

/**
 * Score a device against all signals and return the winning category key.
 * @param {object} device  — device object from the API
 * @returns {string}       — category key (e.g. 'router', 'console', 'unknown')
 */
export function classifyDevice(device) {
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

  // Find winner
  const entries = Object.entries(scores)
  if (!entries.length) return 'unknown'

  entries.sort((a, b) => b[1] - a[1])
  const [bestKey, bestScore] = entries[0]

  // Must meet the confidence threshold — below this we say 'unknown'
  if (bestScore < CONFIDENCE_THRESHOLD) return 'unknown'

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

  const ordered = new Map()
  for (const groupLabel of CATEGORY_GROUP_ORDER) {
    if (groups.has(groupLabel)) ordered.set(groupLabel, groups.get(groupLabel))
  }
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
