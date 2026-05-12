"""
Local DHCP fingerprinting classifier.

Uses DHCP Option 60 (vendor class identifier) and Option 55 (parameter
request list) to infer device type without any external API calls or
additional network traffic.

Returns a (device_type, confidence) tuple where device_type matches the
taxonomy in frontend/src/deviceCategories.js and confidence is 0.0–1.0.
"""

# (substring, exact_match, device_type, confidence)
# Checked in order; first match wins. Case-insensitive.
_VENDOR_CLASS_RULES: list[tuple[str, bool, str, float]] = [
    # Android
    ("android-dhcp",     False, "phone",    0.95),
    ("android",          False, "phone",    0.85),
    # Apple — specific products before generic
    ("apple iphone",     False, "phone",    0.95),
    ("apple ipad",       False, "tablet",   0.95),
    ("apple ipod",       False, "phone",    0.90),
    ("apple tv",         False, "tv",       0.95),
    ("apple watch",      False, "iot",      0.85),
    ("apple homepod",    False, "iot",      0.90),
    ("apple mac",        False, "desktop",  0.80),
    # Windows
    ("msft 5.0",         True,  "desktop",  0.92),
    ("msft 98",          True,  "desktop",  0.88),
    ("msft",             False, "desktop",  0.80),
    # Amazon
    ("amazonecho",       False, "iot",      0.95),
    ("amazon-echo",      False, "iot",      0.95),
    ("kindle",           False, "tablet",   0.90),
    ("amazon fire",      False, "streamer", 0.90),
    ("fire tv",          False, "streamer", 0.95),
    # Roku
    ("roku",             False, "streamer", 0.95),
    # Gaming
    ("nintendo",         False, "console",  0.95),
    ("playstation",      False, "console",  0.95),
    ("sony-ps",          False, "console",  0.90),
    ("xbox",             False, "console",  0.90),
    # Smart home / IoT
    ("sonos",            False, "iot",      0.95),
    ("ring-",            False, "camera",   0.88),
    ("nest",             False, "iot",      0.85),
    ("ecobee",           False, "iot",      0.90),
    ("philips hue",      False, "iot",      0.90),
    ("signify",          False, "iot",      0.85),
    ("espressif",        False, "iot",      0.85),
    ("esphome",          False, "iot",      0.92),
    ("shelly",           False, "iot",      0.92),
    ("tasmota",          False, "iot",      0.92),
    ("tuya",             False, "iot",      0.85),
    ("ezviz",            False, "camera",   0.90),
    ("dahua",            False, "camera",   0.90),
    ("hikvision",        False, "camera",   0.90),
    ("wyze",             False, "camera",   0.85),
    ("tplink",           False, "iot",      0.75),
    ("kasa",             False, "iot",      0.85),
    # Samsung TV
    ("samsungsmartv",    False, "tv",       0.95),
    ("samsung smartv",   False, "tv",       0.95),
    # Chromecast
    ("chromecast",       False, "streamer", 0.95),
    # VoIP
    ("voip",             False, "voip",     0.88),
    ("polycom",          False, "voip",     0.90),
    ("yealink",          False, "voip",     0.90),
    ("cisco-sip",        False, "voip",     0.88),
    # Printers
    ("printer",          False, "printer",  0.85),
    ("hp jetdirect",     False, "printer",  0.95),
    ("lexmark",          False, "printer",  0.90),
    ("brother",          False, "printer",  0.85),
    # Network gear
    ("openwrt",          False, "router",   0.90),
    ("routeros",         False, "router",   0.92),
    ("ddwrt",            False, "router",   0.88),
    ("dd-wrt",           False, "router",   0.88),
    ("ubiquiti",         False, "ap",       0.85),
    ("unifi",            False, "ap",       0.90),
    ("cisco",            False, "switch",   0.78),
    ("udhcp",            False, "router",   0.65),
    # Generic Linux / Raspberry Pi — low confidence
    ("dhcpcd",           False, "iot",      0.55),
    ("linux",            False, "iot",      0.50),
]

# Option 55 parameter-request-list → (os_hint, confidence).
# Longer / more specific sequences first.
_OPT55_SIGNATURES: list[tuple[tuple[int, ...], str, float]] = [
    # iOS / macOS
    ((1, 121, 3, 6, 15, 119, 252, 95, 44, 46), "apple",    0.92),
    ((1, 121, 3, 6, 15, 119, 252, 95, 44),     "apple",    0.90),
    ((1, 3, 6, 15, 119, 252, 95, 44, 46),      "apple",    0.88),
    ((1, 3, 6, 15, 119, 252, 95, 44),          "apple",    0.85),
    ((1, 3, 6, 15, 119, 252),                  "apple",    0.75),
    # Windows (various versions)
    ((1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252), "windows", 0.94),
    ((1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249),      "windows", 0.92),
    ((1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121),           "windows", 0.90),
    ((1, 3, 6, 15, 31, 33, 43, 44, 46, 47),                     "windows", 0.82),
    ((1, 3, 6, 15, 31, 33, 44, 46, 47),                         "windows", 0.78),
    # Android / Linux dhclient
    ((1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42),        "android", 0.88),
    ((1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121),            "android", 0.85),
    ((1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26),                 "android", 0.80),
    ((1, 28, 2, 3, 15, 6, 119, 12, 44, 47),                     "android", 0.75),
    ((1, 3, 6, 12, 15, 28, 42, 51, 54, 58, 59, 60),             "linux",   0.75),
    # Embedded / OpenWrt / udhcpc
    ((1, 3, 6, 12, 15, 51, 54, 58, 59),                         "embedded", 0.72),
    ((1, 3, 6, 28, 51, 58, 59),                                 "embedded", 0.65),
]

# OS hint → most likely device_type on DHCP
_OS_TO_TYPE: dict[str, str] = {
    "apple":    "phone",    # phone/tablet more likely than Mac on DHCP discover
    "windows":  "desktop",
    "android":  "phone",
    "linux":    "iot",      # most linux DHCP traffic on home nets = Pi/NAS/IoT
    "embedded": "iot",
}


def _vc_match(vendor_class: str) -> tuple[str, float] | None:
    vc = vendor_class.lower().strip()
    for fragment, exact, dtype, conf in _VENDOR_CLASS_RULES:
        if exact:
            if vc == fragment.lower():
                return (dtype, conf)
        else:
            if fragment.lower() in vc:
                return (dtype, conf)
    return None


def _opt55_match(opt55: list[int]) -> tuple[str, float] | None:
    t = tuple(opt55)
    best: tuple[str, float] | None = None
    for sig, os_hint, conf in _OPT55_SIGNATURES:
        min_len = min(len(sig), len(t))
        if min_len < 5:
            continue
        if t[:min_len] == sig[:min_len]:
            # Scale by completeness
            scale = min_len / max(len(sig), len(t))
            effective = round(conf * max(scale, 0.7), 2)
            if best is None or effective > best[1]:
                best = (_OS_TO_TYPE.get(os_hint, "unknown"), effective)
    return best


def classify_from_dhcp(
    vendor_class: str | None,
    opt55: list[int] | None,
) -> tuple[str, float]:
    """
    Return (device_type, confidence) from DHCP fingerprint data.
    device_type matches the taxonomy in frontend/src/deviceCategories.js.
    confidence 0.0 means no match.
    """
    if vendor_class:
        result = _vc_match(vendor_class)
        if result:
            return result
    if opt55:
        result = _opt55_match(opt55)
        if result:
            return result
    return ("unknown", 0.0)
