# backend/email_analysis.py
"""
Enhanced Email Server Analysis Engine
Determines: email provider, DMARC reporting service, SEG, inline email security
"""

import dns.resolver
import re
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional

logger = logging.getLogger(__name__)

# ─── Provider Fingerprint Databases ────────────────────────────────────────────

MX_EMAIL_PROVIDERS = [
    # (pattern, provider_name, provider_type)
    # provider_type: "mailbox" | "seg" | "inline" | "hybrid"

    # ── Major Mailbox Providers ──
    (r"\.google\.com$|\.googlemail\.com$", "Google Workspace (Gmail)", "mailbox"),
    (r"\.protection\.outlook\.com$|\.mail\.protection\.outlook\.com$|\.olc\.protection\.outlook\.com$",
     "Microsoft 365 (Exchange Online)", "mailbox"),
    (r"\.outlook\.com$", "Microsoft 365 (Exchange Online)", "mailbox"),
    (r"\.zoho\.com$|\.zoho\.eu$|\.zoho\.in$", "Zoho Mail", "mailbox"),
    (r"\.protonmail\.ch$|\.proton\.ch$|\.protonmail\.com$", "Proton Mail", "mailbox"),
    (r"\.yahoodns\.net$", "Yahoo Mail / Verizon Media", "mailbox"),
    (r"\.emailsrvr\.com$", "Rackspace Email", "mailbox"),
    (r"\.secureserver\.net$", "GoDaddy Email", "mailbox"),
    (r"\.registrar-servers\.com$", "Namecheap Email", "mailbox"),
    (r"\.hover\.com$", "Hover Email", "mailbox"),
    (r"\.fastmail\.com$|\.messagingengine\.com$", "Fastmail", "mailbox"),
    (r"\.migadu\.com$", "Migadu", "mailbox"),
    (r"\.yandex\.(net|ru|com)$", "Yandex Mail", "mailbox"),
    (r"\.icloud\.com$|\.apple\.com$", "Apple iCloud Mail", "mailbox"),
    (r"\.mail\.ru$", "Mail.ru", "mailbox"),
    (r"\.gmx\.(net|com)$", "GMX Mail", "mailbox"),
    (r"\.kundenserver\.de$|\.1and1\.com$", "IONOS (1&1)", "mailbox"),
    (r"\.ovh\.(net|com)$", "OVH Mail", "mailbox"),
    (r"\.gandi\.net$", "Gandi Mail", "mailbox"),
    (r"\.dreamhost\.com$", "DreamHost Email", "mailbox"),
    (r"\.pair\.com$", "pair Networks", "mailbox"),
    (r"\.hostinger\.", "Hostinger Email", "mailbox"),
    (r"\.titan\.email$", "Titan Email", "mailbox"),
    (r"\.transip\.nl$", "TransIP Email", "mailbox"),

    # ── Traditional SEGs (MX-level) ──
    (r"\.pphosted\.com$|\.ppe-hosted\.com$|\.pphosted\.eu$", "Proofpoint", "seg"),
    (r"\.mimecast\.com$|\.mimecast-offshore\.com$", "Mimecast", "seg"),
    (r"\.barracudanetworks\.com$|\.ess\.barracuda\.com$|\.cuda-inc\.com$",
     "Barracuda Email Security Gateway", "seg"),
    (r"\.iphmx\.com$|\.fireeyecloud\.com$|\.ciscoemail\.com$", "Cisco Secure Email", "seg"),
    (r"\.messagelabs\.com$|\.symanteccloud\.com$|\.messagelabs\.net$",
     "Broadcom / Symantec Email Security.cloud", "seg"),
    (r"\.sophos\.com$|\.reflexion\.net$|\.sophos\.eu$", "Sophos Email Security", "seg"),
    (r"\.forcepoint\.com$|\.clearswift\.net$", "Forcepoint / Clearswift Email Security", "seg"),
    # Trend Micro uses regional TLDs (.eu, .co.jp) — match on name, not TLD
    (r"trendmicro\.(com|eu|co\.jp)", "Trend Micro Email Security", "seg"),
    (r"\.fortinet\.com$|\.fortimail\.com$", "Fortinet FortiMail", "seg"),
    (r"\.spamexperts\.com$|\.antispamcloud\.com$", "N-able / SpamExperts", "seg"),
    (r"\.mailguard\.com\.au$", "MailGuard", "seg"),
    (r"\.hornetsecurity\.com$|\.hornetdrive\.com$", "Hornetsecurity", "seg"),
    (r"\.retarus\.com$|\.retarus\.de$", "Retarus Email Security", "seg"),
    (r"\.zerospam\.(ca|io)$", "Zerospam (CIRA)", "seg"),
    (r"\.spamhero\.com$", "SpamHero", "seg"),
    (r"\.appriver\.com$", "AppRiver (Zix)", "seg"),
    (r"\.securence\.com$", "Securence", "seg"),
    (r"\.exclaimer\.net$", "Exclaimer Email Signatures", "seg"),
    (r"\.spamtitan\.com$|\.titanhq\.com$", "SpamTitan (TitanHQ)", "seg"),
    (r"\.libraesva\.com$", "Libraesva Email Security", "seg"),
    (r"\.mailchannels\.net$", "MailChannels", "seg"),
    (r"\.trustwave\.com$", "Trustwave SEG", "seg"),

    # ── Modern vendors that also offer MX-routing (gateway mode) ──
    # When they appear in MX they ARE routing mail, so classify as "seg".
    # API/inline detection for these is handled separately via SPF/DKIM.
    (r"\.mxrecord\.io$|\.mxrecord\.mx$", "Cloudflare Area 1 Email Security", "seg"),
    (r"\.darktrace\.com$", "Darktrace Email", "seg"),
    (r"\.avanan\.net$", "Check Point Harmony Email (Avanan)", "seg"),
    (r"\.perceptionpoint\.io$", "Perception Point", "seg"),
    (r"\.ironscales\.com$", "IRONSCALES", "seg"),
    (r"\.egress\.com$", "Egress Defend", "seg"),
    (r"\.greathorn\.com$", "GreatHorn", "seg"),
    (r"\.tessian\.com$", "Tessian (Proofpoint)", "seg"),
    (r"\.inky\.com$", "INKY Phish Fence", "seg"),
    (r"\.vade\.com$|vadesecure\.com$", "Vade (Hornetsecurity)", "seg"),
    (r"\.clearedin\.com$", "ClearedIn", "seg"),
]

SPF_SECURITY_INDICATORS = [
    # (pattern_in_spf, provider_name, provider_type)
    (r"spf\.protection\.outlook\.com", "Microsoft 365", "mailbox"),
    (r"_spf\.google\.com|googlemail\.com", "Google Workspace", "mailbox"),
    (r"spf\.avanan\.com|avanan\.net", "Check Point Harmony Email (Avanan)", "inline"),
    (r"spf\.proofpoint\.com|pphosted\.com", "Proofpoint", "seg"),
    (r"spf\.mimecast\.com|mimecast\.com", "Mimecast", "seg"),
    (r"spf\.barracuda\.com|barracudanetworks\.com", "Barracuda", "seg"),
    (r"messagelabs\.com|symanteccloud\.com", "Broadcom / Symantec", "seg"),
    (r"spf\.sophos\.com|sophos\.com", "Sophos", "seg"),
    (r"mktomail\.com|marketo\.com", "Marketo (Adobe)", "marketing"),
    (r"spf\.mandrillapp\.com|mailchimp\.com", "Mailchimp / Mandrill", "marketing"),
    (r"sendgrid\.net", "SendGrid (Twilio)", "marketing"),
    (r"amazonses\.com|ses\.amazonaws\.com", "Amazon SES", "marketing"),
    (r"salesforce\.com", "Salesforce", "marketing"),
    (r"hubspot\.com", "HubSpot", "marketing"),
    (r"zendesk\.com", "Zendesk", "service"),
    (r"freshdesk\.com", "Freshdesk", "service"),
    (r"ironscales\.com", "IRONSCALES", "inline"),
    (r"perceptionpoint\.io", "Perception Point", "inline"),
    (r"abnormalsecurity\.com", "Abnormal Security", "inline"),
    (r"tessian\.com", "Tessian", "inline"),
    (r"egress\.com", "Egress", "inline"),
    (r"cloudflare\.com|mxrecord\.io", "Cloudflare Area 1", "inline"),
    (r"darktrace\.com", "Darktrace", "inline"),
    (r"hornetsecurity\.com", "Hornetsecurity", "seg"),
    (r"retarus\.com", "Retarus", "seg"),
    (r"appriver\.com|zixcorp\.com", "Zix / AppRiver", "seg"),
    (r"trendmicro\.(com|eu|co\.jp)", "Trend Micro", "seg"),
    (r"fortinet\.com|fortimail\.com", "Fortinet", "seg"),
    (r"spamtitan\.com|titanhq\.com", "SpamTitan (TitanHQ)", "seg"),
    (r"libraesva\.com", "Libraesva Email Security", "seg"),
    (r"trustwave\.com", "Trustwave SEG", "seg"),
]

DMARC_REPORT_PROVIDERS = [
    # (pattern_in_rua_ruf, provider_name)
    (r"agari\.com", "Agari (Fortra)"),
    (r"dmarcian\.(com|eu)", "Dmarcian"),
    (r"valimail\.com", "Valimail"),
    (r"postmarkapp\.com", "Postmark (ActiveCampaign)"),
    (r"dmarcanalyzer\.com", "DMARC Analyzer (Mimecast)"),
    (r"easydmarc\.com", "EasyDMARC"),
    (r"cloudflare\.net", "Cloudflare"),
    (r"dmarc\.google\.com|google\.com.*dmarc", "Google (built-in DMARC reporting)"),
    (r"microsoft\.com", "Microsoft (built-in DMARC reporting)"),
    (r"proofpoint\.com", "Proofpoint"),
    (r"ondmarc\.com|redsift\.(com|io)", "OnDMARC (Red Sift)"),
    (r"dmarc\.service\.gov\.uk", "NCSC Mail Check (UK Gov)"),
    (r"250ok\.com|validity\.com", "Validity (250ok)"),
    (r"uriports\.com", "URIports"),
    (r"fraudmarc\.com", "Fraudmarc"),
    (r"powerdmarc\.com", "PowerDMARC"),
    (r"mimecast\.com", "Mimecast"),
    (r"barracuda\.com", "Barracuda"),
    (r"mailhardener\.com", "Mailhardener"),
    (r"report-uri\.com", "Report URI"),
    (r"dmarc\.postmarkapp\.com", "Postmark"),
    (r"app\.emailconsul\.com", "EmailConsul"),
    (r"socketlabs\.com", "SocketLabs"),
]

DKIM_SELECTORS_TO_CHECK = [
    # (selector, provider_name)
    ("google", "Google Workspace"),
    ("selector1", "Microsoft 365"),
    ("selector2", "Microsoft 365"),
    ("protonmail", "Proton Mail"),
    ("protonmail2", "Proton Mail"),
    ("protonmail3", "Proton Mail"),
    ("fm1", "Fastmail"),
    ("fm2", "Fastmail"),
    ("fm3", "Fastmail"),
    ("mimecast20190307", "Mimecast"),
    ("s1", "Generic / Multiple"),
    ("s2", "Generic / Multiple"),
    ("k1", "Mailchimp"),
    ("mandrill", "Mandrill (Mailchimp)"),
    ("smtpapi", "SendGrid"),
    ("avanan", "Check Point Harmony Email (Avanan)"),
    ("ironscales", "IRONSCALES"),
    ("pp1", "Proofpoint"),
    ("everlytickey1", "Everlytic"),
    ("hubspot", "HubSpot"),
    ("zendesk1", "Zendesk"),
    ("zixcorp", "Zix / AppRiver"),
]


# ─── Data Classes ──────────────────────────────────────────────────────────────

@dataclass
class MXRecord:
    priority: int
    exchange: str
    provider: Optional[str] = None
    provider_type: Optional[str] = None  # mailbox | seg | inline


@dataclass
class DMARCInfo:
    raw_record: str = ""
    policy: str = "none"  # none | quarantine | reject
    subdomain_policy: Optional[str] = None
    pct: int = 100
    rua: list = field(default_factory=list)
    ruf: list = field(default_factory=list)
    reporting_providers: list = field(default_factory=list)
    adkim: str = "r"  # r=relaxed, s=strict
    aspf: str = "r"


@dataclass
class SPFInfo:
    raw_record: str = ""
    includes: list = field(default_factory=list)
    detected_services: list = field(default_factory=list)
    all_mechanism: str = ""  # +all, ~all, -all, ?all


@dataclass
class DKIMResult:
    selector: str = ""
    provider: str = ""
    found: bool = False


@dataclass
class EmailAnalysisResult:
    domain: str = ""
    mx_records: list = field(default_factory=list)
    spf: Optional[SPFInfo] = None
    dmarc: Optional[DMARCInfo] = None
    dkim_checks: list = field(default_factory=list)

    # ── Conclusions ──
    email_provider: str = "Unknown"
    email_provider_confidence: str = "low"  # low | medium | high
    email_provider_detail: str = ""

    seg_provider: Optional[str] = None
    seg_detail: str = ""

    inline_security_provider: Optional[str] = None
    inline_security_detail: str = ""
    inline_security_evidence: list = field(default_factory=list)

    dmarc_provider: Optional[str] = None
    dmarc_enforcement: str = "none"  # none | monitoring | quarantine | enforced
    dmarc_detail: str = ""

    sending_services: list = field(default_factory=list)

    warnings: list = field(default_factory=list)
    summary: str = ""

    def to_dict(self):
        return asdict(self)


# ─── DNS Query Helpers ─────────────────────────────────────────────────────────

def safe_dns_query(qname: str, rdtype: str, timeout: float = 8.0):
    """Query DNS with error handling. Returns list of rdata strings."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(qname, rdtype)
        return [str(rdata) for rdata in answers]
    except dns.resolver.NXDOMAIN:
        logger.debug(f"NXDOMAIN for {qname} {rdtype}")
        return []
    except dns.resolver.NoAnswer:
        logger.debug(f"No answer for {qname} {rdtype}")
        return []
    except dns.resolver.NoNameservers:
        logger.debug(f"No nameservers for {qname} {rdtype}")
        return []
    except dns.exception.Timeout:
        logger.debug(f"Timeout querying {qname} {rdtype}")
        return []
    except Exception as e:
        logger.warning(f"DNS query failed for {qname} {rdtype}: {e}")
        return []


def match_provider(hostname: str, fingerprints: list):
    """Match a hostname against a list of (pattern, name, type) fingerprints."""
    hostname = hostname.lower().rstrip(".")
    for pattern, name, ptype in fingerprints:
        if re.search(pattern, hostname, re.IGNORECASE):
            return name, ptype
    return None, None


# ─── Core Analysis Functions ───────────────────────────────────────────────────

def analyse_mx(domain: str) -> list[MXRecord]:
    """Fetch and classify MX records."""
    raw = safe_dns_query(domain, "MX")
    records = []
    for entry in raw:
        parts = entry.split()
        if len(parts) >= 2:
            priority = int(parts[0])
            exchange = parts[1].rstrip(".")
            provider, ptype = match_provider(exchange, MX_EMAIL_PROVIDERS)
            records.append(MXRecord(
                priority=priority,
                exchange=exchange,
                provider=provider,
                provider_type=ptype,
            ))
    records.sort(key=lambda r: r.priority)
    return records


def analyse_spf(domain: str) -> Optional[SPFInfo]:
    """Fetch and parse SPF record."""
    txt_records = safe_dns_query(domain, "TXT")
    spf_record = None
    for rec in txt_records:
        cleaned = rec.strip('"').replace('" "', '')
        if cleaned.lower().startswith("v=spf1"):
            spf_record = cleaned
            break

    if not spf_record:
        return None

    info = SPFInfo(raw_record=spf_record)

    # Extract includes
    includes = re.findall(r'include:(\S+)', spf_record, re.IGNORECASE)
    info.includes = includes

    # Detect all mechanism
    all_match = re.search(r'([+\-~?]?)all\b', spf_record)
    if all_match:
        qualifier = all_match.group(1) or "+"
        info.all_mechanism = f"{qualifier}all"

    # Match against known services
    detected = []
    for pattern, name, stype in SPF_SECURITY_INDICATORS:
        if re.search(pattern, spf_record, re.IGNORECASE):
            detected.append({"name": name, "type": stype})
    info.detected_services = detected

    return info


def analyse_dmarc(domain: str) -> Optional[DMARCInfo]:
    """Fetch and parse DMARC record."""
    txt_records = safe_dns_query(f"_dmarc.{domain}", "TXT")
    dmarc_record = None
    for rec in txt_records:
        cleaned = rec.strip('"').replace('" "', '')
        if cleaned.lower().startswith("v=dmarc1"):
            dmarc_record = cleaned
            break

    if not dmarc_record:
        return None

    info = DMARCInfo(raw_record=dmarc_record)

    # Parse tags
    tags = {}
    for part in dmarc_record.split(";"):
        part = part.strip()
        if "=" in part:
            key, val = part.split("=", 1)
            tags[key.strip().lower()] = val.strip()

    info.policy = tags.get("p", "none").lower()
    info.subdomain_policy = tags.get("sp")
    info.pct = int(tags.get("pct", "100"))
    info.adkim = tags.get("adkim", "r")
    info.aspf = tags.get("aspf", "r")

    # Parse rua / ruf
    if "rua" in tags:
        info.rua = [addr.strip() for addr in tags["rua"].split(",")]
    if "ruf" in tags:
        info.ruf = [addr.strip() for addr in tags["ruf"].split(",")]

    # Identify DMARC reporting providers
    all_addrs = info.rua + info.ruf
    providers_found = set()
    for addr in all_addrs:
        for pattern, name in DMARC_REPORT_PROVIDERS:
            if re.search(pattern, addr, re.IGNORECASE):
                providers_found.add(name)
    info.reporting_providers = list(providers_found)

    return info


def check_dkim_selectors(domain: str) -> list[DKIMResult]:
    """Probe well-known DKIM selectors to confirm provider presence."""
    results = []
    for selector, provider in DKIM_SELECTORS_TO_CHECK:
        qname = f"{selector}._domainkey.{domain}"
        txt = safe_dns_query(qname, "TXT")
        cname = safe_dns_query(qname, "CNAME") if not txt else []
        found = bool(txt or cname)
        if found:
            results.append(DKIMResult(selector=selector, provider=provider, found=True))
    return results


# ─── Intelligence / Conclusion Engine ──────────────────────────────────────────

def determine_conclusions(result: EmailAnalysisResult):
    """
    Cross-reference all collected data to produce intelligent conclusions
    about email provider, SEG, inline security, and DMARC.
    """
    mx = result.mx_records
    spf = result.spf
    dmarc = result.dmarc
    dkim = result.dkim_checks

    # ── 1. Email Provider ──
    # Strategy: the lowest-priority MX with type "mailbox" is the real provider.
    # If MX records point to any gateway (SEG), look at SPF/DKIM for the real provider.
    mailbox_providers = [r for r in mx if r.provider_type == "mailbox"]
    seg_providers     = [r for r in mx if r.provider_type == "seg"]

    if mailbox_providers:
        primary = mailbox_providers[0]  # lowest priority = primary
        result.email_provider = primary.provider
        result.email_provider_confidence = "high"
        result.email_provider_detail = (
            f"MX record '{primary.exchange}' (priority {primary.priority}) "
            f"points directly to {primary.provider}."
        )
    elif seg_providers:
        # MX routes through a gateway — real mailbox provider is behind it.
        # Use SPF/DKIM to infer the underlying platform.
        real_provider = _infer_provider_from_spf_dkim(spf, dkim)
        if real_provider:
            result.email_provider = real_provider
            result.email_provider_confidence = "medium"
            result.email_provider_detail = (
                f"MX records route through {seg_providers[0].provider} (gateway). "
                f"SPF/DKIM analysis indicates the underlying mailbox provider "
                f"is {real_provider}."
            )
        else:
            result.email_provider = "Unknown (behind gateway)"
            result.email_provider_confidence = "low"
            result.email_provider_detail = (
                f"MX records route through {seg_providers[0].provider}. "
                f"Could not determine the underlying mailbox provider from "
                f"SPF or DKIM records."
            )
    else:
        # MX doesn't match anything known — try SPF/DKIM
        real_provider = _infer_provider_from_spf_dkim(spf, dkim)
        if real_provider:
            result.email_provider = real_provider
            result.email_provider_confidence = "medium"
            result.email_provider_detail = (
                f"MX records don't match any known provider fingerprint, "
                f"but SPF/DKIM analysis suggests {real_provider}."
            )
        elif mx:
            result.email_provider = f"Self-hosted / Unknown ({mx[0].exchange})"
            result.email_provider_confidence = "low"
            result.email_provider_detail = (
                f"MX points to '{mx[0].exchange}' which doesn't match known "
                f"providers. Likely self-hosted or a niche provider."
            )
        else:
            result.email_provider = "No MX records found"
            result.email_provider_confidence = "low"
            result.email_provider_detail = "No MX records found for this domain."
            result.warnings.append("No MX records found — domain may not receive email.")

    # ── 2. Gateway / SEG Detection ──
    if seg_providers:
        seg_names = list({r.provider for r in seg_providers})
        result.seg_provider = ", ".join(seg_names)
        result.seg_detail = (
            f"Email gateway detected — mail routes through {result.seg_provider} "
            f"before reaching the mailbox. "
            f"MX: {', '.join(r.exchange for r in seg_providers)}."
        )
    else:
        result.seg_detail = "No email gateway (SEG) detected at the MX level."

    # ── 3. API / Inline Email Security Platform ──
    # Detected via SPF includes or DKIM selectors — NOT MX routing.
    # If a vendor is already the identified MX gateway, it is excluded here
    # to avoid double-counting (e.g. Avanan routing via MX is the gateway, not
    # a separate inline layer on top of something else).
    inline_evidence = []
    gateway_names = {r.provider for r in seg_providers}

    # Check SPF includes for known API/inline security vendors
    if spf:
        for svc in spf.detected_services:
            if svc["type"] == "inline" and svc["name"] not in gateway_names:
                inline_evidence.append(f"SPF include → {svc['name']}")

    # Check DKIM selectors for known inline/API security platforms
    inline_dkim_vendors = {"Check Point Harmony Email (Avanan)", "IRONSCALES"}
    for dk in dkim:
        if dk.found and dk.provider in inline_dkim_vendors and dk.provider not in gateway_names:
            inline_evidence.append(f"DKIM selector '{dk.selector}' → {dk.provider}")

    if inline_evidence:
        providers = set()
        for ev in inline_evidence:
            for pattern, name, ptype in SPF_SECURITY_INDICATORS:
                if ptype == "inline" and name in ev:
                    providers.add(name)
            for pattern, name, ptype in MX_EMAIL_PROVIDERS:
                if name in ev:
                    providers.add(name)
        if not providers:
            providers = {"Unknown security platform"}

        result.inline_security_provider = ", ".join(sorted(providers))
        result.inline_security_evidence = inline_evidence
        result.inline_security_detail = (
            f"API-based email security platform detected via SPF/DKIM: "
            f"{result.inline_security_provider}. "
            f"This vendor integrates with the mail platform directly rather than "
            f"routing mail through a separate gateway. "
            f"Evidence: {'; '.join(inline_evidence)}."
        )
    else:
        result.inline_security_detail = (
            "No API-based email security platform detected via SPF/DKIM. "
            "Note: products such as Abnormal Security, Material Security, and Microsoft "
            "Defender for Office 365 (add-on) connect via mail platform API and leave "
            "no DNS footprint — they cannot be detected this way."
        )

    # ── 4. DMARC Analysis ──
    if dmarc:
        if dmarc.policy == "reject":
            result.dmarc_enforcement = "enforced"
        elif dmarc.policy == "quarantine":
            result.dmarc_enforcement = "quarantine"
        elif dmarc.rua or dmarc.ruf:
            result.dmarc_enforcement = "monitoring"
        else:
            result.dmarc_enforcement = "none"

        if dmarc.reporting_providers:
            result.dmarc_provider = ", ".join(dmarc.reporting_providers)
            result.dmarc_detail = (
                f"DMARC policy: p={dmarc.policy} (pct={dmarc.pct}%). "
                f"DMARC reporting/monitoring handled by: {result.dmarc_provider}."
            )
        else:
            result.dmarc_detail = (
                f"DMARC policy: p={dmarc.policy} (pct={dmarc.pct}%). "
                f"Reporting addresses configured but no known DMARC vendor identified."
            )
    else:
        result.dmarc_enforcement = "none"
        result.dmarc_detail = "No DMARC record found."
        result.warnings.append(
            "No DMARC record — domain is vulnerable to email spoofing."
        )

    # ── 5. Sending Services (marketing, ticketing, etc.) ──
    if spf:
        for svc in spf.detected_services:
            if svc["type"] in ("marketing", "service"):
                result.sending_services.append(svc)

    # ── 6. Summary ──
    result.summary = _build_summary(result)


def _infer_provider_from_spf_dkim(spf, dkim):
    """Attempt to determine the mailbox provider from SPF and DKIM."""
    candidates = {}

    if spf:
        for svc in spf.detected_services:
            if svc["type"] == "mailbox":
                name = svc["name"]
                candidates[name] = candidates.get(name, 0) + 2

    if dkim:
        for dk in dkim:
            if dk.found and dk.provider in (
                "Google Workspace", "Microsoft 365", "Proton Mail",
                "Fastmail", "Zoho Mail"
            ):
                candidates[dk.provider] = candidates.get(dk.provider, 0) + 3

    if candidates:
        return max(candidates, key=candidates.get)
    return None


def _build_summary(result: EmailAnalysisResult) -> str:
    """Generate a human-readable summary paragraph."""
    parts = []

    parts.append(f"📧 **{result.domain}** uses **{result.email_provider}** "
                 f"as their email provider "
                 f"(confidence: {result.email_provider_confidence}).")

    if result.seg_provider:
        parts.append(f"🛡️ Mail routes through an email gateway: "
                     f"**{result.seg_provider}**.")

    if result.inline_security_provider:
        parts.append(f"🔒 API-based security platform detected via SPF/DKIM: "
                     f"**{result.inline_security_provider}**.")
    elif not result.seg_provider:
        parts.append("⚠️ No email gateway or API security platform detected.")

    if result.dmarc_provider:
        parts.append(f"📊 DMARC reporting managed by **{result.dmarc_provider}** "
                     f"(enforcement: {result.dmarc_enforcement}).")
    elif result.dmarc:
        parts.append(f"📊 DMARC is configured (p={result.dmarc.policy}) "
                     f"but no known reporting vendor identified.")
    else:
        parts.append("❌ No DMARC record found — spoofing risk.")

    if result.sending_services:
        svc_names = [s["name"] for s in result.sending_services]
        parts.append(f"📬 Third-party sending services: {', '.join(svc_names)}.")

    return " ".join(parts)


# ─── Main Entry Point ─────────────────────────────────────────────────────────

def run_email_analysis(domain: str) -> EmailAnalysisResult:
    """
    Run the full email server analysis for a domain.
    Returns a comprehensive EmailAnalysisResult.
    """
    domain = domain.strip().lower()
    # Strip protocol and path if someone pastes a URL
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0]
    domain = domain.split('@')[-1]  # handle user@domain

    result = EmailAnalysisResult(domain=domain)

    logger.info(f"Starting email analysis for {domain}")

    # Gather all DNS data
    mx_objects = analyse_mx(domain)
    result.mx_records = [asdict(r) for r in mx_objects]

    spf = analyse_spf(domain)
    dmarc = analyse_dmarc(domain)
    dkim = check_dkim_selectors(domain)

    result.spf = asdict(spf) if spf else None
    result.dmarc = asdict(dmarc) if dmarc else None
    result.dkim_checks = [asdict(d) for d in dkim if d.found]

    # Re-create typed objects for the conclusion engine
    result_typed = EmailAnalysisResult(domain=domain)
    result_typed.mx_records = mx_objects
    result_typed.spf = spf
    result_typed.dmarc = dmarc
    result_typed.dkim_checks = dkim

    # Run the intelligence engine
    determine_conclusions(result_typed)

    # Copy conclusions back to the serialisable result
    result.email_provider = result_typed.email_provider
    result.email_provider_confidence = result_typed.email_provider_confidence
    result.email_provider_detail = result_typed.email_provider_detail
    result.seg_provider = result_typed.seg_provider
    result.seg_detail = result_typed.seg_detail
    result.inline_security_provider = result_typed.inline_security_provider
    result.inline_security_detail = result_typed.inline_security_detail
    result.inline_security_evidence = result_typed.inline_security_evidence
    result.dmarc_provider = result_typed.dmarc_provider
    result.dmarc_enforcement = result_typed.dmarc_enforcement
    result.dmarc_detail = result_typed.dmarc_detail
    result.sending_services = result_typed.sending_services
    result.warnings = result_typed.warnings
    result.summary = result_typed.summary

    logger.info(f"Email analysis complete for {domain}: {result.email_provider}")

    return result