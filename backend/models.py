from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Device(Base):
    __tablename__ = "devices"
    mac_address          = Column(String, primary_key=True, index=True)
    ip_address           = Column(String, nullable=True)
    hostname             = Column(String, nullable=True)
    vendor               = Column(String, nullable=True)
    custom_name          = Column(String, nullable=True)
    device_type_override = Column(String, nullable=True)
    vendor_override      = Column(String, nullable=True)
    is_online            = Column(Boolean, default=True)
    first_seen           = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen            = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    scan_results         = Column(JSON, nullable=True)
    deep_scanned         = Column(Boolean, default=False)
    miss_count           = Column(Integer, default=0)

    # Phase 1: user metadata
    is_important         = Column(Boolean, default=False, nullable=False)
    notes                = Column(Text, nullable=True)
    tags                 = Column(String, nullable=True)
    location             = Column(String, nullable=True)

    # Phase 3: vulnerability scanning  ← THESE WERE MISSING
    vuln_last_scanned    = Column(DateTime(timezone=True), nullable=True)
    vuln_severity        = Column(String, nullable=True)

    # Phase 4: ARP-based internet block
    is_blocked           = Column(Boolean, server_default='false', nullable=False)

    # Phase 5: zones and suppression
    zone                 = Column(String, nullable=True)
    is_ignored           = Column(Boolean, server_default='false', nullable=False)

    ip_history   = relationship("IPHistory",    back_populates="device",
                                order_by="IPHistory.first_seen.desc()")
    events       = relationship("DeviceEvent",  back_populates="device",
                                order_by="DeviceEvent.created_at.desc()")
    vuln_reports = relationship("VulnReport",   back_populates="device",
                                order_by="VulnReport.scanned_at.desc()")
    
class IPHistory(Base):
    __tablename__ = "ip_history"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    mac_address = Column(String, ForeignKey("devices.mac_address", ondelete="CASCADE"),
                         nullable=False, index=True)
    ip_address  = Column(String, nullable=False)
    first_seen  = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen   = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    device      = relationship("Device", back_populates="ip_history")


class DeviceEvent(Base):
    """
    Timeline of significant events per device.
    type: 'joined' | 'online' | 'offline' | 'ip_change' | 'scan_complete'
          | 'renamed' | 'tagged' | 'marked_important' | 'port_change' | 'vuln_scan_complete'
    """
    __tablename__ = "device_events"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    mac_address = Column(String, ForeignKey("devices.mac_address", ondelete="CASCADE"),
                         nullable=False, index=True)
    type        = Column(String, nullable=False, index=True)
    detail      = Column(JSON, nullable=True)
    created_at  = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    device      = relationship("Device", back_populates="events")


class VulnReport(Base):
    """
    Stores the result of a Nuclei vulnerability scan for a device.
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'clean'
    findings: list of dicts with keys template_id, name, severity, cvss, cves, description, etc.
    """
    __tablename__ = "vuln_reports"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    mac_address  = Column(String, ForeignKey("devices.mac_address", ondelete="CASCADE"),
                          nullable=False, index=True)
    ip_address   = Column(String, nullable=True)
    scanned_at   = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    duration_s   = Column(Float,   nullable=True)
    severity     = Column(String,  nullable=False, default="clean")
    vuln_count   = Column(Integer, nullable=False, default=0)
    findings     = Column(JSON,    nullable=True)   # list of Nuclei finding dicts
    raw_output   = Column(Text,    nullable=True)   # raw Nuclei JSONL stdout
    scan_args    = Column(String,  nullable=True)   # template tags / severity used
    device       = relationship("Device", back_populates="vuln_reports")


class Alert(Base):
    """
    type: 'new_device' | 'device_offline' | 'device_online' | 'ip_change' | 'vuln_found'
    """
    __tablename__ = "alerts"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    type        = Column(String, nullable=False, index=True)
    mac_address = Column(String, nullable=True, index=True)
    ip_address  = Column(String, nullable=True)
    message     = Column(String, nullable=False)
    detail      = Column(JSON, nullable=True)
    seen        = Column(Boolean, default=False)
    created_at  = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Setting(Base):
    __tablename__ = "settings"
    key         = Column(String, primary_key=True, index=True)
    value       = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    updated_at  = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class FingerprintEntry(Base):
    __tablename__ = "fingerprints"

    id               = Column(Integer, primary_key=True, autoincrement=True)
    oui_prefix       = Column(String(6),  nullable=True,  index=True)
    hostname_pattern = Column(String,     nullable=True)
    open_ports       = Column(JSON,       nullable=True)
    device_type      = Column(String,     nullable=False,  index=True)
    vendor_name      = Column(String,     nullable=True)
    confidence_score = Column(Float,      nullable=False, default=1.0)
    hit_count        = Column(Integer,    nullable=False, default=1)
    source           = Column(String,     nullable=False, default='manual')
    source_mac       = Column(String,     nullable=True,  index=True)
    created_at       = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at       = Column(
        DateTime(timezone=True),
        default=lambda:  datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
