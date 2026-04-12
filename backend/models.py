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
    tags                 = Column(String, nullable=True)   # comma-separated
    location             = Column(String, nullable=True)   # free-text room/zone

    ip_history           = relationship("IPHistory", back_populates="device",
                                         order_by="IPHistory.first_seen.desc()")
    events               = relationship("DeviceEvent", back_populates="device",
                                         order_by="DeviceEvent.created_at.desc()")


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
          | 'renamed' | 'tagged' | 'marked_important' | 'port_change'
    """
    __tablename__ = "device_events"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    mac_address = Column(String, ForeignKey("devices.mac_address", ondelete="CASCADE"),
                         nullable=False, index=True)
    type        = Column(String, nullable=False, index=True)
    detail      = Column(JSON, nullable=True)   # e.g. {"old_ip": "x", "new_ip": "y"}
    created_at  = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    device      = relationship("Device", back_populates="events")


class Alert(Base):
    """
    type: 'new_device' | 'device_offline' | 'device_online' | 'ip_change'
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
