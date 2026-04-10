from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Device(Base):
    __tablename__ = "devices"
    mac_address          = Column(String, primary_key=True, index=True)
    ip_address           = Column(String, nullable=True)
    hostname             = Column(String, nullable=True)
    vendor               = Column(String, nullable=True)
    custom_name          = Column(String, nullable=True)
    # User-correctable overrides — if set, frontend uses these instead of auto-detected values
    device_type_override = Column(String, nullable=True)   # e.g. 'tv', 'router', 'phone'
    vendor_override      = Column(String, nullable=True)   # free-text vendor label
    is_online            = Column(Boolean, default=True)
    first_seen           = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen            = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    scan_results         = Column(JSON, nullable=True)
    deep_scanned         = Column(Boolean, default=False)
    miss_count           = Column(Integer, default=0)
    ip_history           = relationship("IPHistory", back_populates="device", order_by="IPHistory.first_seen.desc()")


class IPHistory(Base):
    __tablename__ = "ip_history"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    mac_address = Column(String, ForeignKey("devices.mac_address", ondelete="CASCADE"), nullable=False, index=True)
    ip_address  = Column(String, nullable=False)
    first_seen  = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen   = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    device      = relationship("Device", back_populates="ip_history")


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
