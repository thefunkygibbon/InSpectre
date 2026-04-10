from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Device(Base):
    __tablename__ = "devices"

    mac_address = Column(String, primary_key=True, index=True)
    ip_address  = Column(String, nullable=True)
    hostname    = Column(String, nullable=True)
    vendor      = Column(String, nullable=True)
    custom_name = Column(String, nullable=True)
    is_online   = Column(Boolean, default=True)
    first_seen  = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen   = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    scan_results = Column(JSON,    nullable=True)
    deep_scanned = Column(Boolean, default=False)
    miss_count   = Column(Integer, default=0)


class IPHistory(Base):
    """
    One row per (mac_address, ip_address) pair.
    first_seen = when this device was first seen at this IP.
    last_seen  = most recent sweep that confirmed the combination.
    """
    __tablename__ = "ip_history"
    __table_args__ = (UniqueConstraint("mac_address", "ip_address", name="uq_ip_history_mac_ip"),)

    id          = Column(Integer, primary_key=True, autoincrement=True)
    mac_address = Column(String, nullable=False, index=True)
    ip_address  = Column(String, nullable=False)
    first_seen  = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen   = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Setting(Base):
    """
    Key/value store for runtime-configurable probe settings.
    The probe polls this table every scan cycle so changes take
    effect without a container restart.
    """
    __tablename__ = "settings"

    key         = Column(String, primary_key=True, index=True)
    value       = Column(Text,   nullable=False)
    description = Column(Text,   nullable=True)
    updated_at  = Column(
        DateTime(timezone=True),
        default=lambda:   datetime.now(timezone.utc),
        onupdate=lambda:  datetime.now(timezone.utc),
    )
