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
    # User-correctable overrides — if set, frontend uses these instead of auto-detected values
    device_type_override = Column(String, nullable=True)   # e.g. 'tv', 'router', 'phone'
    vendor_override      = Column(String, nullable=True)   # free-text vendor label
    is_online            = Column(Boolean, default=True)
    first_seen           = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen            = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    scan_results         = Column(JSON, nullable=True)
    deep_scanned         = Column(Boolean, default=False)
    miss_count           = Column(Integer, default=0)
    ip_history           = relationship("IPHistory", back_populates="device",
                                         order_by="IPHistory.first_seen.desc()")


class IPHistory(Base):
    __tablename__ = "ip_history"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    mac_address = Column(String, ForeignKey("devices.mac_address", ondelete="CASCADE"),
                         nullable=False, index=True)
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


class FingerprintEntry(Base):
    """
    Community fingerprint database — each row is a pattern that maps a set of
    observable device signals to a confirmed vendor + device type.

    This table is built up locally whenever a user manually corrects a device's
    identity in the UI.  In a future release the rows can be anonymously
    exported / contributed to a shared cloud database so that all InSpectre
    users benefit from each other's corrections.

    Signal columns (all optional — any subset may be populated):
      oui_prefix      — first 6 hex chars of MAC (e.g. 'b827eb')
      hostname_pattern— partial hostname string / regex fragment
      open_ports      — JSON list of port numbers observed

    Identity columns:
      device_type     — canonical category key: 'tv', 'router', 'phone', etc.
      vendor_name     — human-readable vendor string: 'Samsung', 'Ubiquiti', …

    Confidence tracking:
      confidence_score— float 0–1, starts at 1.0 for manual corrections;
                        in future can be updated by majority-vote from uploads
      hit_count       — number of times this pattern was matched locally
      source          — 'manual' | 'auto' | 'community'
      created_at / updated_at
    """
    __tablename__ = "fingerprints"

    id               = Column(Integer, primary_key=True, autoincrement=True)

    # ── signal fields ────────────────────────────────────────────────────────
    oui_prefix       = Column(String(6),  nullable=True,  index=True)
    hostname_pattern = Column(String,     nullable=True)
    open_ports       = Column(JSON,       nullable=True)   # e.g. [80, 443, 554]

    # ── identity fields ──────────────────────────────────────────────────────
    device_type      = Column(String,     nullable=False,  index=True)
    vendor_name      = Column(String,     nullable=True)

    # ── confidence & provenance ───────────────────────────────────────────────
    confidence_score = Column(Float,      nullable=False, default=1.0)
    hit_count        = Column(Integer,    nullable=False, default=1)
    source           = Column(String,     nullable=False, default='manual')
    # mac of the device that triggered this entry — kept for local de-dup;
    # would be stripped before any community upload.
    source_mac       = Column(String,     nullable=True,  index=True)

    created_at       = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at       = Column(
        DateTime(timezone=True),
        default=lambda:  datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
