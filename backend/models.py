from sqlalchemy import Column, String, DateTime, JSON, Boolean
from sqlalchemy.orm import declarative_base
from datetime import datetime, timezone

Base = declarative_base()

class Device(Base):
    __tablename__ = "devices"

    mac_address  = Column(String, primary_key=True, index=True)
    ip_address   = Column(String, nullable=True)
    hostname     = Column(String, nullable=True)
    vendor       = Column(String, nullable=True)
    custom_name  = Column(String, nullable=True)
    is_online    = Column(Boolean, default=True)
    first_seen   = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen    = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    scan_results = Column(JSON, nullable=True)    # Populated by probe after nmap
    deep_scanned = Column(Boolean, default=False) # True once nmap scan complete
