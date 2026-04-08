from sqlalchemy import Column, String, DateTime, JSON, Boolean
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class Device(Base):
    __tablename__ = "devices"

    mac_address = Column(String, primary_key=True, index=True)
    ip_address = Column(String)
    hostname = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    custom_name = Column(String, nullable=True) # For your manual renaming
    is_online = Column(Boolean, default=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    scan_results = Column(JSON, nullable=True) # Stores Nmap/Vuln data
