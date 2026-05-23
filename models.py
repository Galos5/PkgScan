from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

class ScanModel(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    endpoint_id = Column(String, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    packages = relationship("ScanPackageModel", back_populates="scan", cascade="all, delete-orphan")


class ScanPackageModel(Base):
    __tablename__ = "scan_packages"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    name = Column(String, index=True)
    version = Column(String)
    ecosystem = Column(String)

    scan = relationship("ScanModel", back_populates="packages")


class VulnerabilityCacheModel(Base):
    __tablename__ = "vulnerability_cache"

    id = Column(Integer, primary_key=True, index=True)
    package_key = Column(String, unique=True, index=True, nullable=False)
    status = Column(String, nullable=False)
    details = Column(String, nullable=True)
    last_scanned_at = Column(DateTime, default=datetime.utcnow)