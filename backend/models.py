"""
SQLAlchemy database models for SpyNet
"""
from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy import (
    Column, Integer, String, DateTime, Text, Float, Boolean, 
    ForeignKey, Index, JSON, BigInteger, create_engine
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.pool import QueuePool
from config import settings

Base = declarative_base()


class PacketInfo(Base):
    """Model for storing packet information"""
    __tablename__ = 'packets'
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    src_ip = Column(String(45), nullable=False, index=True)  # IPv6 support
    dst_ip = Column(String(45), nullable=False, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=False, index=True)
    size = Column(Integer, nullable=False)
    tcp_flags = Column(String(20), nullable=True)
    payload_size = Column(Integer, default=0)
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_packet_timestamp_src', 'timestamp', 'src_ip'),
        Index('idx_packet_timestamp_dst', 'timestamp', 'dst_ip'),
        Index('idx_packet_src_dst', 'src_ip', 'dst_ip'),
        Index('idx_packet_protocol_time', 'protocol', 'timestamp'),
    )
    
    def __repr__(self):
        return f"<PacketInfo(id={self.id}, src={self.src_ip}:{self.src_port}, dst={self.dst_ip}:{self.dst_port})>"


class Alert(Base):
    """Model for storing security alerts"""
    __tablename__ = 'alerts'
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    alert_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)  # Low, Medium, High, Critical
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=True)
    description = Column(Text, nullable=False)
    details = Column(JSON, nullable=True)  # Additional alert details as JSON
    resolved = Column(Boolean, default=False, index=True)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(100), nullable=True)
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_alert_severity_time', 'severity', 'timestamp'),
        Index('idx_alert_type_time', 'alert_type', 'timestamp'),
        Index('idx_alert_source_time', 'source_ip', 'timestamp'),
        Index('idx_alert_unresolved', 'resolved', 'timestamp'),
    )
    
    def __repr__(self):
        return f"<Alert(id={self.id}, type={self.alert_type}, severity={self.severity}, source={self.source_ip})>"


class Connection(Base):
    """Model for tracking network connections and flows"""
    __tablename__ = 'connections'
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    src_ip = Column(String(45), nullable=False, index=True)
    dst_ip = Column(String(45), nullable=False, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=False)
    
    # Connection tracking
    first_seen = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    last_seen = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    packet_count = Column(BigInteger, default=1)
    bytes_sent = Column(BigInteger, default=0)
    bytes_received = Column(BigInteger, default=0)
    
    # Connection state
    state = Column(String(20), default='ACTIVE')  # ACTIVE, CLOSED, TIMEOUT
    tcp_flags_seen = Column(String(50), nullable=True)
    
    # Flow statistics
    avg_packet_size = Column(Float, default=0.0)
    connection_duration = Column(Float, default=0.0)  # seconds
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_connection_src_dst', 'src_ip', 'dst_ip'),
        Index('idx_connection_time_range', 'first_seen', 'last_seen'),
        Index('idx_connection_state_time', 'state', 'last_seen'),
        Index('idx_connection_protocol_time', 'protocol', 'first_seen'),
    )
    
    def __repr__(self):
        return f"<Connection(id={self.id}, {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port})>"


class Config(Base):
    """Model for storing system configuration settings"""
    __tablename__ = 'config'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(100), nullable=False, unique=True, index=True)
    value = Column(JSON, nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(50), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<Config(key={self.key}, category={self.category})>"


# Database connection and session management
class DatabaseManager:
    """Database connection and session management"""
    
    def __init__(self, database_url: str = None):
        self.database_url = database_url or settings.neon_database_url or settings.database_url
        self.engine = None
        self.SessionLocal = None
        self._setup_engine()
    
    def _setup_engine(self):
        """Setup SQLAlchemy engine with connection pooling"""
        self.engine = create_engine(
            self.database_url,
            poolclass=QueuePool,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
            pool_recycle=3600,  # Recycle connections after 1 hour
            echo=settings.debug  # Log SQL queries in debug mode
        )
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
    
    def create_tables(self):
        """Create all database tables"""
        Base.metadata.create_all(bind=self.engine)
    
    def drop_tables(self):
        """Drop all database tables (use with caution)"""
        Base.metadata.drop_all(bind=self.engine)
    
    def get_session(self):
        """Get a database session"""
        return self.SessionLocal()
    
    def close(self):
        """Close database connections"""
        if self.engine:
            self.engine.dispose()


# Global database manager instance
db_manager = DatabaseManager()


def get_db():
    """Dependency to get database session"""
    db = db_manager.get_session()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    """Create all database tables"""
    db_manager.create_tables()


def init_default_config():
    """Initialize default configuration settings"""
    db = db_manager.get_session()
    try:
        # Check if config already exists
        existing_config = db.query(Config).first()
        if existing_config:
            return
        
        # Default configuration settings
        default_configs = [
            {
                'key': 'detection.port_scan_threshold',
                'value': settings.port_scan_threshold,
                'description': 'Number of ports scanned before triggering alert',
                'category': 'detection'
            },
            {
                'key': 'detection.ddos_threshold',
                'value': settings.ddos_threshold,
                'description': 'Connection rate threshold for DDoS detection',
                'category': 'detection'
            },
            {
                'key': 'detection.anomaly_threshold',
                'value': settings.anomaly_threshold,
                'description': 'Anomaly detection sensitivity threshold',
                'category': 'detection'
            },
            {
                'key': 'capture.interface',
                'value': settings.capture_interface,
                'description': 'Network interface for packet capture',
                'category': 'capture'
            },
            {
                'key': 'capture.buffer_size',
                'value': settings.packet_buffer_size,
                'description': 'Packet buffer size for capture queue',
                'category': 'capture'
            },
            {
                'key': 'alerts.email_notifications',
                'value': True,
                'description': 'Enable email notifications for alerts',
                'category': 'alerts'
            },
            {
                'key': 'alerts.critical_only',
                'value': False,
                'description': 'Send notifications only for critical alerts',
                'category': 'alerts'
            }
        ]
        
        for config_data in default_configs:
            config = Config(**config_data)
            db.add(config)
        
        db.commit()
        print("Default configuration initialized successfully")
        
    except Exception as e:
        db.rollback()
        print(f"Error initializing default configuration: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    # Create tables and initialize default config when run directly
    create_tables()
    init_default_config()
    print("Database setup completed successfully")