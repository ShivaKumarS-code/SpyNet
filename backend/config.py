"""
Configuration management for SpyNet backend
"""
import os
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # Database Configuration
    database_url: str = "postgresql://localhost:5432/spynet"
    neon_database_url: Optional[str] = None
    
    # API Configuration
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    debug: bool = True
    
    # Security Configuration
    secret_key: str = "your-secret-key-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    
    # Packet Capture Configuration
    capture_interface: str = "eth0"
    packet_buffer_size: int = 1000
    capture_timeout: int = 1
    
    # Detection Thresholds
    port_scan_threshold: int = 10
    ddos_threshold: int = 100
    anomaly_threshold: float = 0.1
    
    # Logging Configuration
    log_level: str = "INFO"
    log_file: str = "spynet.log"
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()