"""
SpyNet Configuration Manager

This module provides comprehensive configuration management for SpyNet,
including detection thresholds, alert settings, interface configuration,
and custom rule management.
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime
import yaml
from enum import Enum

from config import settings


class ConfigFormat(Enum):
    """Supported configuration file formats"""
    JSON = "json"
    YAML = "yaml"
    YML = "yml"


@dataclass
class DetectionThresholds:
    """Detection threshold configuration"""
    port_scan_threshold: int = 10
    ddos_threshold: int = 100
    anomaly_contamination: float = 0.1
    scan_time_window: int = 300
    ddos_time_window: int = 60
    connection_timeout: int = 300
    brute_force_threshold: int = 5
    brute_force_time_window: int = 300


@dataclass
class AlertConfiguration:
    """Alert system configuration"""
    severity_levels: Dict[str, int] = field(default_factory=lambda: {
        "Low": 1,
        "Medium": 2, 
        "High": 3,
        "Critical": 4
    })
    enable_email: bool = True
    enable_syslog: bool = False
    enable_webhook: bool = False
    critical_only: bool = False
    dedup_window_minutes: int = 10
    max_alerts_per_hour: int = 100
    alert_retention_days: int = 30
    
    # Email settings
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    alert_emails: List[str] = field(default_factory=list)
    
    # Webhook settings
    webhook_url: str = ""
    webhook_timeout: int = 30
    
    # Syslog settings
    syslog_server: str = "localhost"
    syslog_port: int = 514
    syslog_facility: str = "local0"


@dataclass
class InterfaceConfiguration:
    """Network interface configuration"""
    capture_interface: str = "auto"
    packet_buffer_size: int = 1000
    capture_timeout: int = 1
    promiscuous_mode: bool = True
    packet_filters: List[str] = field(default_factory=list)
    excluded_ips: List[str] = field(default_factory=list)
    included_ips: List[str] = field(default_factory=list)
    excluded_ports: List[int] = field(default_factory=list)
    included_ports: List[int] = field(default_factory=list)
    max_packet_size: int = 65535


@dataclass
class CustomRule:
    """Custom threat detection rule"""
    name: str
    description: str
    pattern: str
    pattern_type: str  # "regex", "string", "bytes"
    severity: str = "Medium"
    enabled: bool = True
    protocol: str = "any"  # "tcp", "udp", "icmp", "any"
    ports: List[int] = field(default_factory=list)
    created_date: str = field(default_factory=lambda: datetime.now().isoformat())
    last_modified: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class RuleManagement:
    """Rule management configuration"""
    custom_rules: List[CustomRule] = field(default_factory=list)
    rule_categories: Dict[str, List[str]] = field(default_factory=lambda: {
        "malware": ["trojan", "virus", "backdoor", "botnet"],
        "web_attacks": ["sql_injection", "xss", "command_injection"],
        "network_attacks": ["port_scan", "ddos", "brute_force"],
        "data_exfiltration": ["large_upload", "suspicious_transfer"]
    })
    enable_custom_rules: bool = True
    rule_update_interval: int = 3600  # seconds


@dataclass
class SystemConfiguration:
    """System-wide configuration"""
    log_level: str = "INFO"
    log_file: str = "spynet.log"
    log_rotation_size: int = 10485760  # 10MB
    log_retention_days: int = 30
    debug: bool = False
    
    # Performance settings
    max_connections_tracked: int = 10000
    stats_update_interval: int = 30
    anomaly_model_retrain_hours: int = 24
    cleanup_interval_minutes: int = 60
    
    # Database settings
    database_cleanup_days: int = 30
    connection_pool_size: int = 20
    query_timeout: int = 30


@dataclass
class SpyNetConfiguration:
    """Complete SpyNet configuration"""
    detection: DetectionThresholds = field(default_factory=DetectionThresholds)
    alerts: AlertConfiguration = field(default_factory=AlertConfiguration)
    interface: InterfaceConfiguration = field(default_factory=InterfaceConfiguration)
    rules: RuleManagement = field(default_factory=RuleManagement)
    system: SystemConfiguration = field(default_factory=SystemConfiguration)
    
    # Metadata
    config_version: str = "1.0"
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())


class ConfigurationManager:
    """
    Configuration manager for SpyNet system.
    
    Provides loading, saving, validation, and runtime modification of configuration
    settings including detection thresholds, alert preferences, interface settings,
    and custom rules.
    """
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_file: Path to configuration file (optional)
        """
        self.config_file = config_file or "spynet_config.json"
        self.config_dir = Path("config")
        self.config_dir.mkdir(exist_ok=True)
        
        # Full path to config file
        self.config_path = self.config_dir / self.config_file
        
        # Current configuration
        self.config: SpyNetConfiguration = SpyNetConfiguration()
        
        # Configuration change callbacks
        self.change_callbacks: List[callable] = []
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        # Load configuration
        self.load_configuration()
    
    def load_configuration(self) -> bool:
        """
        Load configuration from file.
        
        Returns:
            True if loaded successfully, False otherwise
        """
        try:
            if not self.config_path.exists():
                self.logger.info(f"Configuration file {self.config_path} not found, creating default")
                return self.save_configuration()
            
            # Determine file format
            file_format = self._detect_file_format(self.config_path)
            
            with open(self.config_path, 'r') as f:
                if file_format == ConfigFormat.JSON:
                    config_data = json.load(f)
                elif file_format in [ConfigFormat.YAML, ConfigFormat.YML]:
                    config_data = yaml.safe_load(f)
                else:
                    raise ValueError(f"Unsupported configuration format: {file_format}")
            
            # Convert to configuration object
            self.config = self._dict_to_config(config_data)
            
            # Validate configuration
            if not self._validate_configuration():
                self.logger.warning("Configuration validation failed, using defaults")
                self.config = SpyNetConfiguration()
                return False
            
            self.logger.info(f"Configuration loaded from {self.config_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}")
            self.config = SpyNetConfiguration()
            return False
    
    def save_configuration(self) -> bool:
        """
        Save current configuration to file.
        
        Returns:
            True if saved successfully, False otherwise
        """
        try:
            # Update last modified timestamp
            self.config.last_updated = datetime.now().isoformat()
            
            # Convert to dictionary
            config_data = self._config_to_dict(self.config)
            
            # Determine file format
            file_format = self._detect_file_format(self.config_path)
            
            # Create backup of existing config
            if self.config_path.exists():
                backup_path = self.config_path.with_suffix(f".backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}")
                # Remove existing backup if it exists
                if backup_path.exists():
                    backup_path.unlink()
                self.config_path.rename(backup_path)
                self.logger.info(f"Created configuration backup: {backup_path}")
            
            # Save configuration
            with open(self.config_path, 'w') as f:
                if file_format == ConfigFormat.JSON:
                    json.dump(config_data, f, indent=2, default=str)
                elif file_format in [ConfigFormat.YAML, ConfigFormat.YML]:
                    yaml.dump(config_data, f, default_flow_style=False, indent=2)
            
            self.logger.info(f"Configuration saved to {self.config_path}")
            
            # Notify callbacks of configuration change
            self._notify_change_callbacks()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving configuration: {e}")
            return False
    
    def _detect_file_format(self, file_path: Path) -> ConfigFormat:
        """Detect configuration file format from extension"""
        suffix = file_path.suffix.lower()
        if suffix == ".json":
            return ConfigFormat.JSON
        elif suffix in [".yaml", ".yml"]:
            return ConfigFormat.YAML
        else:
            # Default to JSON
            return ConfigFormat.JSON
    
    def _dict_to_config(self, config_data: Dict[str, Any]) -> SpyNetConfiguration:
        """Convert dictionary to configuration object"""
        try:
            # Handle nested dictionaries
            detection_data = config_data.get("detection", {})
            alerts_data = config_data.get("alerts", {})
            interface_data = config_data.get("interface", {})
            rules_data = config_data.get("rules", {})
            system_data = config_data.get("system", {})
            
            # Convert custom rules
            custom_rules = []
            for rule_data in rules_data.get("custom_rules", []):
                custom_rules.append(CustomRule(**rule_data))
            rules_data["custom_rules"] = custom_rules
            
            config = SpyNetConfiguration(
                detection=DetectionThresholds(**detection_data),
                alerts=AlertConfiguration(**alerts_data),
                interface=InterfaceConfiguration(**interface_data),
                rules=RuleManagement(**rules_data),
                system=SystemConfiguration(**system_data),
                config_version=config_data.get("config_version", "1.0"),
                last_updated=config_data.get("last_updated", datetime.now().isoformat())
            )
            
            return config
            
        except Exception as e:
            self.logger.error(f"Error converting dictionary to configuration: {e}")
            return SpyNetConfiguration()
    
    def _config_to_dict(self, config: SpyNetConfiguration) -> Dict[str, Any]:
        """Convert configuration object to dictionary"""
        try:
            config_dict = asdict(config)
            
            # Convert custom rules to dictionaries
            if "rules" in config_dict and "custom_rules" in config_dict["rules"]:
                custom_rules = []
                for rule in config_dict["rules"]["custom_rules"]:
                    if isinstance(rule, CustomRule):
                        custom_rules.append(asdict(rule))
                    else:
                        custom_rules.append(rule)
                config_dict["rules"]["custom_rules"] = custom_rules
            
            return config_dict
            
        except Exception as e:
            self.logger.error(f"Error converting configuration to dictionary: {e}")
            return {}
    
    def _validate_configuration(self) -> bool:
        """
        Validate configuration settings.
        
        Returns:
            True if configuration is valid, False otherwise
        """
        try:
            # Validate detection thresholds
            if self.config.detection.port_scan_threshold < 1:
                self.logger.error("Port scan threshold must be >= 1")
                return False
            
            if self.config.detection.ddos_threshold < 1:
                self.logger.error("DDoS threshold must be >= 1")
                return False
            
            if not (0.0 < self.config.detection.anomaly_contamination < 1.0):
                self.logger.error("Anomaly contamination must be between 0.0 and 1.0")
                return False
            
            # Validate alert configuration
            if self.config.alerts.enable_email and not self.config.alerts.alert_emails:
                self.logger.warning("Email alerts enabled but no email addresses configured")
            
            # Validate interface configuration
            if self.config.interface.packet_buffer_size < 100:
                self.logger.error("Packet buffer size must be >= 100")
                return False
            
            # Validate custom rules
            for rule in self.config.rules.custom_rules:
                if not self._validate_custom_rule(rule):
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating configuration: {e}")
            return False
    
    def _validate_custom_rule(self, rule: CustomRule) -> bool:
        """Validate a custom rule"""
        try:
            # Check required fields
            if not rule.name or not rule.pattern:
                self.logger.error(f"Rule missing required fields: {rule.name}")
                return False
            
            # Validate pattern based on type
            if rule.pattern_type == "regex":
                try:
                    re.compile(rule.pattern)
                except re.error as e:
                    self.logger.error(f"Invalid regex pattern in rule {rule.name}: {e}")
                    return False
            
            # Validate severity
            if rule.severity not in self.config.alerts.severity_levels:
                self.logger.error(f"Invalid severity level in rule {rule.name}: {rule.severity}")
                return False
            
            # Validate protocol
            valid_protocols = ["tcp", "udp", "icmp", "any"]
            if rule.protocol.lower() not in valid_protocols:
                self.logger.error(f"Invalid protocol in rule {rule.name}: {rule.protocol}")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating rule {rule.name}: {e}")
            return False
    
    def get_detection_thresholds(self) -> DetectionThresholds:
        """Get current detection thresholds"""
        return self.config.detection
    
    def update_detection_thresholds(self, **kwargs) -> bool:
        """
        Update detection thresholds.
        
        Args:
            **kwargs: Threshold parameters to update
            
        Returns:
            True if updated successfully
        """
        try:
            # Validate parameters before updating
            for key, value in kwargs.items():
                if not hasattr(self.config.detection, key):
                    self.logger.error(f"Invalid detection threshold parameter: {key}")
                    return False
                
                # Validate specific parameters
                if key == "port_scan_threshold" and value < 1:
                    self.logger.error("Port scan threshold must be >= 1")
                    return False
                elif key == "ddos_threshold" and value < 1:
                    self.logger.error("DDoS threshold must be >= 1")
                    return False
                elif key == "anomaly_contamination" and not (0.0 < value < 1.0):
                    self.logger.error("Anomaly contamination must be between 0.0 and 1.0")
                    return False
            
            updated = False
            
            for key, value in kwargs.items():
                if hasattr(self.config.detection, key):
                    setattr(self.config.detection, key, value)
                    updated = True
                    self.logger.info(f"Updated detection threshold {key} to {value}")
            
            if updated:
                return self.save_configuration()
            
            return updated
            
        except Exception as e:
            self.logger.error(f"Error updating detection thresholds: {e}")
            return False
    
    def get_alert_configuration(self) -> AlertConfiguration:
        """Get current alert configuration"""
        return self.config.alerts
    
    def update_alert_configuration(self, **kwargs) -> bool:
        """
        Update alert configuration.
        
        Args:
            **kwargs: Alert parameters to update
            
        Returns:
            True if updated successfully
        """
        try:
            updated = False
            
            for key, value in kwargs.items():
                if hasattr(self.config.alerts, key):
                    setattr(self.config.alerts, key, value)
                    updated = True
                    self.logger.info(f"Updated alert configuration {key} to {value}")
            
            if updated:
                self.save_configuration()
            
            return updated
            
        except Exception as e:
            self.logger.error(f"Error updating alert configuration: {e}")
            return False
    
    def get_interface_configuration(self) -> InterfaceConfiguration:
        """Get current interface configuration"""
        return self.config.interface
    
    def update_interface_configuration(self, **kwargs) -> bool:
        """
        Update interface configuration.
        
        Args:
            **kwargs: Interface parameters to update
            
        Returns:
            True if updated successfully
        """
        try:
            updated = False
            
            for key, value in kwargs.items():
                if hasattr(self.config.interface, key):
                    setattr(self.config.interface, key, value)
                    updated = True
                    self.logger.info(f"Updated interface configuration {key} to {value}")
            
            if updated:
                self.save_configuration()
            
            return updated
            
        except Exception as e:
            self.logger.error(f"Error updating interface configuration: {e}")
            return False
    
    def add_custom_rule(self, rule: CustomRule) -> bool:
        """
        Add a custom threat detection rule.
        
        Args:
            rule: CustomRule object to add
            
        Returns:
            True if added successfully
        """
        try:
            # Validate rule
            if not self._validate_custom_rule(rule):
                return False
            
            # Check for duplicate names
            existing_names = [r.name for r in self.config.rules.custom_rules]
            if rule.name in existing_names:
                self.logger.error(f"Rule with name '{rule.name}' already exists")
                return False
            
            # Add rule
            self.config.rules.custom_rules.append(rule)
            
            # Save configuration
            if self.save_configuration():
                self.logger.info(f"Added custom rule: {rule.name}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error adding custom rule: {e}")
            return False
    
    def remove_custom_rule(self, rule_name: str) -> bool:
        """
        Remove a custom threat detection rule.
        
        Args:
            rule_name: Name of rule to remove
            
        Returns:
            True if removed successfully
        """
        try:
            # Find and remove rule
            original_count = len(self.config.rules.custom_rules)
            self.config.rules.custom_rules = [
                rule for rule in self.config.rules.custom_rules 
                if rule.name != rule_name
            ]
            
            if len(self.config.rules.custom_rules) < original_count:
                # Save configuration
                if self.save_configuration():
                    self.logger.info(f"Removed custom rule: {rule_name}")
                    return True
            else:
                self.logger.warning(f"Rule '{rule_name}' not found")
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error removing custom rule: {e}")
            return False
    
    def update_custom_rule(self, rule_name: str, **kwargs) -> bool:
        """
        Update a custom threat detection rule.
        
        Args:
            rule_name: Name of rule to update
            **kwargs: Rule parameters to update
            
        Returns:
            True if updated successfully
        """
        try:
            # Find rule
            rule = None
            for r in self.config.rules.custom_rules:
                if r.name == rule_name:
                    rule = r
                    break
            
            if not rule:
                self.logger.error(f"Rule '{rule_name}' not found")
                return False
            
            # Update rule attributes
            updated = False
            for key, value in kwargs.items():
                if hasattr(rule, key):
                    setattr(rule, key, value)
                    updated = True
            
            if updated:
                # Update last modified timestamp
                rule.last_modified = datetime.now().isoformat()
                
                # Validate updated rule
                if not self._validate_custom_rule(rule):
                    return False
                
                # Save configuration
                if self.save_configuration():
                    self.logger.info(f"Updated custom rule: {rule_name}")
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error updating custom rule: {e}")
            return False
    
    def get_custom_rules(self, enabled_only: bool = False) -> List[CustomRule]:
        """
        Get custom threat detection rules.
        
        Args:
            enabled_only: Return only enabled rules
            
        Returns:
            List of custom rules
        """
        if enabled_only:
            return [rule for rule in self.config.rules.custom_rules if rule.enabled]
        return self.config.rules.custom_rules.copy()
    
    def export_configuration(self, export_path: str, format: str = "json") -> bool:
        """
        Export configuration to file.
        
        Args:
            export_path: Path to export file
            format: Export format ("json" or "yaml")
            
        Returns:
            True if exported successfully
        """
        try:
            config_data = self._config_to_dict(self.config)
            
            with open(export_path, 'w') as f:
                if format.lower() == "json":
                    json.dump(config_data, f, indent=2, default=str)
                elif format.lower() in ["yaml", "yml"]:
                    yaml.dump(config_data, f, default_flow_style=False, indent=2)
                else:
                    raise ValueError(f"Unsupported export format: {format}")
            
            self.logger.info(f"Configuration exported to {export_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting configuration: {e}")
            return False
    
    def import_configuration(self, import_path: str) -> bool:
        """
        Import configuration from file.
        
        Args:
            import_path: Path to import file
            
        Returns:
            True if imported successfully
        """
        try:
            import_path = Path(import_path)
            if not import_path.exists():
                self.logger.error(f"Import file not found: {import_path}")
                return False
            
            # Detect format and load
            file_format = self._detect_file_format(import_path)
            
            with open(import_path, 'r') as f:
                if file_format == ConfigFormat.JSON:
                    config_data = json.load(f)
                elif file_format in [ConfigFormat.YAML, ConfigFormat.YML]:
                    config_data = yaml.safe_load(f)
                else:
                    raise ValueError(f"Unsupported import format: {file_format}")
            
            # Convert and validate
            imported_config = self._dict_to_config(config_data)
            
            # Backup current configuration
            backup_config = self.config
            self.config = imported_config
            
            if self._validate_configuration():
                # Save imported configuration
                if self.save_configuration():
                    self.logger.info(f"Configuration imported from {import_path}")
                    return True
                else:
                    # Restore backup on save failure
                    self.config = backup_config
                    self.logger.error("Failed to save imported configuration")
                    return False
            else:
                # Restore backup on validation failure
                self.config = backup_config
                self.logger.error("Imported configuration failed validation")
                return False
            
        except Exception as e:
            self.logger.error(f"Error importing configuration: {e}")
            return False
    
    def register_change_callback(self, callback: callable) -> None:
        """Register callback for configuration changes"""
        self.change_callbacks.append(callback)
    
    def _notify_change_callbacks(self) -> None:
        """Notify all registered callbacks of configuration changes"""
        for callback in self.change_callbacks:
            try:
                callback(self.config)
            except Exception as e:
                self.logger.error(f"Error in configuration change callback: {e}")
    
    def get_configuration_summary(self) -> Dict[str, Any]:
        """Get summary of current configuration"""
        return {
            "config_version": self.config.config_version,
            "last_updated": self.config.last_updated,
            "detection_thresholds": {
                "port_scan": self.config.detection.port_scan_threshold,
                "ddos": self.config.detection.ddos_threshold,
                "anomaly_contamination": self.config.detection.anomaly_contamination
            },
            "alert_settings": {
                "email_enabled": self.config.alerts.enable_email,
                "email_count": len(self.config.alerts.alert_emails),
                "severity_levels": len(self.config.alerts.severity_levels)
            },
            "interface_settings": {
                "capture_interface": self.config.interface.capture_interface,
                "packet_filters": len(self.config.interface.packet_filters),
                "excluded_ips": len(self.config.interface.excluded_ips)
            },
            "custom_rules": {
                "total_rules": len(self.config.rules.custom_rules),
                "enabled_rules": len([r for r in self.config.rules.custom_rules if r.enabled])
            }
        }


# Global configuration manager instance
config_manager = ConfigurationManager()


if __name__ == "__main__":
    # Test configuration manager
    print("SpyNet Configuration Manager Test")
    print("=" * 40)
    
    # Create test configuration manager
    test_config = ConfigurationManager("test_config.json")
    
    # Display current configuration summary
    summary = test_config.get_configuration_summary()
    print("Configuration Summary:")
    for key, value in summary.items():
        print(f"  {key}: {value}")
    
    # Test adding a custom rule
    test_rule = CustomRule(
        name="test_sql_injection",
        description="Test SQL injection detection",
        pattern=r"(?i)(union\s+select|select\s+.*\s+from)",
        pattern_type="regex",
        severity="High",
        protocol="tcp",
        ports=[80, 443]
    )
    
    if test_config.add_custom_rule(test_rule):
        print(f"\nAdded test rule: {test_rule.name}")
    
    # Test updating detection thresholds
    if test_config.update_detection_thresholds(port_scan_threshold=15, ddos_threshold=150):
        print("Updated detection thresholds")
    
    print("\nConfiguration manager test completed")