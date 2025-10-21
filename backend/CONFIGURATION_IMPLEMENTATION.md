# SpyNet Configuration and Customization Features Implementation

## Overview

Task 11 has been successfully completed, implementing comprehensive configuration and customization features for the SpyNet system. The implementation includes configuration file parsing, customizable detection thresholds, alert settings, interface configuration, and custom rule management.

## Implemented Features

### 1. Configuration File Parsing for Detection Thresholds and System Settings

**Files Modified/Created:**
- `config_manager.py` - Comprehensive configuration management system
- `spynet_config.json` - Default configuration file

**Features:**
- Support for JSON and YAML configuration formats
- Hierarchical configuration structure with sections for:
  - Detection thresholds (port scan, DDoS, anomaly detection)
  - Alert configuration (email, syslog, webhook settings)
  - Interface settings (capture interface, packet filters)
  - Custom rules management
  - System settings (logging, performance tuning)
- Automatic configuration validation and error handling
- Configuration backup and restore functionality
- Hot-reload capability for configuration changes

### 2. Customizable Alert Severity Levels and Notification Preferences

**Features:**
- Configurable severity levels (Low, Medium, High, Critical)
- Multiple notification channels:
  - Email notifications with SMTP configuration
  - Syslog integration
  - Webhook notifications
- Alert deduplication and rate limiting
- Customizable alert retention policies
- Per-severity notification preferences

**Configuration Options:**
```json
{
  "alerts": {
    "severity_levels": {"Low": 1, "Medium": 2, "High": 3, "Critical": 4},
    "enable_email": true,
    "enable_syslog": false,
    "enable_webhook": false,
    "critical_only": false,
    "dedup_window_minutes": 10,
    "max_alerts_per_hour": 100,
    "alert_retention_days": 30,
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "alert_emails": ["admin@localhost"]
  }
}
```

### 3. Interface Selection and Packet Filtering Configuration

**Features:**
- Configurable network interface selection (auto-detection or manual)
- Packet buffer size configuration
- Advanced packet filtering options:
  - BPF-style packet filters
  - IP address inclusion/exclusion lists
  - Port-based filtering
  - Protocol-specific filtering
- Promiscuous mode configuration
- Maximum packet size limits

**Configuration Options:**
```json
{
  "interface": {
    "capture_interface": "auto",
    "packet_buffer_size": 1000,
    "capture_timeout": 1,
    "promiscuous_mode": true,
    "packet_filters": ["tcp port 80", "udp port 53"],
    "excluded_ips": ["192.168.1.1"],
    "included_ips": [],
    "excluded_ports": [22],
    "included_ports": [80, 443, 8080]
  }
}
```

### 4. Basic Rule Management for Custom Threat Detection Patterns

**Features:**
- Custom rule creation with multiple pattern types:
  - Regular expressions
  - String matching
  - Byte pattern matching
- Rule categorization and organization
- Enable/disable individual rules
- Protocol and port-specific rule targeting
- Rule validation and testing
- Rule import/export functionality

**Custom Rule Structure:**
```python
@dataclass
class CustomRule:
    name: str
    description: str
    pattern: str
    pattern_type: str  # "regex", "string", "bytes"
    severity: str = "Medium"
    enabled: bool = True
    protocol: str = "any"  # "tcp", "udp", "icmp", "any"
    ports: List[int] = field(default_factory=list)
    created_date: str
    last_modified: str
```

## Implementation Components

### 1. Configuration Manager (`config_manager.py`)

**Core Classes:**
- `ConfigurationManager` - Main configuration management class
- `DetectionThresholds` - Detection parameter configuration
- `AlertConfiguration` - Alert system configuration
- `InterfaceConfiguration` - Network interface configuration
- `CustomRule` - Custom threat detection rule
- `RuleManagement` - Rule management configuration
- `SystemConfiguration` - System-wide settings

**Key Methods:**
- `load_configuration()` - Load configuration from file
- `save_configuration()` - Save configuration with backup
- `update_detection_thresholds()` - Update detection parameters
- `update_alert_configuration()` - Update alert settings
- `update_interface_configuration()` - Update interface settings
- `add_custom_rule()` - Add custom detection rule
- `remove_custom_rule()` - Remove custom detection rule
- `export_configuration()` - Export configuration to file
- `import_configuration()` - Import configuration from file

### 2. Configuration API (`config_api.py`)

**REST API Endpoints:**
- `GET /api/v1/config/summary` - Configuration overview
- `GET/PUT /api/v1/config/detection/thresholds` - Detection thresholds
- `GET/PUT /api/v1/config/alerts` - Alert configuration
- `GET/PUT /api/v1/config/interface` - Interface configuration
- `GET/POST/PUT/DELETE /api/v1/config/rules` - Custom rules management
- `POST /api/v1/config/export` - Export configuration
- `POST /api/v1/config/import` - Import configuration
- `POST /api/v1/config/reset` - Reset to defaults
- `GET /api/v1/config/validate` - Validate configuration

### 3. Configuration CLI (`config_cli.py`)

**Command-Line Interface:**
```bash
# Show configuration
python config_cli.py show summary
python config_cli.py show detection
python config_cli.py show alerts
python config_cli.py show interface
python config_cli.py show rules

# Update configuration
python config_cli.py update detection --port-scan-threshold 15
python config_cli.py update alerts --enable-email true
python config_cli.py update interface --capture-interface eth1

# Manage custom rules
python config_cli.py add-rule --name "SQL Injection" --pattern "union.*select" --pattern-type regex --severity High
python config_cli.py remove-rule --name "SQL Injection"
python config_cli.py update-rule --name "SQL Injection" --enabled false

# Configuration management
python config_cli.py export --file config.json --format json
python config_cli.py import --file config.json
python config_cli.py reset
python config_cli.py validate
```

### 4. Component Integration

**Updated Components:**
- `threat_detector.py` - Integrated with configuration manager for thresholds and custom rules
- `anomaly_detector.py` - Uses configurable contamination parameter
- `alert_manager.py` - Uses configurable alert settings and notification preferences
- `packet_capture.py` - Uses configurable interface and filtering settings
- `spynet_app.py` - Registers configuration change callbacks for hot-reload

**Configuration Update Methods:**
Each component now includes an `update_configuration()` method that:
- Loads current settings from configuration manager
- Updates internal parameters
- Handles configuration changes without restart (where possible)

## Testing and Validation

### Test Scripts Created:
1. `test_configuration.py` - Comprehensive configuration system tests
2. `test_config_simple.py` - Simple tests without external dependencies
3. `test_config_integration.py` - Integration tests for component configuration

### Test Coverage:
- Configuration loading and saving
- Parameter validation and error handling
- Custom rule management
- Configuration export/import
- Component integration
- Configuration persistence
- Change callbacks
- Edge case validation

### Validation Features:
- Parameter range validation
- Regex pattern validation for custom rules
- Email address format validation
- File path validation
- Configuration schema validation
- Circular dependency detection

## Usage Examples

### 1. Update Detection Thresholds via CLI
```bash
python config_cli.py update detection --port-scan-threshold 20 --ddos-threshold 200
```

### 2. Add Custom Rule via CLI
```bash
python config_cli.py add-rule \
  --name "XSS Detection" \
  --description "Detects XSS attempts in HTTP traffic" \
  --pattern "<script.*?>.*?</script>" \
  --pattern-type regex \
  --severity High \
  --protocol tcp \
  --ports 80 443
```

### 3. Update Alert Configuration via API
```python
import requests

response = requests.put('http://localhost:8000/api/v1/config/alerts', json={
    'enable_email': True,
    'smtp_server': 'smtp.example.com',
    'alert_emails': ['security@example.com', 'admin@example.com']
})
```

### 4. Programmatic Configuration Management
```python
from config_manager import config_manager, CustomRule

# Update detection thresholds
config_manager.update_detection_thresholds(
    port_scan_threshold=25,
    anomaly_contamination=0.15
)

# Add custom rule
rule = CustomRule(
    name="Suspicious Upload",
    description="Detects large file uploads",
    pattern="Content-Length: [5-9][0-9]{6,}",
    pattern_type="regex",
    severity="Medium"
)
config_manager.add_custom_rule(rule)
```

## Configuration File Structure

The configuration is organized into logical sections:

```json
{
  "config_version": "1.0",
  "last_updated": "2025-10-21T21:39:14.429369",
  "detection": {
    "port_scan_threshold": 10,
    "ddos_threshold": 100,
    "anomaly_contamination": 0.1,
    "scan_time_window": 300,
    "ddos_time_window": 60,
    "connection_timeout": 300,
    "brute_force_threshold": 5,
    "brute_force_time_window": 300
  },
  "alerts": {
    "severity_levels": {"Low": 1, "Medium": 2, "High": 3, "Critical": 4},
    "enable_email": true,
    "enable_syslog": false,
    "enable_webhook": false,
    "critical_only": false,
    "dedup_window_minutes": 10,
    "max_alerts_per_hour": 100,
    "alert_retention_days": 30,
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "smtp_username": "",
    "smtp_password": "",
    "smtp_use_tls": true,
    "alert_emails": [],
    "webhook_url": "",
    "webhook_timeout": 30,
    "syslog_server": "localhost",
    "syslog_port": 514,
    "syslog_facility": "local0"
  },
  "interface": {
    "capture_interface": "auto",
    "packet_buffer_size": 1000,
    "capture_timeout": 1,
    "promiscuous_mode": true,
    "packet_filters": [],
    "excluded_ips": [],
    "included_ips": [],
    "excluded_ports": [],
    "included_ports": [],
    "max_packet_size": 65535
  },
  "rules": {
    "custom_rules": [],
    "rule_categories": {
      "malware": ["trojan", "virus", "backdoor", "botnet"],
      "web_attacks": ["sql_injection", "xss", "command_injection"],
      "network_attacks": ["port_scan", "ddos", "brute_force"],
      "data_exfiltration": ["large_upload", "suspicious_transfer"]
    },
    "enable_custom_rules": true,
    "rule_update_interval": 3600
  },
  "system": {
    "log_level": "INFO",
    "log_file": "spynet.log",
    "log_rotation_size": 10485760,
    "log_retention_days": 30,
    "debug": false,
    "max_connections_tracked": 10000,
    "stats_update_interval": 30,
    "anomaly_model_retrain_hours": 24,
    "cleanup_interval_minutes": 60,
    "database_cleanup_days": 30,
    "connection_pool_size": 20,
    "query_timeout": 30
  }
}
```

## Requirements Satisfied

✅ **Requirement 7.1**: Configuration file parsing for detection thresholds and system settings
✅ **Requirement 7.2**: Ability to customize alert severity levels and notification preferences  
✅ **Requirement 7.4**: Interface selection and packet filtering configuration options
✅ **Additional**: Basic rule management for custom threat detection patterns

The implementation provides a comprehensive, production-ready configuration management system that allows users to customize all aspects of the SpyNet system through multiple interfaces (CLI, API, and direct file editing) while maintaining data integrity and system stability.