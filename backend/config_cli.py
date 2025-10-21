#!/usr/bin/env python3
"""
SpyNet Configuration CLI Tool

Command-line interface for managing SpyNet configuration including
detection thresholds, alert settings, interface configuration, and custom rules.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Any, List
import yaml
import re
from datetime import datetime

from config_manager import config_manager, CustomRule


def print_section_header(title: str) -> None:
    """Print a formatted section header"""
    print(f"\n{'=' * 60}")
    print(f"{title:^60}")
    print('=' * 60)


def print_subsection_header(title: str) -> None:
    """Print a formatted subsection header"""
    print(f"\n{'-' * 40}")
    print(f"{title}")
    print('-' * 40)


def format_value(value: Any) -> str:
    """Format a value for display"""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    elif isinstance(value, list):
        if not value:
            return "None"
        return ", ".join(str(v) for v in value)
    elif isinstance(value, dict):
        return json.dumps(value, indent=2)
    elif value == "":
        return "Not set"
    else:
        return str(value)


def show_configuration_summary():
    """Display configuration summary"""
    print_section_header("SpyNet Configuration Summary")
    
    try:
        summary = config_manager.get_configuration_summary()
        
        print(f"Configuration Version: {summary['config_version']}")
        print(f"Last Updated: {summary['last_updated']}")
        
        print_subsection_header("Detection Thresholds")
        thresholds = summary['detection_thresholds']
        print(f"  Port Scan Threshold: {thresholds['port_scan']}")
        print(f"  DDoS Threshold: {thresholds['ddos']}")
        print(f"  Anomaly Contamination: {thresholds['anomaly_contamination']}")
        
        print_subsection_header("Alert Settings")
        alerts = summary['alert_settings']
        print(f"  Email Enabled: {format_value(alerts['email_enabled'])}")
        print(f"  Email Addresses: {alerts['email_count']}")
        print(f"  Severity Levels: {alerts['severity_levels']}")
        
        print_subsection_header("Interface Settings")
        interface = summary['interface_settings']
        print(f"  Capture Interface: {interface['capture_interface']}")
        print(f"  Packet Filters: {interface['packet_filters']}")
        print(f"  Excluded IPs: {interface['excluded_ips']}")
        
        print_subsection_header("Custom Rules")
        rules = summary['custom_rules']
        print(f"  Total Rules: {rules['total_rules']}")
        print(f"  Enabled Rules: {rules['enabled_rules']}")
        
    except Exception as e:
        print(f"Error retrieving configuration summary: {e}")
        return False
    
    return True


def show_detection_thresholds():
    """Display detection thresholds"""
    print_section_header("Detection Thresholds")
    
    try:
        thresholds = config_manager.get_detection_thresholds()
        
        print(f"Port Scan Threshold: {thresholds.port_scan_threshold}")
        print(f"DDoS Threshold: {thresholds.ddos_threshold}")
        print(f"Anomaly Contamination: {thresholds.anomaly_contamination}")
        print(f"Scan Time Window: {thresholds.scan_time_window} seconds")
        print(f"DDoS Time Window: {thresholds.ddos_time_window} seconds")
        print(f"Connection Timeout: {thresholds.connection_timeout} seconds")
        print(f"Brute Force Threshold: {thresholds.brute_force_threshold}")
        print(f"Brute Force Time Window: {thresholds.brute_force_time_window} seconds")
        
    except Exception as e:
        print(f"Error retrieving detection thresholds: {e}")
        return False
    
    return True


def update_detection_thresholds(args):
    """Update detection thresholds"""
    print_section_header("Update Detection Thresholds")
    
    try:
        update_params = {}
        
        if args.port_scan_threshold is not None:
            update_params['port_scan_threshold'] = args.port_scan_threshold
        if args.ddos_threshold is not None:
            update_params['ddos_threshold'] = args.ddos_threshold
        if args.anomaly_contamination is not None:
            update_params['anomaly_contamination'] = args.anomaly_contamination
        if args.scan_time_window is not None:
            update_params['scan_time_window'] = args.scan_time_window
        if args.ddos_time_window is not None:
            update_params['ddos_time_window'] = args.ddos_time_window
        if args.connection_timeout is not None:
            update_params['connection_timeout'] = args.connection_timeout
        if args.brute_force_threshold is not None:
            update_params['brute_force_threshold'] = args.brute_force_threshold
        if args.brute_force_time_window is not None:
            update_params['brute_force_time_window'] = args.brute_force_time_window
        
        if not update_params:
            print("No parameters provided for update")
            return False
        
        success = config_manager.update_detection_thresholds(**update_params)
        
        if success:
            print("Detection thresholds updated successfully:")
            for key, value in update_params.items():
                print(f"  {key}: {value}")
        else:
            print("Failed to update detection thresholds")
            return False
            
    except Exception as e:
        print(f"Error updating detection thresholds: {e}")
        return False
    
    return True


def show_alert_configuration():
    """Display alert configuration"""
    print_section_header("Alert Configuration")
    
    try:
        alert_config = config_manager.get_alert_configuration()
        
        print_subsection_header("General Settings")
        print(f"Email Enabled: {format_value(alert_config.enable_email)}")
        print(f"Syslog Enabled: {format_value(alert_config.enable_syslog)}")
        print(f"Webhook Enabled: {format_value(alert_config.enable_webhook)}")
        print(f"Critical Only: {format_value(alert_config.critical_only)}")
        print(f"Deduplication Window: {alert_config.dedup_window_minutes} minutes")
        print(f"Max Alerts Per Hour: {alert_config.max_alerts_per_hour}")
        print(f"Alert Retention: {alert_config.alert_retention_days} days")
        
        print_subsection_header("Email Settings")
        print(f"SMTP Server: {alert_config.smtp_server}")
        print(f"SMTP Port: {alert_config.smtp_port}")
        print(f"SMTP Username: {alert_config.smtp_username}")
        print(f"SMTP Password: {'***' if alert_config.smtp_password else 'Not set'}")
        print(f"Use TLS: {format_value(alert_config.smtp_use_tls)}")
        print(f"Alert Emails: {format_value(alert_config.alert_emails)}")
        
        print_subsection_header("Webhook Settings")
        print(f"Webhook URL: {alert_config.webhook_url or 'Not set'}")
        print(f"Webhook Timeout: {alert_config.webhook_timeout} seconds")
        
        print_subsection_header("Syslog Settings")
        print(f"Syslog Server: {alert_config.syslog_server}")
        print(f"Syslog Port: {alert_config.syslog_port}")
        print(f"Syslog Facility: {alert_config.syslog_facility}")
        
        print_subsection_header("Severity Levels")
        for level, value in alert_config.severity_levels.items():
            print(f"  {level}: {value}")
        
    except Exception as e:
        print(f"Error retrieving alert configuration: {e}")
        return False
    
    return True


def update_alert_configuration(args):
    """Update alert configuration"""
    print_section_header("Update Alert Configuration")
    
    try:
        update_params = {}
        
        if args.enable_email is not None:
            update_params['enable_email'] = args.enable_email
        if args.enable_syslog is not None:
            update_params['enable_syslog'] = args.enable_syslog
        if args.enable_webhook is not None:
            update_params['enable_webhook'] = args.enable_webhook
        if args.critical_only is not None:
            update_params['critical_only'] = args.critical_only
        if args.dedup_window_minutes is not None:
            update_params['dedup_window_minutes'] = args.dedup_window_minutes
        if args.max_alerts_per_hour is not None:
            update_params['max_alerts_per_hour'] = args.max_alerts_per_hour
        if args.alert_retention_days is not None:
            update_params['alert_retention_days'] = args.alert_retention_days
        if args.smtp_server is not None:
            update_params['smtp_server'] = args.smtp_server
        if args.smtp_port is not None:
            update_params['smtp_port'] = args.smtp_port
        if args.smtp_username is not None:
            update_params['smtp_username'] = args.smtp_username
        if args.smtp_password is not None:
            update_params['smtp_password'] = args.smtp_password
        if args.smtp_use_tls is not None:
            update_params['smtp_use_tls'] = args.smtp_use_tls
        if args.alert_emails is not None:
            update_params['alert_emails'] = args.alert_emails
        if args.webhook_url is not None:
            update_params['webhook_url'] = args.webhook_url
        if args.webhook_timeout is not None:
            update_params['webhook_timeout'] = args.webhook_timeout
        if args.syslog_server is not None:
            update_params['syslog_server'] = args.syslog_server
        if args.syslog_port is not None:
            update_params['syslog_port'] = args.syslog_port
        if args.syslog_facility is not None:
            update_params['syslog_facility'] = args.syslog_facility
        
        if not update_params:
            print("No parameters provided for update")
            return False
        
        success = config_manager.update_alert_configuration(**update_params)
        
        if success:
            print("Alert configuration updated successfully:")
            for key, value in update_params.items():
                if key == 'smtp_password':
                    print(f"  {key}: ***")
                else:
                    print(f"  {key}: {value}")
        else:
            print("Failed to update alert configuration")
            return False
            
    except Exception as e:
        print(f"Error updating alert configuration: {e}")
        return False
    
    return True


def show_interface_configuration():
    """Display interface configuration"""
    print_section_header("Interface Configuration")
    
    try:
        interface_config = config_manager.get_interface_configuration()
        
        print(f"Capture Interface: {interface_config.capture_interface}")
        print(f"Packet Buffer Size: {interface_config.packet_buffer_size}")
        print(f"Capture Timeout: {interface_config.capture_timeout} seconds")
        print(f"Promiscuous Mode: {format_value(interface_config.promiscuous_mode)}")
        print(f"Max Packet Size: {interface_config.max_packet_size} bytes")
        
        print_subsection_header("Packet Filters")
        if interface_config.packet_filters:
            for i, filter_rule in enumerate(interface_config.packet_filters, 1):
                print(f"  {i}. {filter_rule}")
        else:
            print("  No packet filters configured")
        
        print_subsection_header("IP Address Filters")
        print(f"Excluded IPs: {format_value(interface_config.excluded_ips)}")
        print(f"Included IPs: {format_value(interface_config.included_ips)}")
        
        print_subsection_header("Port Filters")
        print(f"Excluded Ports: {format_value(interface_config.excluded_ports)}")
        print(f"Included Ports: {format_value(interface_config.included_ports)}")
        
    except Exception as e:
        print(f"Error retrieving interface configuration: {e}")
        return False
    
    return True


def update_interface_configuration(args):
    """Update interface configuration"""
    print_section_header("Update Interface Configuration")
    
    try:
        update_params = {}
        
        if args.capture_interface is not None:
            update_params['capture_interface'] = args.capture_interface
        if args.packet_buffer_size is not None:
            update_params['packet_buffer_size'] = args.packet_buffer_size
        if args.capture_timeout is not None:
            update_params['capture_timeout'] = args.capture_timeout
        if args.promiscuous_mode is not None:
            update_params['promiscuous_mode'] = args.promiscuous_mode
        if args.max_packet_size is not None:
            update_params['max_packet_size'] = args.max_packet_size
        if args.packet_filters is not None:
            update_params['packet_filters'] = args.packet_filters
        if args.excluded_ips is not None:
            update_params['excluded_ips'] = args.excluded_ips
        if args.included_ips is not None:
            update_params['included_ips'] = args.included_ips
        if args.excluded_ports is not None:
            update_params['excluded_ports'] = args.excluded_ports
        if args.included_ports is not None:
            update_params['included_ports'] = args.included_ports
        
        if not update_params:
            print("No parameters provided for update")
            return False
        
        success = config_manager.update_interface_configuration(**update_params)
        
        if success:
            print("Interface configuration updated successfully:")
            for key, value in update_params.items():
                print(f"  {key}: {value}")
        else:
            print("Failed to update interface configuration")
            return False
            
    except Exception as e:
        print(f"Error updating interface configuration: {e}")
        return False
    
    return True


def show_custom_rules():
    """Display custom rules"""
    print_section_header("Custom Threat Detection Rules")
    
    try:
        rules = config_manager.get_custom_rules()
        
        if not rules:
            print("No custom rules configured")
            return True
        
        for i, rule in enumerate(rules, 1):
            print_subsection_header(f"Rule {i}: {rule.name}")
            print(f"  Description: {rule.description}")
            print(f"  Pattern: {rule.pattern}")
            print(f"  Pattern Type: {rule.pattern_type}")
            print(f"  Severity: {rule.severity}")
            print(f"  Enabled: {format_value(rule.enabled)}")
            print(f"  Protocol: {rule.protocol}")
            print(f"  Ports: {format_value(rule.ports)}")
            print(f"  Created: {rule.created_date}")
            print(f"  Last Modified: {rule.last_modified}")
        
    except Exception as e:
        print(f"Error retrieving custom rules: {e}")
        return False
    
    return True


def add_custom_rule(args):
    """Add a custom rule"""
    print_section_header("Add Custom Rule")
    
    try:
        # Validate pattern if it's a regex
        if args.pattern_type == "regex":
            try:
                re.compile(args.pattern)
            except re.error as e:
                print(f"Invalid regex pattern: {e}")
                return False
        
        # Create rule
        rule = CustomRule(
            name=args.name,
            description=args.description,
            pattern=args.pattern,
            pattern_type=args.pattern_type,
            severity=args.severity,
            enabled=args.enabled,
            protocol=args.protocol,
            ports=args.ports or []
        )
        
        success = config_manager.add_custom_rule(rule)
        
        if success:
            print(f"Custom rule '{args.name}' added successfully")
        else:
            print(f"Failed to add custom rule '{args.name}'")
            return False
            
    except Exception as e:
        print(f"Error adding custom rule: {e}")
        return False
    
    return True


def remove_custom_rule(args):
    """Remove a custom rule"""
    print_section_header("Remove Custom Rule")
    
    try:
        success = config_manager.remove_custom_rule(args.name)
        
        if success:
            print(f"Custom rule '{args.name}' removed successfully")
        else:
            print(f"Custom rule '{args.name}' not found")
            return False
            
    except Exception as e:
        print(f"Error removing custom rule: {e}")
        return False
    
    return True


def update_custom_rule(args):
    """Update a custom rule"""
    print_section_header("Update Custom Rule")
    
    try:
        update_params = {}
        
        if args.description is not None:
            update_params['description'] = args.description
        if args.pattern is not None:
            # Validate pattern if it's a regex
            if args.pattern_type == "regex":
                try:
                    re.compile(args.pattern)
                except re.error as e:
                    print(f"Invalid regex pattern: {e}")
                    return False
            update_params['pattern'] = args.pattern
        if args.pattern_type is not None:
            update_params['pattern_type'] = args.pattern_type
        if args.severity is not None:
            update_params['severity'] = args.severity
        if args.enabled is not None:
            update_params['enabled'] = args.enabled
        if args.protocol is not None:
            update_params['protocol'] = args.protocol
        if args.ports is not None:
            update_params['ports'] = args.ports
        
        if not update_params:
            print("No parameters provided for update")
            return False
        
        success = config_manager.update_custom_rule(args.name, **update_params)
        
        if success:
            print(f"Custom rule '{args.name}' updated successfully:")
            for key, value in update_params.items():
                print(f"  {key}: {value}")
        else:
            print(f"Custom rule '{args.name}' not found")
            return False
            
    except Exception as e:
        print(f"Error updating custom rule: {e}")
        return False
    
    return True


def export_configuration(args):
    """Export configuration to file"""
    print_section_header("Export Configuration")
    
    try:
        success = config_manager.export_configuration(args.file, args.format)
        
        if success:
            print(f"Configuration exported to {args.file} in {args.format} format")
        else:
            print(f"Failed to export configuration to {args.file}")
            return False
            
    except Exception as e:
        print(f"Error exporting configuration: {e}")
        return False
    
    return True


def import_configuration(args):
    """Import configuration from file"""
    print_section_header("Import Configuration")
    
    try:
        if not Path(args.file).exists():
            print(f"Configuration file {args.file} not found")
            return False
        
        success = config_manager.import_configuration(args.file)
        
        if success:
            print(f"Configuration imported from {args.file}")
        else:
            print(f"Failed to import configuration from {args.file}")
            return False
            
    except Exception as e:
        print(f"Error importing configuration: {e}")
        return False
    
    return True


def reset_configuration():
    """Reset configuration to defaults"""
    print_section_header("Reset Configuration")
    
    try:
        # Confirm reset
        response = input("Are you sure you want to reset all configuration to defaults? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("Configuration reset cancelled")
            return True
        
        # Create backup first
        backup_file = f"config_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        if config_manager.export_configuration(backup_file, "json"):
            print(f"Configuration backup created: {backup_file}")
        
        # Reset configuration
        from config_manager import SpyNetConfiguration
        config_manager.config = SpyNetConfiguration()
        
        success = config_manager.save_configuration()
        
        if success:
            print("Configuration reset to defaults successfully")
        else:
            print("Failed to reset configuration")
            return False
            
    except Exception as e:
        print(f"Error resetting configuration: {e}")
        return False
    
    return True


def validate_configuration():
    """Validate current configuration"""
    print_section_header("Validate Configuration")
    
    try:
        is_valid = config_manager._validate_configuration()
        
        if is_valid:
            print("Configuration is valid")
        else:
            print("Configuration validation failed - check logs for details")
            return False
            
    except Exception as e:
        print(f"Error validating configuration: {e}")
        return False
    
    return True


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="SpyNet Configuration Management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s show summary                    # Show configuration summary
  %(prog)s show detection                  # Show detection thresholds
  %(prog)s show alerts                     # Show alert configuration
  %(prog)s show interface                  # Show interface configuration
  %(prog)s show rules                      # Show custom rules
  
  %(prog)s update detection --port-scan-threshold 15
  %(prog)s update alerts --enable-email true --smtp-server smtp.example.com
  %(prog)s update interface --capture-interface eth1
  
  %(prog)s add-rule --name "SQL Injection" --pattern "union.*select" --pattern-type regex --severity High
  %(prog)s remove-rule --name "SQL Injection"
  %(prog)s update-rule --name "SQL Injection" --enabled false
  
  %(prog)s export --file config.json --format json
  %(prog)s import --file config.json
  %(prog)s reset
  %(prog)s validate
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Show commands
    show_parser = subparsers.add_parser('show', help='Show configuration')
    show_subparsers = show_parser.add_subparsers(dest='show_type', help='What to show')
    
    show_subparsers.add_parser('summary', help='Show configuration summary')
    show_subparsers.add_parser('detection', help='Show detection thresholds')
    show_subparsers.add_parser('alerts', help='Show alert configuration')
    show_subparsers.add_parser('interface', help='Show interface configuration')
    show_subparsers.add_parser('rules', help='Show custom rules')
    
    # Update commands
    update_parser = subparsers.add_parser('update', help='Update configuration')
    update_subparsers = update_parser.add_subparsers(dest='update_type', help='What to update')
    
    # Update detection thresholds
    detection_parser = update_subparsers.add_parser('detection', help='Update detection thresholds')
    detection_parser.add_argument('--port-scan-threshold', type=int, help='Port scan threshold')
    detection_parser.add_argument('--ddos-threshold', type=int, help='DDoS threshold')
    detection_parser.add_argument('--anomaly-contamination', type=float, help='Anomaly contamination (0.0-1.0)')
    detection_parser.add_argument('--scan-time-window', type=int, help='Scan time window (seconds)')
    detection_parser.add_argument('--ddos-time-window', type=int, help='DDoS time window (seconds)')
    detection_parser.add_argument('--connection-timeout', type=int, help='Connection timeout (seconds)')
    detection_parser.add_argument('--brute-force-threshold', type=int, help='Brute force threshold')
    detection_parser.add_argument('--brute-force-time-window', type=int, help='Brute force time window (seconds)')
    
    # Update alert configuration
    alerts_parser = update_subparsers.add_parser('alerts', help='Update alert configuration')
    alerts_parser.add_argument('--enable-email', type=bool, help='Enable email alerts')
    alerts_parser.add_argument('--enable-syslog', type=bool, help='Enable syslog alerts')
    alerts_parser.add_argument('--enable-webhook', type=bool, help='Enable webhook alerts')
    alerts_parser.add_argument('--critical-only', type=bool, help='Only send critical alerts')
    alerts_parser.add_argument('--dedup-window-minutes', type=int, help='Deduplication window (minutes)')
    alerts_parser.add_argument('--max-alerts-per-hour', type=int, help='Maximum alerts per hour')
    alerts_parser.add_argument('--alert-retention-days', type=int, help='Alert retention (days)')
    alerts_parser.add_argument('--smtp-server', help='SMTP server')
    alerts_parser.add_argument('--smtp-port', type=int, help='SMTP port')
    alerts_parser.add_argument('--smtp-username', help='SMTP username')
    alerts_parser.add_argument('--smtp-password', help='SMTP password')
    alerts_parser.add_argument('--smtp-use-tls', type=bool, help='Use TLS for SMTP')
    alerts_parser.add_argument('--alert-emails', nargs='+', help='Alert email addresses')
    alerts_parser.add_argument('--webhook-url', help='Webhook URL')
    alerts_parser.add_argument('--webhook-timeout', type=int, help='Webhook timeout (seconds)')
    alerts_parser.add_argument('--syslog-server', help='Syslog server')
    alerts_parser.add_argument('--syslog-port', type=int, help='Syslog port')
    alerts_parser.add_argument('--syslog-facility', help='Syslog facility')
    
    # Update interface configuration
    interface_parser = update_subparsers.add_parser('interface', help='Update interface configuration')
    interface_parser.add_argument('--capture-interface', help='Capture interface')
    interface_parser.add_argument('--packet-buffer-size', type=int, help='Packet buffer size')
    interface_parser.add_argument('--capture-timeout', type=int, help='Capture timeout (seconds)')
    interface_parser.add_argument('--promiscuous-mode', type=bool, help='Enable promiscuous mode')
    interface_parser.add_argument('--max-packet-size', type=int, help='Maximum packet size (bytes)')
    interface_parser.add_argument('--packet-filters', nargs='+', help='Packet filters')
    interface_parser.add_argument('--excluded-ips', nargs='+', help='Excluded IP addresses')
    interface_parser.add_argument('--included-ips', nargs='+', help='Included IP addresses')
    interface_parser.add_argument('--excluded-ports', nargs='+', type=int, help='Excluded ports')
    interface_parser.add_argument('--included-ports', nargs='+', type=int, help='Included ports')
    
    # Rule management commands
    add_rule_parser = subparsers.add_parser('add-rule', help='Add custom rule')
    add_rule_parser.add_argument('--name', required=True, help='Rule name')
    add_rule_parser.add_argument('--description', required=True, help='Rule description')
    add_rule_parser.add_argument('--pattern', required=True, help='Detection pattern')
    add_rule_parser.add_argument('--pattern-type', required=True, choices=['regex', 'string', 'bytes'], help='Pattern type')
    add_rule_parser.add_argument('--severity', required=True, choices=['Low', 'Medium', 'High', 'Critical'], help='Severity level')
    add_rule_parser.add_argument('--enabled', type=bool, default=True, help='Enable rule')
    add_rule_parser.add_argument('--protocol', default='any', choices=['tcp', 'udp', 'icmp', 'any'], help='Protocol')
    add_rule_parser.add_argument('--ports', nargs='+', type=int, help='Target ports')
    
    remove_rule_parser = subparsers.add_parser('remove-rule', help='Remove custom rule')
    remove_rule_parser.add_argument('--name', required=True, help='Rule name to remove')
    
    update_rule_parser = subparsers.add_parser('update-rule', help='Update custom rule')
    update_rule_parser.add_argument('--name', required=True, help='Rule name to update')
    update_rule_parser.add_argument('--description', help='Rule description')
    update_rule_parser.add_argument('--pattern', help='Detection pattern')
    update_rule_parser.add_argument('--pattern-type', choices=['regex', 'string', 'bytes'], help='Pattern type')
    update_rule_parser.add_argument('--severity', choices=['Low', 'Medium', 'High', 'Critical'], help='Severity level')
    update_rule_parser.add_argument('--enabled', type=bool, help='Enable/disable rule')
    update_rule_parser.add_argument('--protocol', choices=['tcp', 'udp', 'icmp', 'any'], help='Protocol')
    update_rule_parser.add_argument('--ports', nargs='+', type=int, help='Target ports')
    
    # Configuration management commands
    export_parser = subparsers.add_parser('export', help='Export configuration')
    export_parser.add_argument('--file', required=True, help='Export file path')
    export_parser.add_argument('--format', choices=['json', 'yaml'], default='json', help='Export format')
    
    import_parser = subparsers.add_parser('import', help='Import configuration')
    import_parser.add_argument('--file', required=True, help='Import file path')
    
    subparsers.add_parser('reset', help='Reset configuration to defaults')
    subparsers.add_parser('validate', help='Validate current configuration')
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Execute commands
    try:
        success = True
        
        if args.command == 'show':
            if args.show_type == 'summary':
                success = show_configuration_summary()
            elif args.show_type == 'detection':
                success = show_detection_thresholds()
            elif args.show_type == 'alerts':
                success = show_alert_configuration()
            elif args.show_type == 'interface':
                success = show_interface_configuration()
            elif args.show_type == 'rules':
                success = show_custom_rules()
            else:
                print("Invalid show command")
                success = False
        
        elif args.command == 'update':
            if args.update_type == 'detection':
                success = update_detection_thresholds(args)
            elif args.update_type == 'alerts':
                success = update_alert_configuration(args)
            elif args.update_type == 'interface':
                success = update_interface_configuration(args)
            else:
                print("Invalid update command")
                success = False
        
        elif args.command == 'add-rule':
            success = add_custom_rule(args)
        elif args.command == 'remove-rule':
            success = remove_custom_rule(args)
        elif args.command == 'update-rule':
            success = update_custom_rule(args)
        elif args.command == 'export':
            success = export_configuration(args)
        elif args.command == 'import':
            success = import_configuration(args)
        elif args.command == 'reset':
            success = reset_configuration()
        elif args.command == 'validate':
            success = validate_configuration()
        else:
            print(f"Unknown command: {args.command}")
            success = False
        
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())