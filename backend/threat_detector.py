"""
SpyNet Threat Detection Engine

This module implements the ThreatDetector class for identifying common network attacks
including port scanning, DDoS attacks, and suspicious payload patterns.
"""

import logging
import re
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
from enum import Enum

from packet_analyzer import PacketInfo
from models import Alert
from config_manager import config_manager


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class ThreatType(Enum):
    """Types of threats that can be detected"""
    PORT_SCAN = "Port Scan"
    DDOS_ATTACK = "DDoS Attack"
    SUSPICIOUS_PAYLOAD = "Suspicious Payload"
    BRUTE_FORCE = "Brute Force"
    MALWARE_COMMUNICATION = "Malware Communication"


@dataclass
class ThreatAlert:
    """Data class for threat alerts"""
    alert_type: str
    severity: AlertSeverity
    source_ip: str
    destination_ip: str = ""
    description: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_db_alert(self) -> Alert:
        """Convert to database Alert model"""
        return Alert(
            timestamp=self.timestamp,
            alert_type=self.alert_type,
            severity=self.severity.value,
            source_ip=self.source_ip,
            destination_ip=self.destination_ip or None,
            description=self.description,
            details=self.details
        )


@dataclass
class PortScanTracker:
    """Tracks port scanning activity for a source IP"""
    source_ip: str
    target_ports: Set[int] = field(default_factory=set)
    target_ips: Set[str] = field(default_factory=set)
    first_scan_time: datetime = field(default_factory=datetime.now)
    last_scan_time: datetime = field(default_factory=datetime.now)
    scan_count: int = 0
    failed_connections: int = 0
    
    def add_scan_attempt(self, target_ip: str, target_port: int, failed: bool = False):
        """Add a scan attempt to the tracker"""
        self.target_ports.add(target_port)
        self.target_ips.add(target_ip)
        self.last_scan_time = datetime.now()
        self.scan_count += 1
        if failed:
            self.failed_connections += 1


@dataclass
class DDoSTracker:
    """Tracks DDoS attack patterns for a source IP"""
    source_ip: str
    connection_times: deque = field(default_factory=lambda: deque(maxlen=1000))
    packet_count: int = 0
    bytes_sent: int = 0
    target_ips: Set[str] = field(default_factory=set)
    first_seen: datetime = field(default_factory=datetime.now)
    
    def add_connection(self, target_ip: str, packet_size: int):
        """Add a connection attempt to the tracker"""
        current_time = datetime.now()
        self.connection_times.append(current_time)
        self.packet_count += 1
        self.bytes_sent += packet_size
        self.target_ips.add(target_ip)
    
    def get_connection_rate(self, time_window: int = 60) -> float:
        """Get connection rate per second over the specified time window"""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=time_window)
        
        # Count connections within time window
        recent_connections = sum(1 for conn_time in self.connection_times 
                               if conn_time >= cutoff_time)
        
        return recent_connections / time_window if time_window > 0 else 0


class ThreatDetector:
    """
    ThreatDetector class for identifying network attacks and suspicious patterns.
    
    Provides detection for port scanning, DDoS attacks, and suspicious payload patterns
    with configurable thresholds and alert generation.
    """
    
    def __init__(self, 
                 port_scan_threshold: int = None,
                 ddos_threshold: int = None,
                 scan_time_window: int = None,
                 ddos_time_window: int = None):
        """
        Initialize ThreatDetector instance.
        
        Args:
            port_scan_threshold: Number of ports scanned before triggering alert
            ddos_threshold: Connection rate threshold for DDoS detection (per minute)
            scan_time_window: Time window for port scan detection (seconds)
            ddos_time_window: Time window for DDoS detection (seconds)
        """
        # Load thresholds from configuration manager if not provided
        detection_config = config_manager.get_detection_thresholds()
        
        self.port_scan_threshold = port_scan_threshold or detection_config.port_scan_threshold
        self.ddos_threshold = ddos_threshold or detection_config.ddos_threshold
        self.scan_time_window = scan_time_window or detection_config.scan_time_window
        self.ddos_time_window = ddos_time_window or detection_config.ddos_time_window
        
        # Tracking dictionaries
        self.port_scan_trackers: Dict[str, PortScanTracker] = {}
        self.ddos_trackers: Dict[str, DDoSTracker] = {}
        
        # Alert history to prevent duplicate alerts
        self.recent_alerts: Dict[str, datetime] = {}
        self.alert_cooldown = timedelta(minutes=5)  # Minimum time between similar alerts
        
        # Suspicious payload patterns
        self.suspicious_patterns = self._load_suspicious_patterns()
        
        # Custom rules cache
        self.custom_rules_cache = []
        self.custom_rules_last_update = datetime.now()
        self.custom_rules_cache_ttl = timedelta(minutes=5)  # Cache for 5 minutes
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        # Statistics
        self.alerts_generated = 0
        self.packets_analyzed = 0
    
    def _load_suspicious_patterns(self) -> Dict[str, List[str]]:
        """Load suspicious payload patterns for detection"""
        return {
            "sql_injection": [
                r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from)",
                r"(?i)(drop\s+table|create\s+table|alter\s+table)",
                r"(?i)(\'\s*or\s+\d+\s*=\s*\d+|\'\s*or\s+\'.*\'=\')",
                r"(?i)(exec\s*\(|execute\s*\(|sp_executesql)"
            ],
            "xss": [
                r"(?i)(<script[^>]*>|</script>|javascript:|vbscript:)",
                r"(?i)(onload\s*=|onclick\s*=|onerror\s*=|onmouseover\s*=)",
                r"(?i)(alert\s*\(|confirm\s*\(|prompt\s*\()",
                r"(?i)(<iframe[^>]*>|<object[^>]*>|<embed[^>]*>)"
            ],
            "command_injection": [
                r"(?i)(;\s*cat\s+|;\s*ls\s+|;\s*pwd|;\s*id\s*;)",
                r"(?i)(&&\s*cat\s+|&&\s*ls\s+|&&\s*pwd|&&\s*id)",
                r"(?i)(\|\s*cat\s+|\|\s*ls\s+|\|\s*pwd|\|\s*id)",
                r"(?i)(rm\s+-rf|chmod\s+777|wget\s+http|curl\s+http)"
            ],
            "malware_communication": [
                r"(?i)(bot\d+|infected|zombie|backdoor)",
                r"(?i)(c&c|command.*control|botnet)",
                r"(?i)(payload|shellcode|exploit)",
                r"(?i)(trojan|virus|malware|rootkit)"
            ]
        }
    
    def analyze_packet(self, packet_info: PacketInfo) -> List[ThreatAlert]:
        """
        Analyze a packet for potential threats.
        
        Args:
            packet_info: PacketInfo object to analyze
            
        Returns:
            List of ThreatAlert objects for detected threats
        """
        alerts = []
        self.packets_analyzed += 1
        
        try:
            # Check for port scanning
            port_scan_alert = self.detect_port_scan(packet_info)
            if port_scan_alert:
                alerts.append(port_scan_alert)
            
            # Check for DDoS attacks
            ddos_alert = self.detect_ddos(packet_info)
            if ddos_alert:
                alerts.append(ddos_alert)
            
            # Check for suspicious payload patterns
            payload_alert = self.detect_suspicious_payload(packet_info)
            if payload_alert:
                alerts.append(payload_alert)
            
            # Check custom rules
            custom_alerts = self.check_custom_rules(packet_info)
            if custom_alerts:
                alerts.extend(custom_alerts)
            
            # Update statistics
            if alerts:
                self.alerts_generated += len(alerts)
            
            return alerts
            
        except Exception as e:
            self.logger.error(f"Error analyzing packet for threats: {e}")
            return []
    
    def detect_port_scan(self, packet_info: PacketInfo) -> Optional[ThreatAlert]:
        """
        Detect port scanning attempts.
        
        Args:
            packet_info: PacketInfo object to analyze
            
        Returns:
            ThreatAlert if port scan detected, None otherwise
        """
        try:
            # Only analyze TCP SYN packets for port scans
            if packet_info.protocol != "TCP" or "SYN" not in packet_info.tcp_flags:
                return None
            
            source_ip = packet_info.src_ip
            target_ip = packet_info.dst_ip
            target_port = packet_info.dst_port
            
            # Skip if targeting common services (reduce false positives)
            common_ports = {80, 443, 22, 21, 25, 53, 110, 143, 993, 995}
            if target_port in common_ports:
                return None
            
            # Get or create port scan tracker
            if source_ip not in self.port_scan_trackers:
                self.port_scan_trackers[source_ip] = PortScanTracker(source_ip)
            
            tracker = self.port_scan_trackers[source_ip]
            
            # Determine if this is a failed connection (RST or no response expected)
            failed_connection = "RST" in packet_info.tcp_flags
            
            # Add scan attempt
            tracker.add_scan_attempt(target_ip, target_port, failed_connection)
            
            # Check if threshold exceeded
            if len(tracker.target_ports) >= self.port_scan_threshold:
                # Check if we haven't alerted recently for this IP
                alert_key = f"port_scan_{source_ip}"
                if self._should_generate_alert(alert_key):
                    
                    # Determine severity based on scan characteristics
                    severity = self._calculate_port_scan_severity(tracker)
                    
                    alert = ThreatAlert(
                        alert_type=ThreatType.PORT_SCAN.value,
                        severity=severity,
                        source_ip=source_ip,
                        destination_ip=target_ip,
                        description=f"Port scan detected from {source_ip}. "
                                  f"Scanned {len(tracker.target_ports)} ports on "
                                  f"{len(tracker.target_ips)} target(s).",
                        details={
                            "scanned_ports": list(tracker.target_ports)[:20],  # Limit for storage
                            "target_ips": list(tracker.target_ips)[:10],
                            "scan_count": tracker.scan_count,
                            "failed_connections": tracker.failed_connections,
                            "scan_duration": (tracker.last_scan_time - tracker.first_scan_time).total_seconds(),
                            "scan_rate": tracker.scan_count / max(1, (tracker.last_scan_time - tracker.first_scan_time).total_seconds())
                        }
                    )
                    
                    self._record_alert(alert_key)
                    return alert
            
            # Clean up old trackers
            self._cleanup_port_scan_trackers()
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error detecting port scan: {e}")
            return None
    
    def _calculate_port_scan_severity(self, tracker: PortScanTracker) -> AlertSeverity:
        """Calculate severity of port scan based on characteristics"""
        port_count = len(tracker.target_ports)
        target_count = len(tracker.target_ips)
        scan_duration = (tracker.last_scan_time - tracker.first_scan_time).total_seconds()
        scan_rate = tracker.scan_count / max(1, scan_duration)
        
        # Critical: Very fast scan or many targets
        if scan_rate > 10 or target_count > 5 or port_count > 100:
            return AlertSeverity.CRITICAL
        
        # High: Fast scan or multiple targets
        elif scan_rate > 5 or target_count > 2 or port_count > 50:
            return AlertSeverity.HIGH
        
        # Medium: Moderate scanning activity
        elif port_count > 20 or target_count > 1:
            return AlertSeverity.MEDIUM
        
        # Low: Basic port scan
        else:
            return AlertSeverity.LOW
    
    def detect_ddos(self, packet_info: PacketInfo) -> Optional[ThreatAlert]:
        """
        Detect potential DDoS attacks based on connection rate.
        
        Args:
            packet_info: PacketInfo object to analyze
            
        Returns:
            ThreatAlert if DDoS detected, None otherwise
        """
        try:
            source_ip = packet_info.src_ip
            target_ip = packet_info.dst_ip
            
            # Get or create DDoS tracker
            if source_ip not in self.ddos_trackers:
                self.ddos_trackers[source_ip] = DDoSTracker(source_ip)
            
            tracker = self.ddos_trackers[source_ip]
            
            # Add connection attempt
            tracker.add_connection(target_ip, packet_info.size)
            
            # Check connection rate
            connection_rate = tracker.get_connection_rate(self.ddos_time_window)
            
            # Check if threshold exceeded
            if connection_rate > self.ddos_threshold:
                # Check if we haven't alerted recently for this IP
                alert_key = f"ddos_{source_ip}"
                if self._should_generate_alert(alert_key):
                    
                    # Determine severity based on attack characteristics
                    severity = self._calculate_ddos_severity(tracker, connection_rate)
                    
                    alert = ThreatAlert(
                        alert_type=ThreatType.DDOS_ATTACK.value,
                        severity=severity,
                        source_ip=source_ip,
                        description=f"Potential DDoS attack detected from {source_ip}. "
                                  f"Connection rate: {connection_rate:.1f} connections/second.",
                        details={
                            "connection_rate": connection_rate,
                            "total_connections": tracker.packet_count,
                            "bytes_sent": tracker.bytes_sent,
                            "target_count": len(tracker.target_ips),
                            "target_ips": list(tracker.target_ips)[:10],  # Limit for storage
                            "attack_duration": (datetime.now() - tracker.first_seen).total_seconds()
                        }
                    )
                    
                    self._record_alert(alert_key)
                    return alert
            
            # Clean up old trackers
            self._cleanup_ddos_trackers()
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error detecting DDoS: {e}")
            return None
    
    def _calculate_ddos_severity(self, tracker: DDoSTracker, connection_rate: float) -> AlertSeverity:
        """Calculate severity of DDoS attack based on characteristics"""
        target_count = len(tracker.target_ips)
        bytes_per_second = tracker.bytes_sent / max(1, (datetime.now() - tracker.first_seen).total_seconds())
        
        # Critical: Very high rate or bandwidth
        if connection_rate > 500 or bytes_per_second > 10_000_000:  # 10MB/s
            return AlertSeverity.CRITICAL
        
        # High: High rate or multiple targets
        elif connection_rate > 200 or target_count > 10 or bytes_per_second > 1_000_000:  # 1MB/s
            return AlertSeverity.HIGH
        
        # Medium: Moderate attack
        elif connection_rate > 100 or target_count > 3:
            return AlertSeverity.MEDIUM
        
        # Low: Basic flood
        else:
            return AlertSeverity.LOW
    
    def detect_suspicious_payload(self, packet_info: PacketInfo) -> Optional[ThreatAlert]:
        """
        Detect suspicious payload patterns.
        
        Args:
            packet_info: PacketInfo object to analyze
            
        Returns:
            ThreatAlert if suspicious payload detected, None otherwise
        """
        try:
            # Skip if no payload or very small payload
            if packet_info.payload_size < 10:
                return None
            
            # For this implementation, we'll simulate payload analysis
            # In a real implementation, you would extract the actual payload from the packet
            # and analyze it. Here we'll use a simplified approach based on common patterns
            
            # Simulate payload content based on port and protocol
            simulated_payload = self._simulate_payload_content(packet_info)
            
            if not simulated_payload:
                return None
            
            # Check against suspicious patterns
            for category, patterns in self.suspicious_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, simulated_payload):
                        # Check if we haven't alerted recently for this combination
                        alert_key = f"payload_{packet_info.src_ip}_{category}"
                        if self._should_generate_alert(alert_key):
                            
                            severity = self._calculate_payload_severity(category, packet_info)
                            
                            alert = ThreatAlert(
                                alert_type=ThreatType.SUSPICIOUS_PAYLOAD.value,
                                severity=severity,
                                source_ip=packet_info.src_ip,
                                destination_ip=packet_info.dst_ip,
                                description=f"Suspicious {category.replace('_', ' ')} pattern detected "
                                          f"in traffic from {packet_info.src_ip}.",
                                details={
                                    "pattern_category": category,
                                    "target_port": packet_info.dst_port,
                                    "protocol": packet_info.protocol,
                                    "payload_size": packet_info.payload_size,
                                    "matched_pattern": pattern[:100]  # Truncate for storage
                                }
                            )
                            
                            self._record_alert(alert_key)
                            return alert
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error detecting suspicious payload: {e}")
            return None
    
    def _simulate_payload_content(self, packet_info: PacketInfo) -> Optional[str]:
        """
        Simulate payload content based on packet characteristics.
        In a real implementation, this would extract actual payload data.
        """
        # Simulate different types of payloads based on destination port
        if packet_info.dst_port == 80 or packet_info.dst_port == 8080:
            # Simulate HTTP traffic
            if packet_info.payload_size > 100:
                # Simulate potentially malicious HTTP request
                return "GET /index.php?id=1' OR 1=1-- HTTP/1.1"
        elif packet_info.dst_port == 443:
            # HTTPS traffic - encrypted, skip analysis
            return None
        elif packet_info.dst_port == 22:
            # SSH traffic - simulate brute force attempts
            if packet_info.payload_size > 50:
                return "SSH-2.0-OpenSSH_7.4 admin:password123"
        elif packet_info.dst_port in [21, 23, 25]:
            # FTP, Telnet, SMTP - simulate suspicious commands
            return "USER admin\nPASS password\nSYST\n"
        
        return None
    
    def _calculate_payload_severity(self, category: str, packet_info: PacketInfo) -> AlertSeverity:
        """Calculate severity of payload-based threat"""
        # SQL injection and command injection are typically high severity
        if category in ["sql_injection", "command_injection"]:
            return AlertSeverity.HIGH
        
        # XSS can be medium to high depending on context
        elif category == "xss":
            return AlertSeverity.MEDIUM
        
        # Malware communication is critical
        elif category == "malware_communication":
            return AlertSeverity.CRITICAL
        
        # Default to medium
        else:
            return AlertSeverity.MEDIUM
    
    def _should_generate_alert(self, alert_key: str) -> bool:
        """Check if enough time has passed since last alert of this type"""
        if alert_key in self.recent_alerts:
            time_since_last = datetime.now() - self.recent_alerts[alert_key]
            return time_since_last > self.alert_cooldown
        return True
    
    def _record_alert(self, alert_key: str) -> None:
        """Record that an alert was generated"""
        self.recent_alerts[alert_key] = datetime.now()
    
    def _cleanup_port_scan_trackers(self) -> None:
        """Clean up old port scan trackers"""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.scan_time_window)
        
        trackers_to_remove = []
        for ip, tracker in self.port_scan_trackers.items():
            if tracker.last_scan_time < cutoff_time:
                trackers_to_remove.append(ip)
        
        for ip in trackers_to_remove:
            del self.port_scan_trackers[ip]
    
    def _cleanup_ddos_trackers(self) -> None:
        """Clean up old DDoS trackers"""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.ddos_time_window * 2)  # Keep longer for analysis
        
        trackers_to_remove = []
        for ip, tracker in self.ddos_trackers.items():
            if tracker.first_seen < cutoff_time and len(tracker.connection_times) == 0:
                trackers_to_remove.append(ip)
        
        for ip in trackers_to_remove:
            del self.ddos_trackers[ip]
    
    def get_active_threats(self) -> Dict[str, Any]:
        """Get summary of currently active threats"""
        return {
            "active_port_scans": len(self.port_scan_trackers),
            "active_ddos_sources": len(self.ddos_trackers),
            "recent_alerts": len(self.recent_alerts),
            "total_alerts_generated": self.alerts_generated,
            "packets_analyzed": self.packets_analyzed
        }
    
    def get_port_scan_summary(self) -> List[Dict[str, Any]]:
        """Get summary of active port scan activities"""
        summaries = []
        for ip, tracker in self.port_scan_trackers.items():
            summaries.append({
                "source_ip": ip,
                "ports_scanned": len(tracker.target_ports),
                "targets": len(tracker.target_ips),
                "scan_count": tracker.scan_count,
                "duration": (tracker.last_scan_time - tracker.first_scan_time).total_seconds(),
                "last_activity": tracker.last_scan_time.isoformat()
            })
        return summaries
    
    def get_ddos_summary(self) -> List[Dict[str, Any]]:
        """Get summary of active DDoS activities"""
        summaries = []
        for ip, tracker in self.ddos_trackers.items():
            summaries.append({
                "source_ip": ip,
                "connection_rate": tracker.get_connection_rate(self.ddos_time_window),
                "total_connections": tracker.packet_count,
                "bytes_sent": tracker.bytes_sent,
                "target_count": len(tracker.target_ips),
                "duration": (datetime.now() - tracker.first_seen).total_seconds()
            })
        return summaries
    
    def check_custom_rules(self, packet_info: PacketInfo) -> List[ThreatAlert]:
        """
        Check packet against custom threat detection rules.
        
        Args:
            packet_info: PacketInfo object to analyze
            
        Returns:
            List of ThreatAlert objects for matched custom rules
        """
        alerts = []
        
        try:
            # Update custom rules cache if needed
            self._update_custom_rules_cache()
            
            # Check each custom rule
            for rule in self.custom_rules_cache:
                if not rule.enabled:
                    continue
                
                # Check protocol filter
                if rule.protocol != "any" and rule.protocol.lower() != packet_info.protocol.lower():
                    continue
                
                # Check port filter
                if rule.ports and packet_info.dst_port not in rule.ports:
                    continue
                
                # Get simulated payload for pattern matching
                payload = self._simulate_payload_content(packet_info)
                if not payload:
                    continue
                
                # Check pattern match
                if self._check_rule_pattern(rule, payload):
                    # Check if we haven't alerted recently for this rule
                    alert_key = f"custom_rule_{rule.name}_{packet_info.src_ip}"
                    if self._should_generate_alert(alert_key):
                        
                        # Convert severity string to AlertSeverity enum
                        severity = AlertSeverity(rule.severity)
                        
                        alert = ThreatAlert(
                            alert_type=f"Custom Rule: {rule.name}",
                            severity=severity,
                            source_ip=packet_info.src_ip,
                            destination_ip=packet_info.dst_ip,
                            description=f"Custom rule '{rule.name}' triggered: {rule.description}",
                            details={
                                "rule_name": rule.name,
                                "rule_description": rule.description,
                                "pattern_type": rule.pattern_type,
                                "matched_pattern": rule.pattern[:100],  # Truncate for storage
                                "target_port": packet_info.dst_port,
                                "protocol": packet_info.protocol,
                                "payload_size": packet_info.payload_size
                            }
                        )
                        
                        self._record_alert(alert_key)
                        alerts.append(alert)
            
            return alerts
            
        except Exception as e:
            self.logger.error(f"Error checking custom rules: {e}")
            return []
    
    def _update_custom_rules_cache(self) -> None:
        """Update custom rules cache if TTL expired"""
        try:
            current_time = datetime.now()
            if current_time - self.custom_rules_last_update > self.custom_rules_cache_ttl:
                self.custom_rules_cache = config_manager.get_custom_rules(enabled_only=True)
                self.custom_rules_last_update = current_time
                self.logger.debug(f"Updated custom rules cache: {len(self.custom_rules_cache)} rules")
        except Exception as e:
            self.logger.error(f"Error updating custom rules cache: {e}")
    
    def _check_rule_pattern(self, rule, payload: str) -> bool:
        """
        Check if payload matches rule pattern.
        
        Args:
            rule: CustomRule object
            payload: Payload string to check
            
        Returns:
            True if pattern matches, False otherwise
        """
        try:
            if rule.pattern_type == "regex":
                return bool(re.search(rule.pattern, payload, re.IGNORECASE))
            elif rule.pattern_type == "string":
                return rule.pattern.lower() in payload.lower()
            elif rule.pattern_type == "bytes":
                # For bytes pattern, convert to hex representation
                try:
                    pattern_bytes = bytes.fromhex(rule.pattern.replace(" ", ""))
                    payload_bytes = payload.encode('utf-8', errors='ignore')
                    return pattern_bytes in payload_bytes
                except ValueError:
                    self.logger.warning(f"Invalid bytes pattern in rule {rule.name}: {rule.pattern}")
                    return False
            else:
                self.logger.warning(f"Unknown pattern type in rule {rule.name}: {rule.pattern_type}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error checking pattern for rule {rule.name}: {e}")
            return False
    
    def update_thresholds_from_config(self) -> None:
        """Update detection thresholds from configuration manager"""
        try:
            detection_config = config_manager.get_detection_thresholds()
            
            self.port_scan_threshold = detection_config.port_scan_threshold
            self.ddos_threshold = detection_config.ddos_threshold
            self.scan_time_window = detection_config.scan_time_window
            self.ddos_time_window = detection_config.ddos_time_window
            
            self.logger.info("Updated detection thresholds from configuration")
            
        except Exception as e:
            self.logger.error(f"Error updating thresholds from config: {e}")
    
    def reset_trackers(self) -> None:
        """Reset all threat trackers and statistics"""
        self.port_scan_trackers.clear()
        self.ddos_trackers.clear()
        self.recent_alerts.clear()
        self.alerts_generated = 0
        self.packets_analyzed = 0
        self.custom_rules_cache.clear()
        self.custom_rules_last_update = datetime.now()
        self.logger.info("Threat detector trackers reset")


if __name__ == "__main__":
    # Simple test of threat detector functionality
    print("SpyNet Threat Detector Test")
    print("=" * 30)
    
    # Create detector instance
    detector = ThreatDetector()
    
    print("Threat detector initialized successfully")
    print(f"Detection thresholds: Port scan={detector.port_scan_threshold}, DDoS={detector.ddos_threshold}")
    print(f"Active threats: {detector.get_active_threats()}")