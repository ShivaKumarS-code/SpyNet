"""
SpyNet Threat Detection Integration Module

This module integrates the threat detection engine with the packet analyzer
to provide a complete threat detection pipeline.
"""

import logging
from typing import List, Optional, Dict, Any
from datetime import datetime

from packet_analyzer import PacketAnalyzer, PacketInfo
from threat_detector import ThreatDetector, ThreatAlert
from anomaly_detector import AnomalyDetector
from alert_manager import AlertManager
from config import settings


class ThreatDetectionPipeline:
    """
    Integrated threat detection pipeline that combines packet analysis,
    threat detection, and alert management.
    """
    
    def __init__(self, 
                 port_scan_threshold: Optional[int] = None,
                 ddos_threshold: Optional[int] = None,

                 critical_alerts_only: bool = False,
                 enable_anomaly_detection: bool = True,
                 anomaly_threshold: float = -0.5):
        """
        Initialize the threat detection pipeline.
        
        Args:
            port_scan_threshold: Port scan detection threshold
            ddos_threshold: DDoS detection threshold  

            critical_alerts_only: Whether to send only critical alert notifications
            enable_anomaly_detection: Whether to enable ML-based anomaly detection
            anomaly_threshold: Threshold for anomaly score classification
        """
        # Use settings defaults if not provided
        self.port_scan_threshold = port_scan_threshold or settings.port_scan_threshold
        self.ddos_threshold = ddos_threshold or settings.ddos_threshold
        self.enable_anomaly_detection = enable_anomaly_detection
        
        # Initialize components
        self.packet_analyzer = PacketAnalyzer()
        self.threat_detector = ThreatDetector(
            port_scan_threshold=self.port_scan_threshold,
            ddos_threshold=self.ddos_threshold
        )
        self.anomaly_detector = AnomalyDetector(
            anomaly_threshold=anomaly_threshold
        ) if enable_anomaly_detection else None
        self.alert_manager = AlertManager()
        
        # Pipeline statistics
        self.packets_processed = 0
        self.threats_detected = 0
        self.alerts_generated = 0
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        self.logger.info(f"Threat detection pipeline initialized with thresholds: "
                        f"port_scan={self.port_scan_threshold}, ddos={self.ddos_threshold}, "
                        f"anomaly_detection={'enabled' if enable_anomaly_detection else 'disabled'}")
    
    def process_packet(self, packet) -> List[ThreatAlert]:
        """
        Process a single packet through the complete threat detection pipeline.
        
        Args:
            packet: Scapy packet object to process
            
        Returns:
            List of ThreatAlert objects for any detected threats
        """
        try:
            self.packets_processed += 1
            
            # Step 1: Analyze packet to extract information
            packet_info = self.packet_analyzer.analyze_packet(packet)
            if not packet_info:
                return []
            
            # Step 2: Track connections
            self.packet_analyzer.track_connections(packet_info)
            
            # Step 3: Analyze for threats
            threat_alerts = self.threat_detector.analyze_packet(packet_info)
            
            # Step 4: Check for anomalies if enabled
            if self.anomaly_detector:
                anomaly_alert = self.anomaly_detector.detect_anomaly(packet_info)
                if anomaly_alert:
                    threat_alerts.append(anomaly_alert)
            
            # Step 5: Process any alerts
            processed_alerts = []
            for alert in threat_alerts:
                success = self.alert_manager.process_alert(alert)
                if success:
                    processed_alerts.append(alert)
                    self.alerts_generated += 1
            
            if processed_alerts:
                self.threats_detected += 1
                self.logger.info(f"Processed {len(processed_alerts)} alerts for packet from {packet_info.src_ip}")
            
            return processed_alerts
            
        except Exception as e:
            self.logger.error(f"Error processing packet in threat detection pipeline: {e}")
            return []
    
    def process_packet_batch(self, packets: List) -> List[ThreatAlert]:
        """
        Process a batch of packets through the threat detection pipeline.
        
        Args:
            packets: List of Scapy packet objects to process
            
        Returns:
            List of all ThreatAlert objects detected in the batch
        """
        all_alerts = []
        
        for packet in packets:
            alerts = self.process_packet(packet)
            all_alerts.extend(alerts)
        
        if all_alerts:
            self.logger.info(f"Processed batch of {len(packets)} packets, "
                           f"generated {len(all_alerts)} alerts")
        
        return all_alerts
    
    def get_pipeline_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive statistics from all pipeline components.
        
        Returns:
            Dictionary containing pipeline statistics
        """
        analyzer_stats = self.packet_analyzer.get_analyzer_statistics()
        threat_stats = self.threat_detector.get_active_threats()
        alert_stats = self.alert_manager.get_alert_statistics()
        anomaly_stats = self.anomaly_detector.get_anomaly_statistics() if self.anomaly_detector else {}
        
        return {
            "pipeline": {
                "packets_processed": self.packets_processed,
                "threats_detected": self.threats_detected,
                "alerts_generated": self.alerts_generated,
                "detection_rate": (self.threats_detected / max(1, self.packets_processed)) * 100,
                "anomaly_detection_enabled": self.anomaly_detector is not None
            },
            "packet_analyzer": analyzer_stats,
            "threat_detector": threat_stats,
            "anomaly_detector": anomaly_stats,
            "alert_manager": alert_stats.get("manager_stats", {}),
            "recent_alert_summary": {
                "total_alerts": alert_stats.get("total_alerts", 0),
                "severity_distribution": alert_stats.get("severity_distribution", {}),
                "type_distribution": alert_stats.get("type_distribution", {})
            }
        }
    
    def get_active_threats_summary(self) -> Dict[str, Any]:
        """
        Get summary of currently active threats.
        
        Returns:
            Dictionary containing active threat information
        """
        port_scans = self.threat_detector.get_port_scan_summary()
        ddos_attacks = self.threat_detector.get_ddos_summary()
        top_talkers = self.packet_analyzer.get_top_talkers(limit=10)
        
        return {
            "active_port_scans": port_scans,
            "active_ddos_attacks": ddos_attacks,
            "top_talkers": [{"ip": ip, "packets": count} for ip, count in top_talkers],
            "connection_count": self.packet_analyzer.get_connection_count(),
            "protocol_distribution": self.packet_analyzer.get_protocol_statistics()
        }
    
    def get_recent_alerts(self, limit: int = 50, severity_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get recent alerts with simplified format for API responses.
        
        Args:
            limit: Maximum number of alerts to return
            severity_filter: Filter by severity level
            
        Returns:
            List of alert dictionaries
        """
        db_alerts = self.alert_manager.get_recent_alerts(limit=limit, severity_filter=severity_filter)
        
        alerts = []
        for alert in db_alerts:
            alerts.append({
                "id": alert.id,
                "timestamp": alert.timestamp.isoformat(),
                "type": alert.alert_type,
                "severity": alert.severity,
                "source_ip": alert.source_ip,
                "destination_ip": alert.destination_ip,
                "description": alert.description,
                "details": alert.details,
                "resolved": alert.resolved
            })
        
        return alerts
    
    def resolve_alert(self, alert_id: int, resolved_by: str = "user") -> bool:
        """
        Mark an alert as resolved.
        
        Args:
            alert_id: ID of alert to resolve
            resolved_by: Who resolved the alert
            
        Returns:
            True if successful, False otherwise
        """
        return self.alert_manager.mark_alert_resolved(alert_id, resolved_by)
    
    def update_detection_thresholds(self, 
                                  port_scan_threshold: Optional[int] = None,
                                  ddos_threshold: Optional[int] = None,
                                  anomaly_threshold: Optional[float] = None) -> None:
        """
        Update detection thresholds dynamically.
        
        Args:
            port_scan_threshold: New port scan threshold
            ddos_threshold: New DDoS threshold
            anomaly_threshold: New anomaly detection threshold
        """
        if port_scan_threshold is not None:
            self.threat_detector.port_scan_threshold = port_scan_threshold
            self.port_scan_threshold = port_scan_threshold
            self.logger.info(f"Updated port scan threshold to {port_scan_threshold}")
        
        if ddos_threshold is not None:
            self.threat_detector.ddos_threshold = ddos_threshold
            self.ddos_threshold = ddos_threshold
            self.logger.info(f"Updated DDoS threshold to {ddos_threshold}")
        
        if anomaly_threshold is not None and self.anomaly_detector:
            self.anomaly_detector.anomaly_threshold = anomaly_threshold
            self.logger.info(f"Updated anomaly threshold to {anomaly_threshold}")
    
    def train_anomaly_baseline(self, training_packets: List) -> bool:
        """
        Train the anomaly detection baseline with normal traffic data.
        
        Args:
            training_packets: List of Scapy packet objects representing normal traffic
            
        Returns:
            True if training was successful, False otherwise
        """
        if not self.anomaly_detector:
            self.logger.warning("Anomaly detection is not enabled")
            return False
        
        try:
            # Convert packets to PacketInfo objects
            packet_infos = []
            for packet in training_packets:
                packet_info = self.packet_analyzer.analyze_packet(packet)
                if packet_info:
                    packet_infos.append(packet_info)
            
            if not packet_infos:
                self.logger.warning("No valid packets found for training")
                return False
            
            # Train the baseline
            self.anomaly_detector.learn_baseline(packet_infos)
            self.logger.info(f"Anomaly baseline trained with {len(packet_infos)} packets")
            return True
            
        except Exception as e:
            self.logger.error(f"Error training anomaly baseline: {e}")
            return False
    
    def update_anomaly_baseline(self, new_normal_packets: List) -> bool:
        """
        Update the anomaly detection baseline with new normal traffic data.
        
        Args:
            new_normal_packets: List of new normal traffic packets
            
        Returns:
            True if update was successful, False otherwise
        """
        if not self.anomaly_detector:
            return False
        
        try:
            # Convert packets to PacketInfo objects
            packet_infos = []
            for packet in new_normal_packets:
                packet_info = self.packet_analyzer.analyze_packet(packet)
                if packet_info:
                    packet_infos.append(packet_info)
            
            if packet_infos:
                self.anomaly_detector.update_baseline(packet_infos)
                self.logger.info(f"Anomaly baseline updated with {len(packet_infos)} new packets")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error updating anomaly baseline: {e}")
            return False
    
    def get_recent_anomalies(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent anomaly detections.
        
        Args:
            limit: Maximum number of anomalies to return
            
        Returns:
            List of recent anomaly dictionaries
        """
        if not self.anomaly_detector:
            return []
        
        return self.anomaly_detector.get_recent_anomalies(limit)
    
    def mark_anomaly_false_positive(self, anomaly_timestamp: str, source_ip: str) -> bool:
        """
        Mark an anomaly as a false positive for model improvement.
        
        Args:
            anomaly_timestamp: ISO timestamp of the anomaly
            source_ip: Source IP of the anomaly
            
        Returns:
            True if successful, False otherwise
        """
        if not self.anomaly_detector:
            return False
        
        try:
            timestamp = datetime.fromisoformat(anomaly_timestamp.replace('Z', '+00:00'))
            self.anomaly_detector.mark_false_positive(timestamp, source_ip)
            return True
        except Exception as e:
            self.logger.error(f"Error marking false positive: {e}")
            return False
    
    def reset_pipeline(self) -> None:
        """Reset all pipeline components and statistics"""
        self.packet_analyzer.reset_statistics()
        self.threat_detector.reset_trackers()
        
        if self.anomaly_detector:
            self.anomaly_detector.reset_detector()
        
        self.packets_processed = 0
        self.threats_detected = 0
        self.alerts_generated = 0
        
        self.logger.info("Threat detection pipeline reset")
    
    def cleanup_old_data(self, days: int = 30) -> Dict[str, int]:
        """
        Clean up old data from all components.
        
        Args:
            days: Number of days of data to keep
            
        Returns:
            Dictionary with cleanup statistics
        """
        alerts_deleted = self.alert_manager.cleanup_old_alerts(days)
        
        # Reset trackers to clean up memory
        self.threat_detector.reset_trackers()
        self.packet_analyzer.reset_statistics()
        
        cleanup_stats = {
            "alerts_deleted": alerts_deleted,
            "trackers_reset": True
        }
        
        self.logger.info(f"Cleanup completed: {cleanup_stats}")
        return cleanup_stats


# Global pipeline instance for use across the application
threat_pipeline = None


def get_threat_pipeline() -> ThreatDetectionPipeline:
    """
    Get or create the global threat detection pipeline instance.
    
    Returns:
        ThreatDetectionPipeline instance
    """
    global threat_pipeline
    
    if threat_pipeline is None:
        threat_pipeline = ThreatDetectionPipeline()
    
    return threat_pipeline


def initialize_threat_pipeline(**kwargs) -> ThreatDetectionPipeline:
    """
    Initialize the global threat detection pipeline with custom settings.
    
    Args:
        **kwargs: Configuration parameters for the pipeline
        
    Returns:
        ThreatDetectionPipeline instance
    """
    global threat_pipeline
    
    threat_pipeline = ThreatDetectionPipeline(**kwargs)
    return threat_pipeline


if __name__ == "__main__":
    # Simple test of threat detection pipeline
    print("SpyNet Threat Detection Pipeline Test")
    print("=" * 40)
    
    # Initialize pipeline
    pipeline = ThreatDetectionPipeline(
        port_scan_threshold=5,
        ddos_threshold=10,

    )
    
    print("Pipeline initialized successfully")
    print(f"Initial statistics: {pipeline.get_pipeline_statistics()}")
    
    # Test with some sample packet data
    from test_threat_detection import create_test_packet
    
    # Create test packets
    test_packets = []
    
    # Add some normal traffic
    for i in range(5):
        packet_info = create_test_packet(
            src_ip="192.168.1.50",
            dst_ip="192.168.1.10", 
            src_port=12345,
            dst_port=80,
            tcp_flags="ACK"
        )
        # Note: process_packet expects Scapy packet, but for testing we'll simulate
        # by directly calling the analyzer
        pipeline.packet_analyzer.analyze_packet(packet_info)
        pipeline.packet_analyzer.track_connections(packet_info)
    
    print(f"Final statistics: {pipeline.get_pipeline_statistics()}")
    print(f"Active threats: {pipeline.get_active_threats_summary()}")