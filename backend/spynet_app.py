"""
SpyNet Main Application

This module implements the main SpyNet application class that coordinates all components
including packet capture, analysis, threat detection, anomaly detection, and alert management.
"""

import asyncio
import logging
import signal
import sys
import threading
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from pathlib import Path
import argparse
import json

from packet_capture import PacketCapture
from packet_analyzer import PacketAnalyzer
from threat_detector import ThreatDetector
from anomaly_detector import AnomalyDetector
from alert_manager import AlertManager
from config import settings
from models import db_manager
from config_manager import config_manager


class SpyNetApp:
    """
    Main SpyNet application class that coordinates all system components.
    
    Provides centralized control for packet capture, analysis, threat detection,
    anomaly detection, and alert management with proper startup/shutdown procedures.
    """
    
    def __init__(self, config_override: Optional[Dict[str, Any]] = None):
        """
        Initialize SpyNet application.
        
        Args:
            config_override: Optional configuration overrides
        """
        self.config = config_override or {}
        self.running = False
        self.startup_time = None
        
        # Component instances
        self.packet_capture: Optional[PacketCapture] = None
        self.packet_analyzer: Optional[PacketAnalyzer] = None
        self.threat_detector: Optional[ThreatDetector] = None
        self.anomaly_detector: Optional[AnomalyDetector] = None
        self.alert_manager: Optional[AlertManager] = None
        
        # Processing threads
        self.analysis_thread: Optional[threading.Thread] = None
        self.stats_thread: Optional[threading.Thread] = None
        
        # Statistics and monitoring
        self.stats = {
            "packets_captured": 0,
            "packets_analyzed": 0,
            "threats_detected": 0,
            "anomalies_detected": 0,
            "alerts_generated": 0,
            "uptime_seconds": 0,
            "last_packet_time": None,
            "processing_rate": 0.0
        }
        
        # Setup logging
        self.logger = self._setup_logging()
        
        # Initialize components
        self._initialize_components()
        
        # Setup signal handlers for graceful shutdown
        self._setup_signal_handlers()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup application logging"""
        try:
            # Create logs directory
            log_dir = Path("logs")
            log_dir.mkdir(exist_ok=True)
            
            # Configure root logger
            logging.basicConfig(
                level=getattr(logging, self.config.get("log_level", settings.log_level).upper()),
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(log_dir / "spynet_main.log"),
                    logging.StreamHandler(sys.stdout)
                ]
            )
            
            logger = logging.getLogger("spynet.main")
            logger.info("SpyNet logging initialized")
            return logger
            
        except Exception as e:
            print(f"Error setting up logging: {e}")
            return logging.getLogger("spynet.main")
    
    def _initialize_components(self) -> None:
        """Initialize all SpyNet components"""
        try:
            self.logger.info("Initializing SpyNet components...")
            
            # Get configuration from config manager
            interface_config = config_manager.get_interface_configuration()
            detection_config = config_manager.get_detection_thresholds()
            alert_config = config_manager.get_alert_configuration()
            
            # Initialize packet capture
            interface = self.config.get("capture_interface", interface_config.capture_interface)
            buffer_size = self.config.get("packet_buffer_size", interface_config.packet_buffer_size)
            self.packet_capture = PacketCapture(interface=interface, buffer_size=buffer_size)
            
            # Initialize packet analyzer
            connection_timeout = self.config.get("connection_timeout", detection_config.connection_timeout)
            self.packet_analyzer = PacketAnalyzer(connection_timeout=connection_timeout)
            
            # Initialize threat detector with configuration manager integration
            self.threat_detector = ThreatDetector()
            
            # Initialize anomaly detector
            contamination = self.config.get("anomaly_contamination", detection_config.anomaly_contamination)
            self.anomaly_detector = AnomalyDetector(contamination=contamination)
            
            # Initialize alert manager
            self.alert_manager = AlertManager(
                log_file="logs/alerts.log"
            )
            
            # Register configuration change callback
            config_manager.register_change_callback(self._on_configuration_changed)
            
            self.logger.info("All components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing components: {e}")
            raise
    

    
    def _on_configuration_changed(self, new_config) -> None:
        """Handle configuration changes"""
        try:
            self.logger.info("Configuration changed, updating components...")
            
            # Update threat detector thresholds
            if self.threat_detector:
                self.threat_detector.update_thresholds_from_config()
            
            # Update anomaly detector contamination
            if self.anomaly_detector:
                detection_config = config_manager.get_detection_thresholds()
                self.anomaly_detector.contamination = detection_config.anomaly_contamination
            
            # Update alert manager configuration
            if self.alert_manager:
                self.alert_manager.update_configuration()
            
            self.logger.info("Components updated with new configuration")
            
        except Exception as e:
            self.logger.error(f"Error updating components with new configuration: {e}")
    
    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown"""
        try:
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            self.logger.info("Signal handlers configured")
        except Exception as e:
            self.logger.warning(f"Could not setup signal handlers: {e}")
    
    def _signal_handler(self, signum: int, frame) -> None:
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        self.stop()
    
    def start(self) -> bool:
        """
        Start the SpyNet application and all components.
        
        Returns:
            True if started successfully, False otherwise
        """
        try:
            if self.running:
                self.logger.warning("SpyNet is already running")
                return False
            
            self.logger.info("Starting SpyNet Network Intrusion Detection System...")
            self.startup_time = datetime.now()
            
            # Initialize database
            if not self._initialize_database():
                self.logger.error("Failed to initialize database")
                return False
            
            # Start packet capture
            if not self.packet_capture.start_capture():
                self.logger.error("Failed to start packet capture")
                return False
            
            # Start analysis thread
            self.running = True
            self.analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
            self.analysis_thread.start()
            
            # Start statistics thread
            self.stats_thread = threading.Thread(target=self._stats_loop, daemon=True)
            self.stats_thread.start()
            
            self.logger.info("SpyNet started successfully")
            self.logger.info(f"Monitoring interface: {self.packet_capture.interface}")
            self.logger.info(f"Detection thresholds - Port scan: {self.threat_detector.port_scan_threshold}, "
                           f"DDoS: {self.threat_detector.ddos_threshold}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting SpyNet: {e}")
            self.stop()
            return False
    
    def _initialize_database(self) -> bool:
        """Initialize database connection and tables"""
        try:
            self.logger.info("Initializing database...")
            
            # Test database connection and create tables
            db_manager.create_tables()
            
            # Test database operations
            session = db_manager.get_session()
            try:
                # Simple query to test connection
                from sqlalchemy import text
                session.execute(text("SELECT 1"))
                session.commit()
                self.logger.info("Database connection established")
                return True
            except Exception as e:
                self.logger.error(f"Database connection test failed: {e}")
                return False
            finally:
                session.close()
                
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
            return False
    
    def _analysis_loop(self) -> None:
        """Main packet analysis loop running in separate thread"""
        self.logger.info("Starting packet analysis loop...")
        
        last_stats_time = time.time()
        packets_processed_since_last = 0
        
        try:
            while self.running:
                try:
                    # Get packet from capture queue
                    captured_packet = self.packet_capture.get_packet_blocking(timeout=1.0)
                    
                    if captured_packet is None:
                        continue
                    
                    # Update statistics
                    self.stats["packets_captured"] += 1
                    self.stats["last_packet_time"] = captured_packet.timestamp
                    
                    # Analyze packet
                    packet_info = self.packet_analyzer.analyze_packet(captured_packet.raw_packet)
                    
                    if packet_info is None:
                        continue
                    
                    self.stats["packets_analyzed"] += 1
                    packets_processed_since_last += 1
                    
                    # Track connections
                    self.packet_analyzer.track_connections(packet_info)
                    
                    # Detect threats
                    threat_alerts = self.threat_detector.analyze_packet(packet_info)
                    
                    # Detect anomalies
                    anomaly_alert = self.anomaly_detector.detect_anomaly(packet_info)
                    if anomaly_alert:
                        threat_alerts.append(anomaly_alert)
                        self.stats["anomalies_detected"] += 1
                    
                    # Process alerts
                    if threat_alerts:
                        self.stats["threats_detected"] += len(threat_alerts)
                        for alert in threat_alerts:
                            if self.alert_manager.process_alert(alert):
                                self.stats["alerts_generated"] += 1
                    
                    # Calculate processing rate periodically
                    current_time = time.time()
                    if current_time - last_stats_time >= 60:  # Every minute
                        time_elapsed = current_time - last_stats_time
                        self.stats["processing_rate"] = packets_processed_since_last / time_elapsed
                        last_stats_time = current_time
                        packets_processed_since_last = 0
                    
                except Exception as e:
                    self.logger.error(f"Error in analysis loop: {e}")
                    time.sleep(1)  # Brief pause on error
                    
        except Exception as e:
            self.logger.error(f"Fatal error in analysis loop: {e}")
        finally:
            self.logger.info("Packet analysis loop stopped")
    
    def _stats_loop(self) -> None:
        """Statistics monitoring loop"""
        self.logger.info("Starting statistics monitoring loop...")
        
        try:
            while self.running:
                try:
                    # Update uptime
                    if self.startup_time:
                        self.stats["uptime_seconds"] = (datetime.now() - self.startup_time).total_seconds()
                    
                    # Log periodic statistics
                    if self.stats["packets_analyzed"] > 0 and self.stats["packets_analyzed"] % 1000 == 0:
                        self._log_statistics()
                    
                    # Sleep for 30 seconds
                    time.sleep(30)
                    
                except Exception as e:
                    self.logger.error(f"Error in stats loop: {e}")
                    time.sleep(30)
                    
        except Exception as e:
            self.logger.error(f"Fatal error in stats loop: {e}")
        finally:
            self.logger.info("Statistics monitoring loop stopped")
    
    def _log_statistics(self) -> None:
        """Log current system statistics"""
        try:
            uptime_hours = self.stats["uptime_seconds"] / 3600
            
            self.logger.info(f"SpyNet Statistics - Uptime: {uptime_hours:.1f}h, "
                           f"Packets: {self.stats['packets_analyzed']}, "
                           f"Threats: {self.stats['threats_detected']}, "
                           f"Alerts: {self.stats['alerts_generated']}, "
                           f"Rate: {self.stats['processing_rate']:.1f} pkt/s")
            
        except Exception as e:
            self.logger.error(f"Error logging statistics: {e}")
    
    def stop(self) -> None:
        """Stop the SpyNet application and all components gracefully"""
        try:
            if not self.running:
                self.logger.warning("SpyNet is not running")
                return
            
            self.logger.info("Stopping SpyNet...")
            self.running = False
            
            # Stop packet capture
            if self.packet_capture:
                self.packet_capture.stop_capture()
            
            # Wait for threads to finish
            if self.analysis_thread and self.analysis_thread.is_alive():
                self.logger.info("Waiting for analysis thread to finish...")
                self.analysis_thread.join(timeout=10)
            
            if self.stats_thread and self.stats_thread.is_alive():
                self.logger.info("Waiting for stats thread to finish...")
                self.stats_thread.join(timeout=5)
            
            # Log final statistics
            self._log_final_statistics()
            
            self.logger.info("SpyNet stopped successfully")
            
        except Exception as e:
            self.logger.error(f"Error stopping SpyNet: {e}")
    
    def _log_final_statistics(self) -> None:
        """Log final statistics on shutdown"""
        try:
            uptime_hours = self.stats["uptime_seconds"] / 3600
            
            self.logger.info("=== SpyNet Final Statistics ===")
            self.logger.info(f"Total uptime: {uptime_hours:.2f} hours")
            self.logger.info(f"Packets captured: {self.stats['packets_captured']}")
            self.logger.info(f"Packets analyzed: {self.stats['packets_analyzed']}")
            self.logger.info(f"Threats detected: {self.stats['threats_detected']}")
            self.logger.info(f"Anomalies detected: {self.stats['anomalies_detected']}")
            self.logger.info(f"Alerts generated: {self.stats['alerts_generated']}")
            
            if self.stats['packets_analyzed'] > 0:
                avg_rate = self.stats['packets_analyzed'] / max(1, self.stats['uptime_seconds'])
                self.logger.info(f"Average processing rate: {avg_rate:.2f} packets/second")
            
            # Component statistics
            if self.packet_capture:
                capture_stats = self.packet_capture.get_statistics()
                self.logger.info(f"Packet capture stats: {capture_stats}")
            
            if self.threat_detector:
                threat_stats = self.threat_detector.get_active_threats()
                self.logger.info(f"Threat detector stats: {threat_stats}")
            
            if self.anomaly_detector:
                anomaly_stats = self.anomaly_detector.get_anomaly_statistics()
                self.logger.info(f"Anomaly detector stats: {anomaly_stats}")
            
        except Exception as e:
            self.logger.error(f"Error logging final statistics: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get current system status and statistics.
        
        Returns:
            Dictionary containing system status information
        """
        try:
            status = {
                "running": self.running,
                "startup_time": self.startup_time.isoformat() if self.startup_time else None,
                "uptime_seconds": self.stats["uptime_seconds"],
                "statistics": self.stats.copy(),
                "components": {
                    "packet_capture": {
                        "running": self.packet_capture.is_running() if self.packet_capture else False,
                        "interface": self.packet_capture.interface if self.packet_capture else None,
                        "stats": self.packet_capture.get_statistics() if self.packet_capture else {}
                    },
                    "packet_analyzer": {
                        "active_connections": self.packet_analyzer.get_connection_count() if self.packet_analyzer else 0,
                        "stats": self.packet_analyzer.get_analyzer_statistics() if self.packet_analyzer else {}
                    },
                    "threat_detector": {
                        "active_threats": self.threat_detector.get_active_threats() if self.threat_detector else {},
                        "port_scans": len(self.threat_detector.port_scan_trackers) if self.threat_detector else 0,
                        "ddos_sources": len(self.threat_detector.ddos_trackers) if self.threat_detector else 0
                    },
                    "anomaly_detector": {
                        "model_trained": self.anomaly_detector.trained if self.anomaly_detector else False,
                        "stats": self.anomaly_detector.get_anomaly_statistics() if self.anomaly_detector else {}
                    },
                    "alert_manager": {
                        "alerts_processed": self.alert_manager.alerts_processed if self.alert_manager else 0,
                        "notifications_sent": self.alert_manager.notifications_sent if self.alert_manager else 0
                    }
                }
            }
            
            return status
            
        except Exception as e:
            self.logger.error(f"Error getting system status: {e}")
            return {"error": str(e)}
    
    def get_recent_activity(self, minutes: int = 60) -> Dict[str, Any]:
        """
        Get recent system activity summary.
        
        Args:
            minutes: Time window in minutes
            
        Returns:
            Dictionary containing recent activity information
        """
        try:
            activity = {
                "time_window_minutes": minutes,
                "timestamp": datetime.now().isoformat(),
                "packet_analysis": {
                    "packets_processed": self.stats["packets_analyzed"],
                    "processing_rate": self.stats["processing_rate"],
                    "last_packet": self.stats["last_packet_time"].isoformat() if self.stats["last_packet_time"] else None
                },
                "threat_detection": {
                    "threats_detected": self.stats["threats_detected"],
                    "active_port_scans": len(self.threat_detector.port_scan_trackers) if self.threat_detector else 0,
                    "active_ddos_sources": len(self.threat_detector.ddos_trackers) if self.threat_detector else 0,
                    "port_scan_summary": self.threat_detector.get_port_scan_summary() if self.threat_detector else [],
                    "ddos_summary": self.threat_detector.get_ddos_summary() if self.threat_detector else []
                },
                "anomaly_detection": {
                    "anomalies_detected": self.stats["anomalies_detected"],
                    "recent_anomalies": self.anomaly_detector.get_recent_anomalies(10) if self.anomaly_detector else []
                },
                "network_analysis": {
                    "active_connections": self.packet_analyzer.get_connection_count() if self.packet_analyzer else 0,
                    "top_talkers": self.packet_analyzer.get_top_talkers(10) if self.packet_analyzer else [],
                    "protocol_stats": self.packet_analyzer.get_protocol_statistics() if self.packet_analyzer else {}
                }
            }
            
            return activity
            
        except Exception as e:
            self.logger.error(f"Error getting recent activity: {e}")
            return {"error": str(e)}
    
    def configure_detection_thresholds(self, **kwargs) -> bool:
        """
        Configure detection thresholds dynamically.
        
        Args:
            **kwargs: Threshold parameters to update
            
        Returns:
            True if configuration updated successfully
        """
        try:
            updated = False
            
            if "port_scan_threshold" in kwargs and self.threat_detector:
                self.threat_detector.port_scan_threshold = kwargs["port_scan_threshold"]
                updated = True
                self.logger.info(f"Port scan threshold updated to {kwargs['port_scan_threshold']}")
            
            if "ddos_threshold" in kwargs and self.threat_detector:
                self.threat_detector.ddos_threshold = kwargs["ddos_threshold"]
                updated = True
                self.logger.info(f"DDoS threshold updated to {kwargs['ddos_threshold']}")
            
            if "anomaly_contamination" in kwargs and self.anomaly_detector:
                self.anomaly_detector.contamination = kwargs["anomaly_contamination"]
                updated = True
                self.logger.info(f"Anomaly contamination updated to {kwargs['anomaly_contamination']}")
            
            return updated
            
        except Exception as e:
            self.logger.error(f"Error configuring thresholds: {e}")
            return False
    
    def reset_statistics(self) -> None:
        """Reset all system statistics"""
        try:
            self.stats = {
                "packets_captured": 0,
                "packets_analyzed": 0,
                "threats_detected": 0,
                "anomalies_detected": 0,
                "alerts_generated": 0,
                "uptime_seconds": 0,
                "last_packet_time": None,
                "processing_rate": 0.0
            }
            
            # Reset component statistics
            if self.packet_analyzer:
                self.packet_analyzer.reset_statistics()
            
            if self.threat_detector:
                self.threat_detector.reset_trackers()
            
            self.logger.info("System statistics reset")
            
        except Exception as e:
            self.logger.error(f"Error resetting statistics: {e}")


def create_cli_parser() -> argparse.ArgumentParser:
    """Create command-line interface parser"""
    parser = argparse.ArgumentParser(
        description="SpyNet Network Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python spynet_app.py start                    # Start with default settings
  python spynet_app.py start -i eth1           # Start monitoring eth1 interface
  python spynet_app.py status                  # Show system status
  python spynet_app.py stop                    # Stop the system
        """
    )
    
    parser.add_argument(
        "command",
        choices=["start", "stop", "status", "config"],
        help="Command to execute"
    )
    
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to monitor"
    )
    
    parser.add_argument(
        "--port-scan-threshold",
        type=int,
        help="Port scan detection threshold"
    )
    
    parser.add_argument(
        "--ddos-threshold", 
        type=int,
        help="DDoS detection threshold"
    )
    

    
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level"
    )
    
    parser.add_argument(
        "--config-file",
        help="Configuration file path"
    )
    
    return parser


def main():
    """Main entry point for SpyNet application"""
    parser = create_cli_parser()
    args = parser.parse_args()
    
    # Build configuration from command line arguments
    config = {}
    
    if args.interface:
        config["capture_interface"] = args.interface
    
    if args.port_scan_threshold:
        config["port_scan_threshold"] = args.port_scan_threshold
    
    if args.ddos_threshold:
        config["ddos_threshold"] = args.ddos_threshold
    

    
    if args.log_level:
        config["log_level"] = args.log_level
    
    # Load additional configuration from file if specified
    if args.config_file:
        try:
            with open(args.config_file, 'r') as f:
                file_config = json.load(f)
                config.update(file_config)
        except Exception as e:
            print(f"Error loading config file: {e}")
            sys.exit(1)
    
    # Execute command
    if args.command == "start":
        # Create and start SpyNet application
        app = SpyNetApp(config_override=config)
        
        if app.start():
            try:
                # Keep the application running
                while app.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nShutdown requested by user")
            finally:
                app.stop()
        else:
            print("Failed to start SpyNet")
            sys.exit(1)
    
    elif args.command == "status":
        # Show system status (would need to implement IPC or API call)
        print("Status command not implemented - use API endpoint /api/v1/system/status")
    
    elif args.command == "stop":
        # Stop system (would need to implement IPC or signal)
        print("Stop command not implemented - use Ctrl+C or kill signal")
    
    elif args.command == "config":
        # Show current configuration
        print("Current configuration:")
        print(f"  Interface: {config.get('capture_interface', settings.capture_interface)}")
        print(f"  Port scan threshold: {config.get('port_scan_threshold', settings.port_scan_threshold)}")
        print(f"  DDoS threshold: {config.get('ddos_threshold', settings.ddos_threshold)}")

        print(f"  Log level: {config.get('log_level', settings.log_level)}")


if __name__ == "__main__":
    main()