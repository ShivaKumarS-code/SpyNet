"""
SpyNet Alert Management System

This module implements the AlertManager class for processing, storing, and notifying
about security alerts with severity classification and notification capabilities.
"""

import logging
import smtplib
import json
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

from sqlalchemy.orm import Session
from sqlalchemy import desc, and_, or_

from models import Alert, get_db, db_manager
from threat_detector import ThreatAlert, AlertSeverity
from config import settings


class AlertManager:
    """
    AlertManager class for processing and managing security alerts.
    
    Provides alert storage, email notifications, logging, and deduplication
    capabilities with configurable severity thresholds.
    """
    
    def __init__(self, 
                 email_config: Optional[Dict[str, Any]] = None,
                 log_file: str = "alerts.log",
                 enable_email: bool = True,
                 critical_only: bool = False):
        """
        Initialize AlertManager instance.
        
        Args:
            email_config: Email configuration dictionary
            log_file: Path to alert log file
            enable_email: Whether to enable email notifications
            critical_only: Whether to send notifications only for critical alerts
        """
        self.email_config = email_config or self._get_default_email_config()
        self.log_file = Path(log_file)
        self.enable_email = enable_email
        self.critical_only = critical_only
        
        # Alert deduplication tracking
        self.recent_alerts: Dict[str, datetime] = {}
        self.dedup_window = timedelta(minutes=10)  # Deduplication time window
        
        # Statistics
        self.alerts_processed = 0
        self.alerts_stored = 0
        self.notifications_sent = 0
        self.dedup_count = 0
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        self._setup_alert_logging()
    
    def _get_default_email_config(self) -> Dict[str, Any]:
        """Get default email configuration from settings"""
        return {
            "smtp_server": settings.smtp_server,
            "smtp_port": settings.smtp_port,
            "username": settings.smtp_username,
            "password": settings.smtp_password,
            "from_email": settings.smtp_username or "spynet@localhost",
            "to_emails": ["admin@localhost"]  # Default recipient
        }
    
    def _setup_alert_logging(self) -> None:
        """Setup dedicated alert file logging"""
        try:
            # Create alert log directory if it doesn't exist
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Setup alert-specific logger
            alert_logger = logging.getLogger("spynet.alerts")
            alert_logger.setLevel(logging.INFO)
            
            # Create file handler if not already exists
            if not alert_logger.handlers:
                file_handler = logging.FileHandler(self.log_file)
                formatter = logging.Formatter(
                    '%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
                file_handler.setFormatter(formatter)
                alert_logger.addHandler(file_handler)
            
            self.alert_logger = alert_logger
            
        except Exception as e:
            self.logger.error(f"Error setting up alert logging: {e}")
            self.alert_logger = self.logger
    
    def process_alert(self, threat_alert: ThreatAlert) -> bool:
        """
        Process a threat alert - store, log, and notify as appropriate.
        
        Args:
            threat_alert: ThreatAlert object to process
            
        Returns:
            True if alert was processed successfully, False otherwise
        """
        try:
            self.alerts_processed += 1
            
            # Check for deduplication
            if self._is_duplicate_alert(threat_alert):
                self.dedup_count += 1
                self.logger.debug(f"Duplicate alert suppressed: {threat_alert.alert_type} from {threat_alert.source_ip}")
                return True
            
            # Store alert in database
            db_alert = self._store_alert(threat_alert)
            if db_alert:
                self.alerts_stored += 1
            
            # Log alert to file
            self._log_alert(threat_alert)
            
            # Send notification if appropriate
            if self._should_notify(threat_alert):
                self._send_notification(threat_alert)
                self.notifications_sent += 1
            
            # Record alert for deduplication
            self._record_alert_for_dedup(threat_alert)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error processing alert: {e}")
            return False
    
    def _is_duplicate_alert(self, threat_alert: ThreatAlert) -> bool:
        """Check if this alert is a duplicate within the deduplication window"""
        alert_key = self._generate_alert_key(threat_alert)
        
        if alert_key in self.recent_alerts:
            time_since_last = datetime.now() - self.recent_alerts[alert_key]
            return time_since_last < self.dedup_window
        
        return False
    
    def _generate_alert_key(self, threat_alert: ThreatAlert) -> str:
        """Generate unique key for alert deduplication"""
        return f"{threat_alert.alert_type}_{threat_alert.source_ip}_{threat_alert.destination_ip}"
    
    def _record_alert_for_dedup(self, threat_alert: ThreatAlert) -> None:
        """Record alert timestamp for deduplication tracking"""
        alert_key = self._generate_alert_key(threat_alert)
        self.recent_alerts[alert_key] = datetime.now()
        
        # Clean up old entries
        self._cleanup_dedup_tracking()
    
    def _cleanup_dedup_tracking(self) -> None:
        """Clean up old deduplication tracking entries"""
        current_time = datetime.now()
        cutoff_time = current_time - self.dedup_window * 2  # Keep entries a bit longer
        
        keys_to_remove = []
        for key, timestamp in self.recent_alerts.items():
            if timestamp < cutoff_time:
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self.recent_alerts[key]
    
    def _store_alert(self, threat_alert: ThreatAlert) -> Optional[Alert]:
        """Store alert in database"""
        try:
            db = db_manager.get_session()
            try:
                # Convert ThreatAlert to database Alert model
                db_alert = threat_alert.to_db_alert()
                
                # Add to database
                db.add(db_alert)
                db.commit()
                db.refresh(db_alert)
                
                self.logger.debug(f"Alert stored in database: ID {db_alert.id}")
                return db_alert
                
            except Exception as e:
                db.rollback()
                self.logger.error(f"Error storing alert in database: {e}")
                return None
            finally:
                db.close()
                
        except Exception as e:
            self.logger.error(f"Error getting database session: {e}")
            return None
    
    def _log_alert(self, threat_alert: ThreatAlert) -> None:
        """Log alert to file"""
        try:
            alert_data = {
                "timestamp": threat_alert.timestamp.isoformat(),
                "type": threat_alert.alert_type,
                "severity": threat_alert.severity.value,
                "source_ip": threat_alert.source_ip,
                "destination_ip": threat_alert.destination_ip,
                "description": threat_alert.description,
                "details": threat_alert.details
            }
            
            log_message = f"ALERT: {json.dumps(alert_data, separators=(',', ':'))}"
            self.alert_logger.info(log_message)
            
        except Exception as e:
            self.logger.error(f"Error logging alert to file: {e}")
    
    def _should_notify(self, threat_alert: ThreatAlert) -> bool:
        """Determine if notification should be sent for this alert"""
        if not self.enable_email:
            return False
        
        if self.critical_only:
            return threat_alert.severity == AlertSeverity.CRITICAL
        
        # Send notifications for Medium, High, and Critical alerts
        return threat_alert.severity in [AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL]
    
    def _send_notification(self, threat_alert: ThreatAlert) -> bool:
        """Send email notification for alert"""
        try:
            if not self.email_config.get("username") or not self.email_config.get("password"):
                self.logger.warning("Email credentials not configured, skipping notification")
                return False
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = self.email_config["from_email"]
            msg['To'] = ", ".join(self.email_config["to_emails"])
            msg['Subject'] = f"SpyNet Security Alert - {threat_alert.severity.value}: {threat_alert.alert_type}"
            
            # Create email body
            body = self._create_email_body(threat_alert)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            with smtplib.SMTP(self.email_config["smtp_server"], self.email_config["smtp_port"]) as server:
                server.starttls()
                server.login(self.email_config["username"], self.email_config["password"])
                server.send_message(msg)
            
            self.logger.info(f"Email notification sent for {threat_alert.alert_type} alert")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending email notification: {e}")
            return False
    
    def _create_email_body(self, threat_alert: ThreatAlert) -> str:
        """Create HTML email body for alert notification"""
        severity_colors = {
            AlertSeverity.LOW: "#28a745",
            AlertSeverity.MEDIUM: "#ffc107", 
            AlertSeverity.HIGH: "#fd7e14",
            AlertSeverity.CRITICAL: "#dc3545"
        }
        
        color = severity_colors.get(threat_alert.severity, "#6c757d")
        
        html_body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .alert-header {{ background-color: {color}; color: white; padding: 15px; border-radius: 5px; }}
                .alert-content {{ padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-top: 10px; }}
                .detail-table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
                .detail-table th, .detail-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                .detail-table th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="alert-header">
                <h2>SpyNet Security Alert</h2>
                <h3>{threat_alert.severity.value}: {threat_alert.alert_type}</h3>
            </div>
            
            <div class="alert-content">
                <p><strong>Description:</strong> {threat_alert.description}</p>
                
                <table class="detail-table">
                    <tr><th>Timestamp</th><td>{threat_alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</td></tr>
                    <tr><th>Source IP</th><td>{threat_alert.source_ip}</td></tr>
                    <tr><th>Destination IP</th><td>{threat_alert.destination_ip or 'N/A'}</td></tr>
                    <tr><th>Alert Type</th><td>{threat_alert.alert_type}</td></tr>
                    <tr><th>Severity</th><td>{threat_alert.severity.value}</td></tr>
                </table>
                
                <h4>Additional Details:</h4>
                <ul>
        """
        
        # Add details
        for key, value in threat_alert.details.items():
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value[:5])  # Limit list items
                if len(threat_alert.details[key]) > 5:
                    value += "..."
            html_body += f"<li><strong>{key.replace('_', ' ').title()}:</strong> {value}</li>"
        
        html_body += """
                </ul>
                
                <p><em>This is an automated alert from SpyNet Network Intrusion Detection System.</em></p>
            </div>
        </body>
        </html>
        """
        
        return html_body
    
    def get_recent_alerts(self, limit: int = 50, severity_filter: Optional[str] = None) -> List[Alert]:
        """
        Get recent alerts from database.
        
        Args:
            limit: Maximum number of alerts to return
            severity_filter: Filter by severity level (Low, Medium, High, Critical)
            
        Returns:
            List of Alert objects
        """
        try:
            db = db_manager.get_session()
            try:
                query = db.query(Alert).order_by(desc(Alert.timestamp))
                
                if severity_filter:
                    query = query.filter(Alert.severity == severity_filter)
                
                alerts = query.limit(limit).all()
                return alerts
                
            finally:
                db.close()
                
        except Exception as e:
            self.logger.error(f"Error retrieving recent alerts: {e}")
            return []
    
    def get_alerts_by_source(self, source_ip: str, hours: int = 24) -> List[Alert]:
        """
        Get alerts from a specific source IP within time window.
        
        Args:
            source_ip: Source IP address to filter by
            hours: Time window in hours
            
        Returns:
            List of Alert objects
        """
        try:
            db = db_manager.get_session()
            try:
                cutoff_time = datetime.now() - timedelta(hours=hours)
                
                alerts = db.query(Alert).filter(
                    and_(
                        Alert.source_ip == source_ip,
                        Alert.timestamp >= cutoff_time
                    )
                ).order_by(desc(Alert.timestamp)).all()
                
                return alerts
                
            finally:
                db.close()
                
        except Exception as e:
            self.logger.error(f"Error retrieving alerts by source: {e}")
            return []
    
    def get_alert_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get alert statistics for the specified time window.
        
        Args:
            hours: Time window in hours
            
        Returns:
            Dictionary containing alert statistics
        """
        try:
            db = db_manager.get_session()
            try:
                cutoff_time = datetime.now() - timedelta(hours=hours)
                
                # Total alerts
                total_alerts = db.query(Alert).filter(Alert.timestamp >= cutoff_time).count()
                
                # Alerts by severity
                severity_counts = {}
                for severity in ["Low", "Medium", "High", "Critical"]:
                    count = db.query(Alert).filter(
                        and_(
                            Alert.severity == severity,
                            Alert.timestamp >= cutoff_time
                        )
                    ).count()
                    severity_counts[severity] = count
                
                # Alerts by type
                type_counts = {}
                alert_types = db.query(Alert.alert_type).filter(Alert.timestamp >= cutoff_time).distinct().all()
                for (alert_type,) in alert_types:
                    count = db.query(Alert).filter(
                        and_(
                            Alert.alert_type == alert_type,
                            Alert.timestamp >= cutoff_time
                        )
                    ).count()
                    type_counts[alert_type] = count
                
                # Top source IPs
                from sqlalchemy import func
                top_sources = db.query(
                    Alert.source_ip,
                    func.count(Alert.id).label('alert_count')
                ).filter(
                    Alert.timestamp >= cutoff_time
                ).group_by(Alert.source_ip).order_by(
                    desc('alert_count')
                ).limit(10).all()
                
                return {
                    "total_alerts": total_alerts,
                    "severity_distribution": severity_counts,
                    "type_distribution": type_counts,
                    "top_source_ips": [{"ip": ip, "count": count} for ip, count in top_sources],
                    "time_window_hours": hours,
                    "manager_stats": {
                        "alerts_processed": self.alerts_processed,
                        "alerts_stored": self.alerts_stored,
                        "notifications_sent": self.notifications_sent,
                        "duplicates_suppressed": self.dedup_count
                    }
                }
                
            finally:
                db.close()
                
        except Exception as e:
            self.logger.error(f"Error retrieving alert statistics: {e}")
            return {}
    
    def mark_alert_resolved(self, alert_id: int, resolved_by: str = "system") -> bool:
        """
        Mark an alert as resolved.
        
        Args:
            alert_id: ID of alert to resolve
            resolved_by: Who resolved the alert
            
        Returns:
            True if successful, False otherwise
        """
        try:
            db = db_manager.get_session()
            try:
                alert = db.query(Alert).filter(Alert.id == alert_id).first()
                if alert:
                    alert.resolved = True
                    alert.resolved_at = datetime.now()
                    alert.resolved_by = resolved_by
                    db.commit()
                    
                    self.logger.info(f"Alert {alert_id} marked as resolved by {resolved_by}")
                    return True
                else:
                    self.logger.warning(f"Alert {alert_id} not found")
                    return False
                    
            except Exception as e:
                db.rollback()
                self.logger.error(f"Error marking alert as resolved: {e}")
                return False
            finally:
                db.close()
                
        except Exception as e:
            self.logger.error(f"Error getting database session: {e}")
            return False
    
    def cleanup_old_alerts(self, days: int = 30) -> int:
        """
        Clean up alerts older than specified days.
        
        Args:
            days: Number of days to keep alerts
            
        Returns:
            Number of alerts deleted
        """
        try:
            db = db_manager.get_session()
            try:
                cutoff_time = datetime.now() - timedelta(days=days)
                
                # Delete old alerts
                deleted_count = db.query(Alert).filter(Alert.timestamp < cutoff_time).delete()
                db.commit()
                
                self.logger.info(f"Cleaned up {deleted_count} alerts older than {days} days")
                return deleted_count
                
            except Exception as e:
                db.rollback()
                self.logger.error(f"Error cleaning up old alerts: {e}")
                return 0
            finally:
                db.close()
                
        except Exception as e:
            self.logger.error(f"Error getting database session: {e}")
            return 0


if __name__ == "__main__":
    # Simple test of alert manager functionality
    print("SpyNet Alert Manager Test")
    print("=" * 30)
    
    # Create alert manager instance
    alert_manager = AlertManager(enable_email=False)  # Disable email for testing
    
    print("Alert manager initialized successfully")
    print(f"Alert statistics: {alert_manager.get_alert_statistics()}")