"""
Database utilities and operations for SpyNet
"""
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, and_, or_
from models import PacketInfo, Alert, Connection, Config, db_manager, get_db
import logging

logger = logging.getLogger(__name__)


class DatabaseOperations:
    """High-level database operations for SpyNet"""
    
    def __init__(self):
        self.db_manager = db_manager
    
    # Packet operations
    def store_packet(self, packet_data: Dict[str, Any]) -> PacketInfo:
        """Store a packet in the database"""
        db = self.db_manager.get_session()
        try:
            packet = PacketInfo(
                timestamp=packet_data.get('timestamp', datetime.utcnow()),
                src_ip=packet_data['src_ip'],
                dst_ip=packet_data['dst_ip'],
                src_port=packet_data.get('src_port'),
                dst_port=packet_data.get('dst_port'),
                protocol=packet_data['protocol'],
                size=packet_data['size'],
                tcp_flags=packet_data.get('tcp_flags'),
                payload_size=packet_data.get('payload_size', 0)
            )
            db.add(packet)
            db.commit()
            db.refresh(packet)
            return packet
        except Exception as e:
            db.rollback()
            logger.error(f"Error storing packet: {e}")
            raise
        finally:
            db.close()
    
    def get_recent_packets(self, limit: int = 100, hours: int = 1) -> List[PacketInfo]:
        """Get recent packets from the database"""
        db = self.db_manager.get_session()
        try:
            since = datetime.utcnow() - timedelta(hours=hours)
            packets = db.query(PacketInfo).filter(
                PacketInfo.timestamp >= since
            ).order_by(desc(PacketInfo.timestamp)).limit(limit).all()
            return packets
        finally:
            db.close()
    
    def get_traffic_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get traffic statistics for the specified time period"""
        db = self.db_manager.get_session()
        try:
            since = datetime.utcnow() - timedelta(hours=hours)
            
            # Basic statistics
            total_packets = db.query(func.count(PacketInfo.id)).filter(
                PacketInfo.timestamp >= since
            ).scalar()
            
            total_bytes = db.query(func.sum(PacketInfo.size)).filter(
                PacketInfo.timestamp >= since
            ).scalar() or 0
            
            # Protocol distribution
            protocol_stats = db.query(
                PacketInfo.protocol,
                func.count(PacketInfo.id).label('count')
            ).filter(
                PacketInfo.timestamp >= since
            ).group_by(PacketInfo.protocol).all()
            
            # Top talkers (source IPs)
            top_sources = db.query(
                PacketInfo.src_ip,
                func.count(PacketInfo.id).label('packet_count'),
                func.sum(PacketInfo.size).label('total_bytes')
            ).filter(
                PacketInfo.timestamp >= since
            ).group_by(PacketInfo.src_ip).order_by(
                desc('packet_count')
            ).limit(10).all()
            
            return {
                'total_packets': total_packets,
                'total_bytes': total_bytes,
                'protocol_distribution': [
                    {'protocol': p.protocol, 'count': p.count} 
                    for p in protocol_stats
                ],
                'top_sources': [
                    {
                        'ip': s.src_ip,
                        'packet_count': s.packet_count,
                        'total_bytes': s.total_bytes
                    }
                    for s in top_sources
                ]
            }
        finally:
            db.close()
    
    # Alert operations
    def create_alert(self, alert_data: Dict[str, Any]) -> Alert:
        """Create a new security alert"""
        db = self.db_manager.get_session()
        try:
            alert = Alert(
                timestamp=alert_data.get('timestamp', datetime.utcnow()),
                alert_type=alert_data['alert_type'],
                severity=alert_data['severity'],
                source_ip=alert_data['source_ip'],
                destination_ip=alert_data.get('destination_ip'),
                description=alert_data['description'],
                details=alert_data.get('details', {})
            )
            db.add(alert)
            db.commit()
            db.refresh(alert)
            return alert
        except Exception as e:
            db.rollback()
            logger.error(f"Error creating alert: {e}")
            raise
        finally:
            db.close()
    
    def get_recent_alerts(self, limit: int = 50, severity: str = None) -> List[Alert]:
        """Get recent alerts, optionally filtered by severity"""
        db = self.db_manager.get_session()
        try:
            query = db.query(Alert)
            
            if severity:
                query = query.filter(Alert.severity == severity)
            
            alerts = query.order_by(desc(Alert.timestamp)).limit(limit).all()
            return alerts
        finally:
            db.close()
    
    def get_unresolved_alerts(self) -> List[Alert]:
        """Get all unresolved alerts"""
        db = self.db_manager.get_session()
        try:
            alerts = db.query(Alert).filter(
                Alert.resolved == False
            ).order_by(desc(Alert.timestamp)).all()
            return alerts
        finally:
            db.close()
    
    def resolve_alert(self, alert_id: int, resolved_by: str = None) -> bool:
        """Mark an alert as resolved"""
        db = self.db_manager.get_session()
        try:
            alert = db.query(Alert).filter(Alert.id == alert_id).first()
            if alert:
                alert.resolved = True
                alert.resolved_at = datetime.utcnow()
                alert.resolved_by = resolved_by
                db.commit()
                return True
            return False
        except Exception as e:
            db.rollback()
            logger.error(f"Error resolving alert {alert_id}: {e}")
            raise
        finally:
            db.close()
    
    # Connection operations
    def update_connection(self, connection_data: Dict[str, Any]) -> Connection:
        """Update or create a connection record"""
        db = self.db_manager.get_session()
        try:
            # Try to find existing connection
            connection = db.query(Connection).filter(
                and_(
                    Connection.src_ip == connection_data['src_ip'],
                    Connection.dst_ip == connection_data['dst_ip'],
                    Connection.src_port == connection_data.get('src_port'),
                    Connection.dst_port == connection_data.get('dst_port'),
                    Connection.protocol == connection_data['protocol']
                )
            ).first()
            
            if connection:
                # Update existing connection
                connection.last_seen = datetime.utcnow()
                connection.packet_count += 1
                connection.bytes_sent += connection_data.get('bytes_sent', 0)
                connection.bytes_received += connection_data.get('bytes_received', 0)
                
                # Update averages
                if connection.packet_count > 0:
                    total_bytes = connection.bytes_sent + connection.bytes_received
                    connection.avg_packet_size = total_bytes / connection.packet_count
                
                # Update connection duration
                duration = (connection.last_seen - connection.first_seen).total_seconds()
                connection.connection_duration = duration
                
            else:
                # Create new connection
                connection = Connection(
                    src_ip=connection_data['src_ip'],
                    dst_ip=connection_data['dst_ip'],
                    src_port=connection_data.get('src_port'),
                    dst_port=connection_data.get('dst_port'),
                    protocol=connection_data['protocol'],
                    bytes_sent=connection_data.get('bytes_sent', 0),
                    bytes_received=connection_data.get('bytes_received', 0),
                    tcp_flags_seen=connection_data.get('tcp_flags')
                )
                db.add(connection)
            
            db.commit()
            db.refresh(connection)
            return connection
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error updating connection: {e}")
            raise
        finally:
            db.close()
    
    def get_active_connections(self, limit: int = 100) -> List[Connection]:
        """Get active network connections"""
        db = self.db_manager.get_session()
        try:
            # Consider connections active if seen in last 5 minutes
            since = datetime.utcnow() - timedelta(minutes=5)
            connections = db.query(Connection).filter(
                and_(
                    Connection.last_seen >= since,
                    Connection.state == 'ACTIVE'
                )
            ).order_by(desc(Connection.last_seen)).limit(limit).all()
            return connections
        finally:
            db.close()
    
    def cleanup_old_connections(self, hours: int = 24):
        """Clean up old inactive connections"""
        db = self.db_manager.get_session()
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            
            # Mark old connections as closed
            updated = db.query(Connection).filter(
                and_(
                    Connection.last_seen < cutoff,
                    Connection.state == 'ACTIVE'
                )
            ).update({'state': 'TIMEOUT'})
            
            db.commit()
            logger.info(f"Marked {updated} connections as timed out")
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error cleaning up connections: {e}")
            raise
        finally:
            db.close()
    
    # Configuration operations
    def get_config(self, key: str) -> Any:
        """Get configuration value by key"""
        db = self.db_manager.get_session()
        try:
            config = db.query(Config).filter(Config.key == key).first()
            return config.value if config else None
        finally:
            db.close()
    
    def set_config(self, key: str, value: Any, description: str = None, category: str = 'general'):
        """Set configuration value"""
        db = self.db_manager.get_session()
        try:
            config = db.query(Config).filter(Config.key == key).first()
            
            if config:
                config.value = value
                config.updated_at = datetime.utcnow()
                if description:
                    config.description = description
            else:
                config = Config(
                    key=key,
                    value=value,
                    description=description,
                    category=category
                )
                db.add(config)
            
            db.commit()
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error setting config {key}: {e}")
            raise
        finally:
            db.close()
    
    def get_all_config(self, category: str = None) -> Dict[str, Any]:
        """Get all configuration values, optionally filtered by category"""
        db = self.db_manager.get_session()
        try:
            query = db.query(Config)
            if category:
                query = query.filter(Config.category == category)
            
            configs = query.all()
            return {config.key: config.value for config in configs}
        finally:
            db.close()
    
    # Maintenance operations
    def cleanup_old_data(self, days: int = 30):
        """Clean up old data to manage database size"""
        db = self.db_manager.get_session()
        try:
            cutoff = datetime.utcnow() - timedelta(days=days)
            
            # Clean up old packets (keep only recent data)
            deleted_packets = db.query(PacketInfo).filter(
                PacketInfo.timestamp < cutoff
            ).delete()
            
            # Clean up resolved alerts older than cutoff
            deleted_alerts = db.query(Alert).filter(
                and_(
                    Alert.timestamp < cutoff,
                    Alert.resolved == True
                )
            ).delete()
            
            # Clean up old closed connections
            deleted_connections = db.query(Connection).filter(
                and_(
                    Connection.last_seen < cutoff,
                    Connection.state.in_(['CLOSED', 'TIMEOUT'])
                )
            ).delete()
            
            db.commit()
            
            logger.info(f"Cleanup completed: {deleted_packets} packets, "
                       f"{deleted_alerts} alerts, {deleted_connections} connections deleted")
            
            return {
                'packets_deleted': deleted_packets,
                'alerts_deleted': deleted_alerts,
                'connections_deleted': deleted_connections
            }
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error during cleanup: {e}")
            raise
        finally:
            db.close()


# Global database operations instance
db_ops = DatabaseOperations()


# Convenience functions
def store_packet(packet_data: Dict[str, Any]) -> PacketInfo:
    """Store a packet in the database"""
    return db_ops.store_packet(packet_data)


def create_alert(alert_data: Dict[str, Any]) -> Alert:
    """Create a new security alert"""
    return db_ops.create_alert(alert_data)


def get_recent_alerts(limit: int = 50, severity: str = None) -> List[Alert]:
    """Get recent alerts"""
    return db_ops.get_recent_alerts(limit, severity)


def get_traffic_stats(hours: int = 24) -> Dict[str, Any]:
    """Get traffic statistics"""
    return db_ops.get_traffic_stats(hours)


if __name__ == "__main__":
    # Test database operations
    print("Testing database operations...")
    
    # Test traffic stats (will be empty initially)
    stats = get_traffic_stats()
    print(f"Traffic stats: {stats}")
    
    print("Database operations module ready!")