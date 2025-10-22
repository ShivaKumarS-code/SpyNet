"""
Reporting and Forensics Module for SpyNet
Provides comprehensive reporting, data export, and forensic analysis capabilities
"""
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple, Union
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, and_, or_, between, text
from models import PacketInfo, Alert, Connection, Config, db_manager
import json
import csv
import io
import logging
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import pandas as pd
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ReportConfig:
    """Configuration for report generation"""
    title: str
    description: str
    time_range: Tuple[datetime, datetime]
    include_packets: bool = True
    include_alerts: bool = True
    include_connections: bool = True
    include_statistics: bool = True
    export_format: str = "json"  # json, csv, pdf
    max_records: int = 10000


@dataclass
class SecuritySummary:
    """Security summary data structure"""
    time_period: str
    total_packets: int
    total_bytes: int
    unique_sources: int
    unique_destinations: int
    protocol_distribution: Dict[str, int]
    alert_summary: Dict[str, int]
    top_threats: List[Dict[str, Any]]
    connection_summary: Dict[str, Any]
    anomaly_count: int
    risk_score: float


@dataclass
class ForensicSearchResult:
    """Forensic search result data structure"""
    total_matches: int
    packets: List[Dict[str, Any]]
    connections: List[Dict[str, Any]]
    alerts: List[Dict[str, Any]]
    search_criteria: Dict[str, Any]
    execution_time: float


class ReportGenerator:
    """Main reporting and forensics engine"""
    
    def __init__(self):
        self.db_manager = db_manager
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
    
    def generate_security_summary(self, 
                                 start_time: datetime, 
                                 end_time: datetime) -> SecuritySummary:
        """Generate comprehensive security summary report"""
        db = self.db_manager.get_session()
        try:
            logger.info(f"Generating security summary from {start_time} to {end_time}")
            
            # Basic traffic statistics
            packet_stats = self._get_packet_statistics(db, start_time, end_time)
            
            # Alert analysis
            alert_stats = self._get_alert_statistics(db, start_time, end_time)
            
            # Connection analysis
            connection_stats = self._get_connection_statistics(db, start_time, end_time)
            
            # Protocol distribution
            protocol_dist = self._get_protocol_distribution(db, start_time, end_time)
            
            # Top threats analysis
            top_threats = self._get_top_threats(db, start_time, end_time)
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(alert_stats, packet_stats)
            
            time_period = f"{start_time.strftime('%Y-%m-%d %H:%M')} to {end_time.strftime('%Y-%m-%d %H:%M')}"
            
            return SecuritySummary(
                time_period=time_period,
                total_packets=packet_stats['total_packets'],
                total_bytes=packet_stats['total_bytes'],
                unique_sources=packet_stats['unique_sources'],
                unique_destinations=packet_stats['unique_destinations'],
                protocol_distribution=protocol_dist,
                alert_summary=alert_stats,
                top_threats=top_threats,
                connection_summary=connection_stats,
                anomaly_count=alert_stats.get('anomaly', 0),
                risk_score=risk_score
            )
            
        except Exception as e:
            logger.error(f"Error generating security summary: {e}")
            raise
        finally:
            db.close()
    
    def forensic_search(self, 
                       search_criteria: Dict[str, Any],
                       limit: int = 1000) -> ForensicSearchResult:
        """Advanced forensic search across all data types"""
        start_time = datetime.now()
        db = self.db_manager.get_session()
        
        try:
            logger.info(f"Performing forensic search with criteria: {search_criteria}")
            
            # Search packets
            packets = self._search_packets(db, search_criteria, limit)
            
            # Search connections
            connections = self._search_connections(db, search_criteria, limit)
            
            # Search alerts
            alerts = self._search_alerts(db, search_criteria, limit)
            
            execution_time = (datetime.now() - start_time).total_seconds()
            total_matches = len(packets) + len(connections) + len(alerts)
            
            return ForensicSearchResult(
                total_matches=total_matches,
                packets=packets,
                connections=connections,
                alerts=alerts,
                search_criteria=search_criteria,
                execution_time=execution_time
            )
            
        except Exception as e:
            logger.error(f"Error in forensic search: {e}")
            raise
        finally:
            db.close()
    
    def export_data(self, 
                   data: Union[SecuritySummary, ForensicSearchResult, List[Dict]], 
                   format: str = "json",
                   filename: str = None) -> str:
        """Export data in specified format"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"spynet_export_{timestamp}"
        
        filepath = self.reports_dir / f"{filename}.{format}"
        
        try:
            if format.lower() == "json":
                return self._export_json(data, filepath)
            elif format.lower() == "csv":
                return self._export_csv(data, filepath)
            else:
                raise ValueError(f"Unsupported export format: {format}")
                
        except Exception as e:
            logger.error(f"Error exporting data: {e}")
            raise
    
    def generate_trend_analysis(self, 
                               days: int = 7,
                               granularity: str = "hour") -> Dict[str, Any]:
        """Generate historical trend analysis"""
        end_time = datetime.now()
        start_time = end_time - timedelta(days=days)
        
        db = self.db_manager.get_session()
        try:
            logger.info(f"Generating trend analysis for {days} days with {granularity} granularity")
            
            # Traffic trends
            traffic_trends = self._get_traffic_trends(db, start_time, end_time, granularity)
            
            # Alert trends
            alert_trends = self._get_alert_trends(db, start_time, end_time, granularity)
            
            # Protocol trends
            protocol_trends = self._get_protocol_trends(db, start_time, end_time, granularity)
            
            # Top talkers over time
            top_talkers_trends = self._get_top_talkers_trends(db, start_time, end_time)
            
            # Threat evolution
            threat_evolution = self._get_threat_evolution(db, start_time, end_time, granularity)
            
            return {
                "analysis_period": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat(),
                    "days": days,
                    "granularity": granularity
                },
                "traffic_trends": traffic_trends,
                "alert_trends": alert_trends,
                "protocol_trends": protocol_trends,
                "top_talkers_trends": top_talkers_trends,
                "threat_evolution": threat_evolution,
                "summary": self._generate_trend_summary(traffic_trends, alert_trends)
            }
            
        except Exception as e:
            logger.error(f"Error generating trend analysis: {e}")
            raise
        finally:
            db.close()
    
    def generate_compliance_report(self, 
                                  report_type: str = "security_audit",
                                  days: int = 30) -> Dict[str, Any]:
        """Generate compliance and audit reports"""
        end_time = datetime.now()
        start_time = end_time - timedelta(days=days)
        
        db = self.db_manager.get_session()
        try:
            logger.info(f"Generating {report_type} compliance report for {days} days")
            
            if report_type == "security_audit":
                return self._generate_security_audit_report(db, start_time, end_time)
            elif report_type == "incident_summary":
                return self._generate_incident_summary_report(db, start_time, end_time)
            elif report_type == "network_activity":
                return self._generate_network_activity_report(db, start_time, end_time)
            else:
                raise ValueError(f"Unknown report type: {report_type}")
                
        except Exception as e:
            logger.error(f"Error generating compliance report: {e}")
            raise
        finally:
            db.close()
    
    # Private helper methods
    def _get_packet_statistics(self, db: Session, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Get packet statistics for time range"""
        total_packets = db.query(func.count(PacketInfo.id)).filter(
            between(PacketInfo.timestamp, start_time, end_time)
        ).scalar() or 0
        
        total_bytes = db.query(func.sum(PacketInfo.size)).filter(
            between(PacketInfo.timestamp, start_time, end_time)
        ).scalar() or 0
        
        unique_sources = db.query(func.count(func.distinct(PacketInfo.src_ip))).filter(
            between(PacketInfo.timestamp, start_time, end_time)
        ).scalar() or 0
        
        unique_destinations = db.query(func.count(func.distinct(PacketInfo.dst_ip))).filter(
            between(PacketInfo.timestamp, start_time, end_time)
        ).scalar() or 0
        
        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "unique_sources": unique_sources,
            "unique_destinations": unique_destinations
        }
    
    def _get_alert_statistics(self, db: Session, start_time: datetime, end_time: datetime) -> Dict[str, int]:
        """Get alert statistics by type and severity"""
        alerts = db.query(Alert.alert_type, Alert.severity, func.count(Alert.id)).filter(
            between(Alert.timestamp, start_time, end_time)
        ).group_by(Alert.alert_type, Alert.severity).all()
        
        stats = defaultdict(int)
        for alert_type, severity, count in alerts:
            stats[f"{alert_type}_{severity}"] = count
            stats[alert_type] = stats.get(alert_type, 0) + count
            stats[severity] = stats.get(severity, 0) + count
            stats["total"] = stats.get("total", 0) + count
        
        return dict(stats)
    
    def _get_connection_statistics(self, db: Session, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Get connection statistics"""
        total_connections = db.query(func.count(Connection.id)).filter(
            between(Connection.first_seen, start_time, end_time)
        ).scalar() or 0
        
        avg_duration = db.query(func.avg(Connection.connection_duration)).filter(
            between(Connection.first_seen, start_time, end_time)
        ).scalar() or 0
        
        total_bytes_transferred = db.query(
            func.sum(Connection.bytes_sent + Connection.bytes_received)
        ).filter(
            between(Connection.first_seen, start_time, end_time)
        ).scalar() or 0
        
        return {
            "total_connections": total_connections,
            "avg_duration_seconds": float(avg_duration),
            "total_bytes_transferred": total_bytes_transferred
        }
    
    def _get_protocol_distribution(self, db: Session, start_time: datetime, end_time: datetime) -> Dict[str, int]:
        """Get protocol distribution"""
        protocols = db.query(PacketInfo.protocol, func.count(PacketInfo.id)).filter(
            between(PacketInfo.timestamp, start_time, end_time)
        ).group_by(PacketInfo.protocol).all()
        
        return {protocol: count for protocol, count in protocols}
    
    def _get_top_threats(self, db: Session, start_time: datetime, end_time: datetime, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top threats by frequency and severity"""
        threats = db.query(
            Alert.alert_type,
            Alert.severity,
            Alert.source_ip,
            func.count(Alert.id).label('count')
        ).filter(
            between(Alert.timestamp, start_time, end_time)
        ).group_by(Alert.alert_type, Alert.severity, Alert.source_ip).order_by(
            desc('count')
        ).limit(limit).all()
        
        return [
            {
                "threat_type": threat.alert_type,
                "severity": threat.severity,
                "source_ip": threat.source_ip,
                "count": threat.count
            }
            for threat in threats
        ]
    
    def _calculate_risk_score(self, alert_stats: Dict[str, int], packet_stats: Dict[str, Any]) -> float:
        """Calculate overall risk score based on alerts and traffic"""
        critical_alerts = alert_stats.get("Critical", 0)
        high_alerts = alert_stats.get("High", 0)
        medium_alerts = alert_stats.get("Medium", 0)
        total_alerts = alert_stats.get("total", 0)
        total_packets = packet_stats.get("total_packets", 1)
        
        # Risk score calculation (0-100)
        alert_ratio = total_alerts / max(total_packets, 1) * 1000  # Alerts per 1000 packets
        severity_weight = (critical_alerts * 10 + high_alerts * 5 + medium_alerts * 2)
        
        risk_score = min(100, alert_ratio * 10 + severity_weight / max(total_alerts, 1) * 20)
        return round(risk_score, 2)
    
    def _search_packets(self, db: Session, criteria: Dict[str, Any], limit: int) -> List[Dict[str, Any]]:
        """Search packets based on criteria"""
        query = db.query(PacketInfo)
        
        # Apply filters
        if "src_ip" in criteria:
            query = query.filter(PacketInfo.src_ip == criteria["src_ip"])
        if "dst_ip" in criteria:
            query = query.filter(PacketInfo.dst_ip == criteria["dst_ip"])
        if "protocol" in criteria:
            query = query.filter(PacketInfo.protocol == criteria["protocol"])
        if "src_port" in criteria:
            query = query.filter(PacketInfo.src_port == criteria["src_port"])
        if "dst_port" in criteria:
            query = query.filter(PacketInfo.dst_port == criteria["dst_port"])
        if "start_time" in criteria and "end_time" in criteria:
            query = query.filter(between(PacketInfo.timestamp, criteria["start_time"], criteria["end_time"]))
        if "min_size" in criteria:
            query = query.filter(PacketInfo.size >= criteria["min_size"])
        if "max_size" in criteria:
            query = query.filter(PacketInfo.size <= criteria["max_size"])
        
        packets = query.order_by(desc(PacketInfo.timestamp)).limit(limit).all()
        
        return [
            {
                "id": p.id,
                "timestamp": p.timestamp.isoformat(),
                "src_ip": p.src_ip,
                "dst_ip": p.dst_ip,
                "src_port": p.src_port,
                "dst_port": p.dst_port,
                "protocol": p.protocol,
                "size": p.size,
                "tcp_flags": p.tcp_flags,
                "payload_size": p.payload_size
            }
            for p in packets
        ]
    
    def _search_connections(self, db: Session, criteria: Dict[str, Any], limit: int) -> List[Dict[str, Any]]:
        """Search connections based on criteria"""
        query = db.query(Connection)
        
        # Apply filters
        if "src_ip" in criteria:
            query = query.filter(Connection.src_ip == criteria["src_ip"])
        if "dst_ip" in criteria:
            query = query.filter(Connection.dst_ip == criteria["dst_ip"])
        if "protocol" in criteria:
            query = query.filter(Connection.protocol == criteria["protocol"])
        if "start_time" in criteria and "end_time" in criteria:
            query = query.filter(between(Connection.first_seen, criteria["start_time"], criteria["end_time"]))
        if "min_duration" in criteria:
            query = query.filter(Connection.connection_duration >= criteria["min_duration"])
        if "state" in criteria:
            query = query.filter(Connection.state == criteria["state"])
        
        connections = query.order_by(desc(Connection.last_seen)).limit(limit).all()
        
        return [
            {
                "id": c.id,
                "src_ip": c.src_ip,
                "dst_ip": c.dst_ip,
                "src_port": c.src_port,
                "dst_port": c.dst_port,
                "protocol": c.protocol,
                "first_seen": c.first_seen.isoformat(),
                "last_seen": c.last_seen.isoformat(),
                "packet_count": c.packet_count,
                "bytes_sent": c.bytes_sent,
                "bytes_received": c.bytes_received,
                "state": c.state,
                "duration": c.connection_duration
            }
            for c in connections
        ]
    
    def _search_alerts(self, db: Session, criteria: Dict[str, Any], limit: int) -> List[Dict[str, Any]]:
        """Search alerts based on criteria"""
        query = db.query(Alert)
        
        # Apply filters
        if "alert_type" in criteria:
            query = query.filter(Alert.alert_type == criteria["alert_type"])
        if "severity" in criteria:
            query = query.filter(Alert.severity == criteria["severity"])
        if "source_ip" in criteria:
            query = query.filter(Alert.source_ip == criteria["source_ip"])
        if "resolved" in criteria:
            query = query.filter(Alert.resolved == criteria["resolved"])
        if "start_time" in criteria and "end_time" in criteria:
            query = query.filter(between(Alert.timestamp, criteria["start_time"], criteria["end_time"]))
        
        alerts = query.order_by(desc(Alert.timestamp)).limit(limit).all()
        
        return [
            {
                "id": a.id,
                "timestamp": a.timestamp.isoformat(),
                "alert_type": a.alert_type,
                "severity": a.severity,
                "source_ip": a.source_ip,
                "destination_ip": a.destination_ip,
                "description": a.description,
                "details": a.details,
                "resolved": a.resolved,
                "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
                "resolved_by": a.resolved_by
            }
            for a in alerts
        ]
    
    def _export_json(self, data: Any, filepath: Path) -> str:
        """Export data as JSON"""
        if isinstance(data, (SecuritySummary, ForensicSearchResult)):
            data_dict = asdict(data)
        elif isinstance(data, list):
            data_dict = {"data": data, "exported_at": datetime.now().isoformat()}
        else:
            data_dict = data
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data_dict, f, indent=2, default=str)
        
        logger.info(f"Data exported to JSON: {filepath}")
        return str(filepath)
    
    def _export_csv(self, data: Any, filepath: Path) -> str:
        """Export data as CSV"""
        if isinstance(data, SecuritySummary):
            # Convert security summary to tabular format
            rows = []
            summary_dict = asdict(data)
            for key, value in summary_dict.items():
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        rows.append({"category": key, "metric": sub_key, "value": sub_value})
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            for sub_key, sub_value in item.items():
                                rows.append({"category": key, "index": i, "metric": sub_key, "value": sub_value})
                        else:
                            rows.append({"category": key, "index": i, "value": item})
                else:
                    rows.append({"category": "summary", "metric": key, "value": value})
            
            df = pd.DataFrame(rows)
            
        elif isinstance(data, ForensicSearchResult):
            # Export forensic results as separate sheets/files
            all_data = []
            for packet in data.packets:
                packet["data_type"] = "packet"
                all_data.append(packet)
            for connection in data.connections:
                connection["data_type"] = "connection"
                all_data.append(connection)
            for alert in data.alerts:
                alert["data_type"] = "alert"
                all_data.append(alert)
            
            df = pd.DataFrame(all_data)
            
        elif isinstance(data, list) and data:
            df = pd.DataFrame(data)
        else:
            # Fallback for other data types
            df = pd.DataFrame([{"data": str(data)}])
        
        df.to_csv(filepath, index=False)
        logger.info(f"Data exported to CSV: {filepath}")
        return str(filepath)
    
    def _get_traffic_trends(self, db: Session, start_time: datetime, end_time: datetime, granularity: str) -> List[Dict[str, Any]]:
        """Get traffic trends over time"""
        if granularity == "hour":
            time_format = "%Y-%m-%d %H:00:00"
            time_trunc = func.date_trunc('hour', PacketInfo.timestamp)
        elif granularity == "day":
            time_format = "%Y-%m-%d"
            time_trunc = func.date_trunc('day', PacketInfo.timestamp)
        else:
            raise ValueError(f"Unsupported granularity: {granularity}")
        
        trends = db.query(
            time_trunc.label('time_bucket'),
            func.count(PacketInfo.id).label('packet_count'),
            func.sum(PacketInfo.size).label('total_bytes')
        ).filter(
            between(PacketInfo.timestamp, start_time, end_time)
        ).group_by('time_bucket').order_by('time_bucket').all()
        
        return [
            {
                "timestamp": trend.time_bucket.isoformat(),
                "packet_count": trend.packet_count,
                "total_bytes": trend.total_bytes or 0
            }
            for trend in trends
        ]
    
    def _get_alert_trends(self, db: Session, start_time: datetime, end_time: datetime, granularity: str) -> List[Dict[str, Any]]:
        """Get alert trends over time"""
        if granularity == "hour":
            time_trunc = func.date_trunc('hour', Alert.timestamp)
        elif granularity == "day":
            time_trunc = func.date_trunc('day', Alert.timestamp)
        else:
            raise ValueError(f"Unsupported granularity: {granularity}")
        
        trends = db.query(
            time_trunc.label('time_bucket'),
            Alert.severity,
            func.count(Alert.id).label('alert_count')
        ).filter(
            between(Alert.timestamp, start_time, end_time)
        ).group_by('time_bucket', Alert.severity).order_by('time_bucket').all()
        
        # Group by time bucket
        result = defaultdict(lambda: {"timestamp": None, "Critical": 0, "High": 0, "Medium": 0, "Low": 0})
        for trend in trends:
            bucket_key = trend.time_bucket.isoformat()
            result[bucket_key]["timestamp"] = bucket_key
            result[bucket_key][trend.severity] = trend.alert_count
        
        return list(result.values())
    
    def _get_protocol_trends(self, db: Session, start_time: datetime, end_time: datetime, granularity: str) -> List[Dict[str, Any]]:
        """Get protocol distribution trends over time"""
        if granularity == "hour":
            time_trunc = func.date_trunc('hour', PacketInfo.timestamp)
        elif granularity == "day":
            time_trunc = func.date_trunc('day', PacketInfo.timestamp)
        else:
            raise ValueError(f"Unsupported granularity: {granularity}")
        
        trends = db.query(
            time_trunc.label('time_bucket'),
            PacketInfo.protocol,
            func.count(PacketInfo.id).label('packet_count')
        ).filter(
            between(PacketInfo.timestamp, start_time, end_time)
        ).group_by('time_bucket', PacketInfo.protocol).order_by('time_bucket').all()
        
        # Group by time bucket
        result = defaultdict(lambda: {"timestamp": None})
        for trend in trends:
            bucket_key = trend.time_bucket.isoformat()
            result[bucket_key]["timestamp"] = bucket_key
            result[bucket_key][trend.protocol] = trend.packet_count
        
        return list(result.values())
    
    def _get_top_talkers_trends(self, db: Session, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Get top talkers over time periods"""
        # Divide time range into periods
        total_hours = (end_time - start_time).total_seconds() / 3600
        period_hours = max(1, int(total_hours / 24))  # Up to 24 periods
        
        periods = []
        current_time = start_time
        while current_time < end_time:
            period_end = min(current_time + timedelta(hours=period_hours), end_time)
            
            top_talkers = db.query(
                PacketInfo.src_ip,
                func.count(PacketInfo.id).label('packet_count'),
                func.sum(PacketInfo.size).label('total_bytes')
            ).filter(
                between(PacketInfo.timestamp, current_time, period_end)
            ).group_by(PacketInfo.src_ip).order_by(desc('packet_count')).limit(5).all()
            
            periods.append({
                "period_start": current_time.isoformat(),
                "period_end": period_end.isoformat(),
                "top_talkers": [
                    {
                        "ip": talker.src_ip,
                        "packet_count": talker.packet_count,
                        "total_bytes": talker.total_bytes or 0
                    }
                    for talker in top_talkers
                ]
            })
            
            current_time = period_end
        
        return periods
    
    def _get_threat_evolution(self, db: Session, start_time: datetime, end_time: datetime, granularity: str) -> List[Dict[str, Any]]:
        """Get threat evolution over time"""
        if granularity == "hour":
            time_trunc = func.date_trunc('hour', Alert.timestamp)
        elif granularity == "day":
            time_trunc = func.date_trunc('day', Alert.timestamp)
        else:
            raise ValueError(f"Unsupported granularity: {granularity}")
        
        evolution = db.query(
            time_trunc.label('time_bucket'),
            Alert.alert_type,
            func.count(Alert.id).label('threat_count')
        ).filter(
            between(Alert.timestamp, start_time, end_time)
        ).group_by('time_bucket', Alert.alert_type).order_by('time_bucket').all()
        
        # Group by time bucket
        result = defaultdict(lambda: {"timestamp": None})
        for item in evolution:
            bucket_key = item.time_bucket.isoformat()
            result[bucket_key]["timestamp"] = bucket_key
            result[bucket_key][item.alert_type] = item.threat_count
        
        return list(result.values())
    
    def _generate_trend_summary(self, traffic_trends: List[Dict], alert_trends: List[Dict]) -> Dict[str, Any]:
        """Generate summary of trends"""
        if not traffic_trends or not alert_trends:
            return {"status": "insufficient_data"}
        
        # Traffic trend analysis
        packet_counts = [t["packet_count"] for t in traffic_trends]
        avg_packets = sum(packet_counts) / len(packet_counts)
        peak_traffic = max(packet_counts)
        
        # Alert trend analysis
        total_alerts_per_period = []
        for period in alert_trends:
            total = period.get("Critical", 0) + period.get("High", 0) + period.get("Medium", 0) + period.get("Low", 0)
            total_alerts_per_period.append(total)
        
        avg_alerts = sum(total_alerts_per_period) / len(total_alerts_per_period) if total_alerts_per_period else 0
        peak_alerts = max(total_alerts_per_period) if total_alerts_per_period else 0
        
        return {
            "traffic_summary": {
                "average_packets_per_period": int(avg_packets),
                "peak_traffic_packets": peak_traffic,
                "traffic_variance": "high" if peak_traffic > avg_packets * 2 else "normal"
            },
            "alert_summary": {
                "average_alerts_per_period": round(avg_alerts, 2),
                "peak_alerts": peak_alerts,
                "alert_trend": "increasing" if total_alerts_per_period and total_alerts_per_period[-1] > avg_alerts else "stable"
            }
        }
    
    def _generate_security_audit_report(self, db: Session, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Generate security audit compliance report"""
        # Get all critical and high severity alerts
        critical_alerts = db.query(Alert).filter(
            and_(
                between(Alert.timestamp, start_time, end_time),
                Alert.severity.in_(["Critical", "High"])
            )
        ).all()
        
        # Resolution statistics
        resolved_critical = [a for a in critical_alerts if a.resolved]
        unresolved_critical = [a for a in critical_alerts if not a.resolved]
        
        # Response time analysis
        response_times = []
        for alert in resolved_critical:
            if alert.resolved_at:
                response_time = (alert.resolved_at - alert.timestamp).total_seconds() / 3600  # hours
                response_times.append(response_time)
        
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        return {
            "report_type": "security_audit",
            "period": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat()
            },
            "critical_incidents": {
                "total_critical_high_alerts": len(critical_alerts),
                "resolved_count": len(resolved_critical),
                "unresolved_count": len(unresolved_critical),
                "resolution_rate": len(resolved_critical) / len(critical_alerts) * 100 if critical_alerts else 0
            },
            "response_metrics": {
                "average_response_time_hours": round(avg_response_time, 2),
                "fastest_response_hours": min(response_times) if response_times else 0,
                "slowest_response_hours": max(response_times) if response_times else 0
            },
            "compliance_status": "compliant" if len(unresolved_critical) == 0 else "non_compliant",
            "recommendations": self._generate_audit_recommendations(unresolved_critical, avg_response_time)
        }
    
    def _generate_incident_summary_report(self, db: Session, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Generate incident summary report"""
        alerts = db.query(Alert).filter(
            between(Alert.timestamp, start_time, end_time)
        ).all()
        
        # Group by type and severity
        incident_types = defaultdict(lambda: {"count": 0, "severities": defaultdict(int)})
        for alert in alerts:
            incident_types[alert.alert_type]["count"] += 1
            incident_types[alert.alert_type]["severities"][alert.severity] += 1
        
        # Top incident sources
        source_incidents = defaultdict(int)
        for alert in alerts:
            source_incidents[alert.source_ip] += 1
        
        top_sources = sorted(source_incidents.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            "report_type": "incident_summary",
            "period": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat()
            },
            "total_incidents": len(alerts),
            "incident_breakdown": dict(incident_types),
            "top_incident_sources": [{"ip": ip, "incident_count": count} for ip, count in top_sources],
            "severity_distribution": {
                severity: len([a for a in alerts if a.severity == severity])
                for severity in ["Critical", "High", "Medium", "Low"]
            }
        }
    
    def _generate_network_activity_report(self, db: Session, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Generate network activity report"""
        # Traffic statistics
        packet_stats = self._get_packet_statistics(db, start_time, end_time)
        protocol_dist = self._get_protocol_distribution(db, start_time, end_time)
        
        # Connection analysis
        connections = db.query(Connection).filter(
            between(Connection.first_seen, start_time, end_time)
        ).all()
        
        # Bandwidth analysis
        total_bandwidth = sum(c.bytes_sent + c.bytes_received for c in connections)
        avg_connection_duration = sum(c.connection_duration for c in connections) / len(connections) if connections else 0
        
        return {
            "report_type": "network_activity",
            "period": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat()
            },
            "traffic_summary": packet_stats,
            "protocol_distribution": protocol_dist,
            "connection_analysis": {
                "total_connections": len(connections),
                "total_bandwidth_bytes": total_bandwidth,
                "average_connection_duration": round(avg_connection_duration, 2)
            },
            "network_health": "healthy" if packet_stats["total_packets"] > 0 else "no_traffic"
        }
    
    def _generate_audit_recommendations(self, unresolved_alerts: List[Alert], avg_response_time: float) -> List[str]:
        """Generate audit recommendations based on findings"""
        recommendations = []
        
        if unresolved_alerts:
            recommendations.append(f"Resolve {len(unresolved_alerts)} outstanding critical/high severity alerts")
        
        if avg_response_time > 24:  # More than 24 hours
            recommendations.append("Improve incident response time - current average exceeds 24 hours")
        
        # Check for specific threat patterns
        threat_types = [a.alert_type for a in unresolved_alerts]
        if "port_scan" in threat_types:
            recommendations.append("Implement additional port scan protection measures")
        if "ddos" in threat_types:
            recommendations.append("Review DDoS mitigation strategies")
        
        if not recommendations:
            recommendations.append("Security posture appears healthy - maintain current monitoring practices")
        
        return recommendations


# Global reporting instance
report_generator = ReportGenerator()


# Convenience functions
def generate_security_summary(hours: int = 24) -> SecuritySummary:
    """Generate security summary for the last N hours"""
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=hours)
    return report_generator.generate_security_summary(start_time, end_time)


def forensic_search(criteria: Dict[str, Any], limit: int = 1000) -> ForensicSearchResult:
    """Perform forensic search"""
    return report_generator.forensic_search(criteria, limit)


def export_security_data(data: Any, format: str = "json", filename: str = None) -> str:
    """Export security data"""
    return report_generator.export_data(data, format, filename)


def generate_trend_analysis(days: int = 7) -> Dict[str, Any]:
    """Generate trend analysis"""
    return report_generator.generate_trend_analysis(days)


if __name__ == "__main__":
    # Test reporting functionality
    print("Testing SpyNet Reporting Module...")
    
    try:
        # Test security summary
        summary = generate_security_summary(hours=24)
        print(f"Generated security summary: {summary.total_packets} packets analyzed")
        
        # Test forensic search
        search_criteria = {
            "protocol": "TCP",
            "start_time": datetime.now() - timedelta(hours=1),
            "end_time": datetime.now()
        }
        results = forensic_search(search_criteria, limit=100)
        print(f"Forensic search found {results.total_matches} matches")
        
        # Test trend analysis
        trends = generate_trend_analysis(days=7)
        print(f"Generated trend analysis for 7 days")
        
        print("Reporting module tests completed successfully!")
        
    except Exception as e:
        print(f"Error testing reporting module: {e}")
        logger.error(f"Reporting module test failed: {e}")