"""
SpyNet Anomaly Detection Engine

This module implements the AnomalyDetector class using Isolation Forest from scikit-learn
to detect unusual network behavior patterns and identify potential zero-day attacks.
"""

import logging
import pickle
import numpy as np
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
except ImportError as e:
    print(f"Error importing scikit-learn: {e}")
    print("Please install scikit-learn: pip install scikit-learn")
    raise

from packet_analyzer import PacketInfo
from models import Alert
from threat_detector import ThreatAlert, AlertSeverity, ThreatType


@dataclass
class TrafficFeatures:
    """Data class for extracted network traffic features"""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    packet_size: int
    protocol: str
    src_port: int
    dst_port: int
    tcp_flags: str = ""
    payload_size: int = 0
    
    # Derived features
    is_weekend: bool = False
    hour_of_day: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    unique_ports_accessed: int = 0
    connection_duration: float = 0.0
    
    def __post_init__(self):
        """Calculate derived features after initialization"""
        self.is_weekend = self.timestamp.weekday() >= 5
        self.hour_of_day = self.timestamp.hour


@dataclass
class BaselineStats:
    """Statistics for baseline network behavior"""
    avg_packet_size: float = 0.0
    std_packet_size: float = 0.0
    avg_packets_per_minute: float = 0.0
    std_packets_per_minute: float = 0.0
    protocol_distribution: Dict[str, float] = field(default_factory=dict)
    port_distribution: Dict[int, float] = field(default_factory=dict)
    hourly_traffic_pattern: Dict[int, float] = field(default_factory=dict)
    ip_communication_patterns: Dict[str, int] = field(default_factory=dict)
    
    # Time-based patterns
    weekday_avg_traffic: float = 0.0
    weekend_avg_traffic: float = 0.0
    
    # Connection patterns
    avg_connection_duration: float = 0.0
    std_connection_duration: float = 0.0
    avg_unique_ports_per_ip: float = 0.0


class AnomalyDetector:
    """
    AnomalyDetector class using Isolation Forest for detecting unusual network behavior.
    
    Provides baseline learning functionality, feature extraction for network traffic patterns,
    and integration with the main threat detection pipeline.
    """
    
    def __init__(self, 
                 contamination: float = 0.1,
                 baseline_window_hours: int = 24,
                 min_baseline_samples: int = 1000,
                 anomaly_threshold: float = -0.5,
                 model_save_path: str = "models/anomaly_model.pkl"):
        """
        Initialize AnomalyDetector instance.
        
        Args:
            contamination: Expected proportion of anomalies in the data
            baseline_window_hours: Hours of data to use for baseline learning
            min_baseline_samples: Minimum samples needed before training model
            anomaly_threshold: Threshold for anomaly score classification
            model_save_path: Path to save/load the trained model
        """
        self.contamination = contamination
        self.baseline_window_hours = baseline_window_hours
        self.min_baseline_samples = min_baseline_samples
        self.anomaly_threshold = anomaly_threshold
        self.model_save_path = Path(model_save_path)
        
        # Machine learning components
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            max_features=1.0
        )
        self.scaler = StandardScaler()
        self.trained = False
        
        # Baseline statistics
        self.baseline_stats = BaselineStats()
        self.baseline_data: List[TrafficFeatures] = []
        
        # Feature tracking for real-time analysis
        self.recent_traffic: deque = deque(maxlen=10000)  # Keep recent traffic for analysis
        self.ip_activity: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.protocol_counts: Dict[str, int] = defaultdict(int)
        self.port_counts: Dict[int, int] = defaultdict(int)
        
        # Anomaly tracking
        self.detected_anomalies: List[Dict[str, Any]] = []
        self.anomaly_scores: deque = deque(maxlen=1000)
        
        # Statistics
        self.packets_processed = 0
        self.anomalies_detected = 0
        self.false_positives = 0
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        # Create model directory if it doesn't exist
        self.model_save_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Try to load existing model
        self._load_model()
    
    def extract_features(self, packet_info: PacketInfo) -> TrafficFeatures:
        """
        Extract features from packet information for ML analysis.
        
        Args:
            packet_info: PacketInfo object to extract features from
            
        Returns:
            TrafficFeatures object with extracted features
        """
        try:
            # Create basic traffic features
            features = TrafficFeatures(
                timestamp=packet_info.timestamp,
                src_ip=packet_info.src_ip,
                dst_ip=packet_info.dst_ip,
                packet_size=packet_info.size,
                protocol=packet_info.protocol,
                src_port=packet_info.src_port,
                dst_port=packet_info.dst_port,
                tcp_flags=packet_info.tcp_flags,
                payload_size=packet_info.payload_size
            )
            
            # Calculate derived features based on recent activity
            self._calculate_derived_features(features)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting features: {e}")
            # Return basic features on error
            return TrafficFeatures(
                timestamp=packet_info.timestamp,
                src_ip=packet_info.src_ip,
                dst_ip=packet_info.dst_ip,
                packet_size=packet_info.size,
                protocol=packet_info.protocol,
                src_port=packet_info.src_port,
                dst_port=packet_info.dst_port
            )
    
    def _calculate_derived_features(self, features: TrafficFeatures) -> None:
        """Calculate derived features based on recent network activity"""
        try:
            current_time = features.timestamp
            
            # Get recent activity for this IP
            src_activity = self.ip_activity[features.src_ip]
            
            # Calculate packets per second for this IP
            if len(src_activity) > 1:
                time_window = 60  # 1 minute window
                recent_packets = [
                    pkt for pkt in src_activity 
                    if (current_time - pkt['timestamp']).total_seconds() <= time_window
                ]
                features.packets_per_second = len(recent_packets) / time_window
                
                # Calculate bytes per second
                total_bytes = sum(pkt['size'] for pkt in recent_packets)
                features.bytes_per_second = total_bytes / time_window
                
                # Calculate unique ports accessed
                unique_ports = set(pkt['dst_port'] for pkt in recent_packets)
                features.unique_ports_accessed = len(unique_ports)
            
            # Update IP activity tracking
            src_activity.append({
                'timestamp': current_time,
                'size': features.packet_size,
                'dst_port': features.dst_port,
                'protocol': features.protocol
            })
            
        except Exception as e:
            self.logger.error(f"Error calculating derived features: {e}")
    
    def learn_baseline(self, traffic_data: List[PacketInfo]) -> None:
        """
        Learn normal traffic patterns from historical data.
        
        Args:
            traffic_data: List of PacketInfo objects representing normal traffic
        """
        try:
            self.logger.info(f"Learning baseline from {len(traffic_data)} packets")
            
            # Extract features from all packets
            feature_list = []
            for packet_info in traffic_data:
                features = self.extract_features(packet_info)
                feature_list.append(features)
                self.baseline_data.append(features)
            
            # Calculate baseline statistics
            self._calculate_baseline_stats(feature_list)
            
            # Check if we have enough data to train the model
            if len(self.baseline_data) >= self.min_baseline_samples:
                self._train_model()
            else:
                self.logger.warning(f"Not enough baseline data ({len(self.baseline_data)}) "
                                  f"to train model (need {self.min_baseline_samples})")
            
        except Exception as e:
            self.logger.error(f"Error learning baseline: {e}")
            raise
    
    def _calculate_baseline_stats(self, feature_list: List[TrafficFeatures]) -> None:
        """Calculate statistical baseline from feature data"""
        try:
            if not feature_list:
                return
            
            # Packet size statistics
            packet_sizes = [f.packet_size for f in feature_list]
            self.baseline_stats.avg_packet_size = np.mean(packet_sizes)
            self.baseline_stats.std_packet_size = np.std(packet_sizes)
            
            # Protocol distribution
            protocol_counts = defaultdict(int)
            for f in feature_list:
                protocol_counts[f.protocol] += 1
            
            total_packets = len(feature_list)
            self.baseline_stats.protocol_distribution = {
                proto: count / total_packets 
                for proto, count in protocol_counts.items()
            }
            
            # Port distribution (top 20 ports)
            port_counts = defaultdict(int)
            for f in feature_list:
                if f.dst_port > 0:
                    port_counts[f.dst_port] += 1
            
            sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:20]
            self.baseline_stats.port_distribution = {
                port: count / total_packets 
                for port, count in sorted_ports
            }
            
            # Hourly traffic patterns
            hourly_counts = defaultdict(int)
            for f in feature_list:
                hourly_counts[f.hour_of_day] += 1
            
            self.baseline_stats.hourly_traffic_pattern = {
                hour: count / total_packets 
                for hour, count in hourly_counts.items()
            }
            
            # Weekend vs weekday patterns
            weekday_packets = [f for f in feature_list if not f.is_weekend]
            weekend_packets = [f for f in feature_list if f.is_weekend]
            
            if weekday_packets:
                self.baseline_stats.weekday_avg_traffic = len(weekday_packets) / max(1, len(set(f.timestamp.date() for f in weekday_packets if not f.is_weekend)))
            
            if weekend_packets:
                self.baseline_stats.weekend_avg_traffic = len(weekend_packets) / max(1, len(set(f.timestamp.date() for f in weekend_packets if f.is_weekend)))
            
            self.logger.info("Baseline statistics calculated successfully")
            
        except Exception as e:
            self.logger.error(f"Error calculating baseline stats: {e}")
    
    def _train_model(self) -> None:
        """Train the Isolation Forest model on baseline data"""
        try:
            self.logger.info("Training anomaly detection model...")
            
            # Convert features to numerical array
            feature_matrix = self._features_to_matrix(self.baseline_data)
            
            if feature_matrix.shape[0] < self.min_baseline_samples:
                self.logger.warning("Insufficient data for training")
                return
            
            # Scale features
            feature_matrix_scaled = self.scaler.fit_transform(feature_matrix)
            
            # Train Isolation Forest
            self.isolation_forest.fit(feature_matrix_scaled)
            self.trained = True
            
            # Save the trained model
            self._save_model()
            
            self.logger.info(f"Model trained successfully on {feature_matrix.shape[0]} samples")
            
        except Exception as e:
            self.logger.error(f"Error training model: {e}")
            raise
    
    def _features_to_matrix(self, features_list: List[TrafficFeatures]) -> np.ndarray:
        """Convert list of TrafficFeatures to numerical matrix for ML"""
        try:
            feature_vectors = []
            
            for features in features_list:
                # Create numerical feature vector
                vector = [
                    features.packet_size,
                    features.payload_size,
                    features.src_port,
                    features.dst_port,
                    features.hour_of_day,
                    int(features.is_weekend),
                    features.packets_per_second,
                    features.bytes_per_second,
                    features.unique_ports_accessed,
                    # Protocol encoding (one-hot for common protocols)
                    1 if features.protocol == "TCP" else 0,
                    1 if features.protocol == "UDP" else 0,
                    1 if features.protocol == "ICMP" else 0,
                    # TCP flags encoding
                    1 if "SYN" in features.tcp_flags else 0,
                    1 if "ACK" in features.tcp_flags else 0,
                    1 if "FIN" in features.tcp_flags else 0,
                    1 if "RST" in features.tcp_flags else 0,
                ]
                
                feature_vectors.append(vector)
            
            return np.array(feature_vectors, dtype=np.float32)
            
        except Exception as e:
            self.logger.error(f"Error converting features to matrix: {e}")
            return np.array([])
    
    def detect_anomaly(self, packet_info: PacketInfo) -> Optional[ThreatAlert]:
        """
        Detect if current traffic is anomalous compared to baseline.
        
        Args:
            packet_info: PacketInfo object to analyze
            
        Returns:
            ThreatAlert if anomaly detected, None otherwise
        """
        try:
            self.packets_processed += 1
            
            # Check if model is trained
            if not self.trained:
                return None
            
            # Extract features
            features = self.extract_features(packet_info)
            
            # Convert to matrix format
            feature_matrix = self._features_to_matrix([features])
            
            if feature_matrix.shape[0] == 0:
                return None
            
            # Scale features
            feature_matrix_scaled = self.scaler.transform(feature_matrix)
            
            # Get anomaly score
            anomaly_score = self.isolation_forest.decision_function(feature_matrix_scaled)[0]
            is_anomaly = self.isolation_forest.predict(feature_matrix_scaled)[0] == -1
            
            # Store anomaly score for analysis
            self.anomaly_scores.append({
                'timestamp': features.timestamp,
                'score': anomaly_score,
                'src_ip': features.src_ip,
                'is_anomaly': is_anomaly
            })
            
            # Check if anomaly score exceeds threshold
            if is_anomaly and anomaly_score < self.anomaly_threshold:
                self.anomalies_detected += 1
                
                # Calculate severity based on anomaly score
                severity = self._calculate_anomaly_severity(anomaly_score, features)
                
                # Create anomaly alert
                alert = ThreatAlert(
                    alert_type="Network Anomaly",
                    severity=severity,
                    source_ip=features.src_ip,
                    destination_ip=features.dst_ip,
                    description=f"Anomalous network behavior detected from {features.src_ip}. "
                              f"Anomaly score: {anomaly_score:.3f}",
                    details={
                        "anomaly_score": anomaly_score,
                        "packet_size": features.packet_size,
                        "protocol": features.protocol,
                        "src_port": features.src_port,
                        "dst_port": features.dst_port,
                        "packets_per_second": features.packets_per_second,
                        "bytes_per_second": features.bytes_per_second,
                        "unique_ports_accessed": features.unique_ports_accessed,
                        "hour_of_day": features.hour_of_day,
                        "is_weekend": features.is_weekend,
                        "baseline_comparison": self._compare_to_baseline(features)
                    }
                )
                
                # Store anomaly for analysis
                self.detected_anomalies.append({
                    'timestamp': features.timestamp,
                    'alert': alert,
                    'features': features,
                    'score': anomaly_score
                })
                
                return alert
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error detecting anomaly: {e}")
            return None
    
    def _calculate_anomaly_severity(self, anomaly_score: float, features: TrafficFeatures) -> AlertSeverity:
        """Calculate severity of anomaly based on score and characteristics"""
        try:
            # Very low scores indicate strong anomalies
            if anomaly_score < -0.8:
                return AlertSeverity.CRITICAL
            elif anomaly_score < -0.6:
                return AlertSeverity.HIGH
            elif anomaly_score < -0.4:
                return AlertSeverity.MEDIUM
            else:
                return AlertSeverity.LOW
                
        except Exception as e:
            self.logger.error(f"Error calculating anomaly severity: {e}")
            return AlertSeverity.LOW
    
    def _compare_to_baseline(self, features: TrafficFeatures) -> Dict[str, Any]:
        """Compare current features to baseline statistics"""
        try:
            comparison = {}
            
            # Packet size comparison
            if self.baseline_stats.avg_packet_size > 0:
                size_deviation = abs(features.packet_size - self.baseline_stats.avg_packet_size) / self.baseline_stats.avg_packet_size
                comparison['packet_size_deviation'] = size_deviation
            
            # Protocol comparison
            expected_protocol_freq = self.baseline_stats.protocol_distribution.get(features.protocol, 0)
            comparison['protocol_frequency'] = expected_protocol_freq
            comparison['is_rare_protocol'] = expected_protocol_freq < 0.01
            
            # Port comparison
            expected_port_freq = self.baseline_stats.port_distribution.get(features.dst_port, 0)
            comparison['port_frequency'] = expected_port_freq
            comparison['is_rare_port'] = expected_port_freq < 0.001
            
            # Time-based comparison
            expected_hourly_freq = self.baseline_stats.hourly_traffic_pattern.get(features.hour_of_day, 0)
            comparison['hourly_frequency'] = expected_hourly_freq
            comparison['is_unusual_time'] = expected_hourly_freq < 0.01
            
            return comparison
            
        except Exception as e:
            self.logger.error(f"Error comparing to baseline: {e}")
            return {}
    
    def _save_model(self) -> None:
        """Save the trained model and scaler to disk"""
        try:
            model_data = {
                'isolation_forest': self.isolation_forest,
                'scaler': self.scaler,
                'baseline_stats': self.baseline_stats,
                'trained': self.trained,
                'contamination': self.contamination,
                'anomaly_threshold': self.anomaly_threshold
            }
            
            with open(self.model_save_path, 'wb') as f:
                pickle.dump(model_data, f)
            
            self.logger.info(f"Model saved to {self.model_save_path}")
            
        except Exception as e:
            self.logger.error(f"Error saving model: {e}")
    
    def _load_model(self) -> None:
        """Load a previously trained model from disk"""
        try:
            if not self.model_save_path.exists():
                self.logger.info("No existing model found")
                return
            
            with open(self.model_save_path, 'rb') as f:
                model_data = pickle.load(f)
            
            self.isolation_forest = model_data['isolation_forest']
            self.scaler = model_data['scaler']
            self.baseline_stats = model_data['baseline_stats']
            self.trained = model_data['trained']
            
            self.logger.info(f"Model loaded from {self.model_save_path}")
            
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            self.trained = False
    
    def update_baseline(self, new_traffic_data: List[PacketInfo]) -> None:
        """
        Update baseline with new normal traffic data.
        
        Args:
            new_traffic_data: List of new PacketInfo objects representing normal traffic
        """
        try:
            self.logger.info(f"Updating baseline with {len(new_traffic_data)} new packets")
            
            # Add new data to baseline
            for packet_info in new_traffic_data:
                features = self.extract_features(packet_info)
                self.baseline_data.append(features)
            
            # Keep only recent data within the baseline window
            cutoff_time = datetime.now() - timedelta(hours=self.baseline_window_hours)
            self.baseline_data = [
                f for f in self.baseline_data 
                if f.timestamp >= cutoff_time
            ]
            
            # Retrain model if we have enough data
            if len(self.baseline_data) >= self.min_baseline_samples:
                self._calculate_baseline_stats(self.baseline_data)
                self._train_model()
            
        except Exception as e:
            self.logger.error(f"Error updating baseline: {e}")
    
    def get_anomaly_statistics(self) -> Dict[str, Any]:
        """Get statistics about anomaly detection performance"""
        try:
            recent_scores = [score['score'] for score in self.anomaly_scores if score['score'] is not None]
            
            return {
                "packets_processed": self.packets_processed,
                "anomalies_detected": self.anomalies_detected,
                "false_positives": self.false_positives,
                "model_trained": self.trained,
                "baseline_samples": len(self.baseline_data),
                "recent_anomaly_scores": {
                    "count": len(recent_scores),
                    "mean": np.mean(recent_scores) if recent_scores else 0,
                    "std": np.std(recent_scores) if recent_scores else 0,
                    "min": np.min(recent_scores) if recent_scores else 0,
                    "max": np.max(recent_scores) if recent_scores else 0
                },
                "detection_rate": self.anomalies_detected / max(1, self.packets_processed),
                "baseline_stats": {
                    "avg_packet_size": self.baseline_stats.avg_packet_size,
                    "protocol_count": len(self.baseline_stats.protocol_distribution),
                    "port_count": len(self.baseline_stats.port_distribution)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error getting anomaly statistics: {e}")
            return {}
    
    def get_recent_anomalies(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent anomaly detections"""
        try:
            recent_anomalies = sorted(
                self.detected_anomalies, 
                key=lambda x: x['timestamp'], 
                reverse=True
            )[:limit]
            
            return [
                {
                    "timestamp": anomaly['timestamp'].isoformat(),
                    "source_ip": anomaly['features'].src_ip,
                    "destination_ip": anomaly['features'].dst_ip,
                    "anomaly_score": anomaly['score'],
                    "severity": anomaly['alert'].severity.value,
                    "description": anomaly['alert'].description,
                    "packet_size": anomaly['features'].packet_size,
                    "protocol": anomaly['features'].protocol
                }
                for anomaly in recent_anomalies
            ]
            
        except Exception as e:
            self.logger.error(f"Error getting recent anomalies: {e}")
            return []
    
    def mark_false_positive(self, anomaly_timestamp: datetime, source_ip: str) -> None:
        """Mark an anomaly as a false positive for model improvement"""
        try:
            self.false_positives += 1
            
            # Find and mark the anomaly
            for anomaly in self.detected_anomalies:
                if (anomaly['timestamp'] == anomaly_timestamp and 
                    anomaly['features'].src_ip == source_ip):
                    anomaly['false_positive'] = True
                    break
            
            self.logger.info(f"Marked anomaly as false positive: {source_ip} at {anomaly_timestamp}")
            
        except Exception as e:
            self.logger.error(f"Error marking false positive: {e}")
    
    def reset_detector(self) -> None:
        """Reset the anomaly detector state"""
        try:
            self.baseline_data.clear()
            self.recent_traffic.clear()
            self.ip_activity.clear()
            self.protocol_counts.clear()
            self.port_counts.clear()
            self.detected_anomalies.clear()
            self.anomaly_scores.clear()
            
            self.packets_processed = 0
            self.anomalies_detected = 0
            self.false_positives = 0
            self.trained = False
            
            # Reset baseline stats
            self.baseline_stats = BaselineStats()
            
            # Reset ML components
            self.isolation_forest = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=100
            )
            self.scaler = StandardScaler()
            
            self.logger.info("Anomaly detector reset successfully")
            
        except Exception as e:
            self.logger.error(f"Error resetting detector: {e}")


if __name__ == "__main__":
    # Simple test of anomaly detector functionality
    print("SpyNet Anomaly Detector Test")
    print("=" * 30)
    
    # Create detector instance
    detector = AnomalyDetector()
    
    print("Anomaly detector initialized successfully")
    print(f"Model trained: {detector.trained}")
    print(f"Baseline samples: {len(detector.baseline_data)}")
    print(f"Statistics: {detector.get_anomaly_statistics()}")