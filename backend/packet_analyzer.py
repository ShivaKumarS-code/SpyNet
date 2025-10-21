"""
SpyNet Packet Analyzer Module

This module implements the PacketAnalyzer class to extract essential packet information,
perform protocol parsing for TCP, UDP, and ICMP packets, and track network connections.
"""

import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib

try:
    from scapy.all import Packet
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
except ImportError as e:
    print(f"Error importing Scapy: {e}")
    print("Please install Scapy: pip install scapy")
    raise


@dataclass
class PacketInfo:
    """Data class containing essential packet information"""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    size: int
    tcp_flags: str = ""
    payload_size: int = 0
    ttl: int = 0
    packet_id: str = ""
    
    def __post_init__(self):
        """Generate unique packet ID after initialization"""
        if not self.packet_id:
            self.packet_id = self._generate_packet_id()
    
    def _generate_packet_id(self) -> str:
        """Generate unique packet identifier"""
        data = f"{self.timestamp}{self.src_ip}{self.dst_ip}{self.src_port}{self.dst_port}{self.protocol}"
        return hashlib.md5(data.encode()).hexdigest()[:16]


@dataclass
class ConnectionInfo:
    """Data class for tracking network connections"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: datetime
    last_seen: datetime
    packet_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    state: str = "UNKNOWN"  # TCP states: SYN_SENT, ESTABLISHED, FIN_WAIT, etc.
    
    def get_flow_key(self) -> str:
        """Generate unique flow identifier"""
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}:{self.protocol}"
    
    def get_reverse_flow_key(self) -> str:
        """Generate reverse flow identifier"""
        return f"{self.dst_ip}:{self.dst_port}->{self.src_ip}:{self.src_port}:{self.protocol}"


@dataclass
class FlowInfo:
    """Data class for flow summary information"""
    src_ip: str
    dst_ip: str
    total_packets: int
    total_bytes: int
    duration: timedelta
    protocols: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    first_seen: datetime = None
    last_seen: datetime = None


class PacketAnalyzer:
    """
    PacketAnalyzer class for extracting essential packet information and tracking connections.
    
    Provides protocol parsing for TCP, UDP, and ICMP packets, connection tracking,
    and metadata extraction including IPs, ports, protocols, and packet sizes.
    """
    
    def __init__(self, connection_timeout: int = 300):
        """
        Initialize PacketAnalyzer instance.
        
        Args:
            connection_timeout: Timeout in seconds for inactive connections
        """
        self.connection_tracker: Dict[str, ConnectionInfo] = {}
        self.connection_timeout = connection_timeout
        self.packet_count = 0
        self.total_bytes = 0
        
        # Protocol statistics
        self.protocol_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
    def analyze_packet(self, packet: Packet) -> Optional[PacketInfo]:
        """
        Extract essential packet information from a Scapy packet.
        
        Args:
            packet: Scapy packet object to analyze
            
        Returns:
            PacketInfo object with extracted metadata or None if parsing fails
        """
        try:
            # Check if packet has IP layer
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            packet_size = len(packet)
            
            # Extract basic IP information
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            ttl = ip_layer.ttl
            protocol = self._get_protocol_name(ip_layer.proto)
            
            # Initialize port information
            src_port = 0
            dst_port = 0
            tcp_flags = ""
            payload_size = 0
            
            # Parse transport layer protocols
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                tcp_flags = self._parse_tcp_flags(tcp_layer.flags)
                payload_size = len(tcp_layer.payload) if tcp_layer.payload else 0
                
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                payload_size = len(udp_layer.payload) if udp_layer.payload else 0
                
            elif packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                # For ICMP, use type and code as "ports"
                src_port = icmp_layer.type
                dst_port = icmp_layer.code
                payload_size = len(icmp_layer.payload) if icmp_layer.payload else 0
            
            # Create PacketInfo object
            packet_info = PacketInfo(
                timestamp=datetime.now(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                size=packet_size,
                tcp_flags=tcp_flags,
                payload_size=payload_size,
                ttl=ttl
            )
            
            # Update statistics
            self.packet_count += 1
            self.total_bytes += packet_size
            self.protocol_stats[protocol] += 1
            if src_port > 0:
                self.port_stats[src_port] += 1
            if dst_port > 0:
                self.port_stats[dst_port] += 1
            
            return packet_info
            
        except Exception as e:
            self.logger.error(f"Error analyzing packet: {e}")
            return None
    
    def _get_protocol_name(self, proto_num: int) -> str:
        """
        Convert protocol number to protocol name.
        
        Args:
            proto_num: IP protocol number
            
        Returns:
            Protocol name string
        """
        protocol_map = {
            1: "ICMP",
            6: "TCP", 
            17: "UDP",
            47: "GRE",
            50: "ESP",
            51: "AH"
        }
        return protocol_map.get(proto_num, f"PROTO_{proto_num}")
    
    def _parse_tcp_flags(self, flags: int) -> str:
        """
        Parse TCP flags into readable string.
        
        Args:
            flags: TCP flags integer
            
        Returns:
            String representation of TCP flags
        """
        flag_names = []
        
        if flags & 0x01:  # FIN
            flag_names.append("FIN")
        if flags & 0x02:  # SYN
            flag_names.append("SYN")
        if flags & 0x04:  # RST
            flag_names.append("RST")
        if flags & 0x08:  # PSH
            flag_names.append("PSH")
        if flags & 0x10:  # ACK
            flag_names.append("ACK")
        if flags & 0x20:  # URG
            flag_names.append("URG")
        if flags & 0x40:  # ECE
            flag_names.append("ECE")
        if flags & 0x80:  # CWR
            flag_names.append("CWR")
            
        return "|".join(flag_names) if flag_names else "NONE"
    
    def track_connections(self, packet_info: PacketInfo) -> None:
        """
        Track connection states for flow analysis.
        
        Args:
            packet_info: PacketInfo object to track
        """
        try:
            # Generate flow key
            flow_key = f"{packet_info.src_ip}:{packet_info.src_port}->{packet_info.dst_ip}:{packet_info.dst_port}:{packet_info.protocol}"
            reverse_flow_key = f"{packet_info.dst_ip}:{packet_info.dst_port}->{packet_info.src_ip}:{packet_info.src_port}:{packet_info.protocol}"
            
            # Check if connection already exists (either direction)
            connection = None
            if flow_key in self.connection_tracker:
                connection = self.connection_tracker[flow_key]
            elif reverse_flow_key in self.connection_tracker:
                connection = self.connection_tracker[reverse_flow_key]
                # Update bytes for reverse direction
                connection.bytes_received += packet_info.size
            
            if connection:
                # Update existing connection
                connection.last_seen = packet_info.timestamp
                connection.packet_count += 1
                if flow_key in self.connection_tracker:
                    connection.bytes_sent += packet_info.size
                
                # Update TCP state if applicable
                if packet_info.protocol == "TCP":
                    connection.state = self._update_tcp_state(connection.state, packet_info.tcp_flags)
            else:
                # Create new connection
                connection = ConnectionInfo(
                    src_ip=packet_info.src_ip,
                    dst_ip=packet_info.dst_ip,
                    src_port=packet_info.src_port,
                    dst_port=packet_info.dst_port,
                    protocol=packet_info.protocol,
                    start_time=packet_info.timestamp,
                    last_seen=packet_info.timestamp,
                    packet_count=1,
                    bytes_sent=packet_info.size,
                    state=self._get_initial_tcp_state(packet_info.tcp_flags) if packet_info.protocol == "TCP" else "ACTIVE"
                )
                
                self.connection_tracker[flow_key] = connection
            
            # Clean up old connections
            self._cleanup_old_connections()
            
        except Exception as e:
            self.logger.error(f"Error tracking connection: {e}")
    
    def _update_tcp_state(self, current_state: str, tcp_flags: str) -> str:
        """
        Update TCP connection state based on flags.
        
        Args:
            current_state: Current TCP state
            tcp_flags: TCP flags string
            
        Returns:
            Updated TCP state
        """
        if "SYN" in tcp_flags and "ACK" not in tcp_flags:
            return "SYN_SENT"
        elif "SYN" in tcp_flags and "ACK" in tcp_flags:
            return "SYN_RECEIVED"
        elif "ACK" in tcp_flags and current_state in ["SYN_SENT", "SYN_RECEIVED"]:
            return "ESTABLISHED"
        elif "FIN" in tcp_flags:
            return "FIN_WAIT"
        elif "RST" in tcp_flags:
            return "RESET"
        else:
            return current_state
    
    def _get_initial_tcp_state(self, tcp_flags: str) -> str:
        """
        Get initial TCP state based on flags.
        
        Args:
            tcp_flags: TCP flags string
            
        Returns:
            Initial TCP state
        """
        if "SYN" in tcp_flags and "ACK" not in tcp_flags:
            return "SYN_SENT"
        elif "SYN" in tcp_flags and "ACK" in tcp_flags:
            return "SYN_RECEIVED"
        else:
            return "UNKNOWN"
    
    def _cleanup_old_connections(self) -> None:
        """Clean up connections that have timed out"""
        current_time = datetime.now()
        timeout_threshold = timedelta(seconds=self.connection_timeout)
        
        # Find connections to remove
        connections_to_remove = []
        for flow_key, connection in self.connection_tracker.items():
            if current_time - connection.last_seen > timeout_threshold:
                connections_to_remove.append(flow_key)
        
        # Remove old connections
        for flow_key in connections_to_remove:
            del self.connection_tracker[flow_key]
        
        if connections_to_remove:
            self.logger.debug(f"Cleaned up {len(connections_to_remove)} old connections")
    
    def get_flow_summary(self, src_ip: str, dst_ip: str) -> Optional[FlowInfo]:
        """
        Get summary of traffic between two hosts.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            
        Returns:
            FlowInfo object with traffic summary or None if no flows found
        """
        try:
            # Find all connections between the two IPs (both directions)
            matching_connections = []
            
            for connection in self.connection_tracker.values():
                if ((connection.src_ip == src_ip and connection.dst_ip == dst_ip) or
                    (connection.src_ip == dst_ip and connection.dst_ip == src_ip)):
                    matching_connections.append(connection)
            
            if not matching_connections:
                return None
            
            # Calculate summary statistics
            total_packets = sum(conn.packet_count for conn in matching_connections)
            total_bytes = sum(conn.bytes_sent + conn.bytes_received for conn in matching_connections)
            
            # Get unique protocols and ports
            protocols = list(set(conn.protocol for conn in matching_connections))
            all_ports = []
            for conn in matching_connections:
                if conn.src_port > 0:
                    all_ports.append(conn.src_port)
                if conn.dst_port > 0:
                    all_ports.append(conn.dst_port)
            ports = list(set(all_ports))
            
            # Get time range
            first_seen = min(conn.start_time for conn in matching_connections)
            last_seen = max(conn.last_seen for conn in matching_connections)
            duration = last_seen - first_seen
            
            return FlowInfo(
                src_ip=src_ip,
                dst_ip=dst_ip,
                total_packets=total_packets,
                total_bytes=total_bytes,
                duration=duration,
                protocols=protocols,
                ports=ports,
                first_seen=first_seen,
                last_seen=last_seen
            )
            
        except Exception as e:
            self.logger.error(f"Error getting flow summary: {e}")
            return None
    
    def get_active_connections(self) -> List[ConnectionInfo]:
        """
        Get list of currently active connections.
        
        Returns:
            List of active ConnectionInfo objects
        """
        return list(self.connection_tracker.values())
    
    def get_connection_count(self) -> int:
        """
        Get number of active connections.
        
        Returns:
            Number of active connections
        """
        return len(self.connection_tracker)
    
    def get_top_talkers(self, limit: int = 10) -> List[Tuple[str, int]]:
        """
        Get top talking IP addresses by packet count.
        
        Args:
            limit: Maximum number of results to return
            
        Returns:
            List of tuples (IP address, packet count)
        """
        ip_stats = defaultdict(int)
        
        for connection in self.connection_tracker.values():
            ip_stats[connection.src_ip] += connection.packet_count
            ip_stats[connection.dst_ip] += connection.packet_count
        
        # Sort by packet count and return top talkers
        sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1], reverse=True)
        return sorted_ips[:limit]
    
    def get_protocol_statistics(self) -> Dict[str, int]:
        """
        Get protocol distribution statistics.
        
        Returns:
            Dictionary mapping protocol names to packet counts
        """
        return dict(self.protocol_stats)
    
    def get_port_statistics(self, limit: int = 20) -> Dict[int, int]:
        """
        Get port usage statistics.
        
        Args:
            limit: Maximum number of ports to return
            
        Returns:
            Dictionary mapping port numbers to usage counts
        """
        sorted_ports = sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)
        return dict(sorted_ports[:limit])
    
    def get_analyzer_statistics(self) -> Dict[str, Any]:
        """
        Get overall analyzer statistics.
        
        Returns:
            Dictionary containing analyzer statistics
        """
        return {
            "packets_analyzed": self.packet_count,
            "total_bytes": self.total_bytes,
            "active_connections": len(self.connection_tracker),
            "unique_protocols": len(self.protocol_stats),
            "unique_ports": len(self.port_stats),
            "connection_timeout": self.connection_timeout
        }
    
    def reset_statistics(self) -> None:
        """Reset all statistics and clear connection tracker"""
        self.connection_tracker.clear()
        self.packet_count = 0
        self.total_bytes = 0
        self.protocol_stats.clear()
        self.port_stats.clear()
        self.logger.info("Analyzer statistics reset")


if __name__ == "__main__":
    # Simple test of packet analyzer functionality
    print("SpyNet Packet Analyzer Test")
    print("=" * 30)
    
    # Create analyzer instance
    analyzer = PacketAnalyzer()
    
    # Test with sample packet data (would normally come from PacketCapture)
    print("Packet analyzer initialized successfully")
    print(f"Initial statistics: {analyzer.get_analyzer_statistics()}")