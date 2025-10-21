"""
Pydantic models for API request/response validation
"""
from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict


class TrafficStatsResponse(BaseModel):
    """Response model for traffic statistics"""
    model_config = ConfigDict(from_attributes=True)
    
    total_packets: int = Field(description="Total number of packets captured")
    total_bytes: int = Field(description="Total bytes of traffic")
    time_period_hours: int = Field(description="Time period analyzed in hours")
    avg_packets_per_hour: float = Field(description="Average packets per hour")
    avg_bytes_per_hour: float = Field(description="Average bytes per hour")
    protocol_distribution: List[Dict[str, Any]] = Field(description="Distribution of protocols")
    top_sources: List[Dict[str, Any]] = Field(description="Top source IP addresses")


class AlertResponse(BaseModel):
    """Response model for security alerts"""
    model_config = ConfigDict(from_attributes=True)
    
    id: int = Field(description="Alert ID")
    timestamp: datetime = Field(description="When the alert was created")
    alert_type: str = Field(description="Type of security alert")
    severity: str = Field(description="Alert severity level")
    source_ip: str = Field(description="Source IP address")
    destination_ip: Optional[str] = Field(None, description="Destination IP address")
    description: str = Field(description="Alert description")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional alert details")
    resolved: bool = Field(description="Whether the alert has been resolved")
    resolved_at: Optional[datetime] = Field(None, description="When the alert was resolved")
    resolved_by: Optional[str] = Field(None, description="Who resolved the alert")


class TopTalkersResponse(BaseModel):
    """Response model for top talkers (most active IPs)"""
    model_config = ConfigDict(from_attributes=True)
    
    top_talkers: List[Dict[str, Any]] = Field(description="List of top talking IP addresses")
    time_period_hours: int = Field(description="Time period analyzed in hours")
    total_unique_sources: int = Field(description="Total number of unique source IPs")


class ConnectionResponse(BaseModel):
    """Response model for network connections"""
    model_config = ConfigDict(from_attributes=True)
    
    id: int = Field(description="Connection ID")
    src_ip: str = Field(description="Source IP address")
    dst_ip: str = Field(description="Destination IP address")
    src_port: Optional[int] = Field(None, description="Source port")
    dst_port: Optional[int] = Field(None, description="Destination port")
    protocol: str = Field(description="Network protocol")
    first_seen: datetime = Field(description="When connection was first observed")
    last_seen: datetime = Field(description="When connection was last observed")
    packet_count: int = Field(description="Number of packets in this connection")
    bytes_sent: int = Field(description="Bytes sent from source to destination")
    bytes_received: int = Field(description="Bytes received from destination to source")
    state: str = Field(description="Connection state")
    avg_packet_size: float = Field(description="Average packet size")
    connection_duration: float = Field(description="Connection duration in seconds")


class AlertCreateRequest(BaseModel):
    """Request model for creating alerts"""
    alert_type: str = Field(description="Type of security alert")
    severity: str = Field(description="Alert severity (Low, Medium, High, Critical)")
    source_ip: str = Field(description="Source IP address")
    destination_ip: Optional[str] = Field(None, description="Destination IP address")
    description: str = Field(description="Alert description")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional alert details")


class AlertResolveRequest(BaseModel):
    """Request model for resolving alerts"""
    resolved_by: Optional[str] = Field(None, description="Username of who resolved the alert")


class PacketInfoResponse(BaseModel):
    """Response model for packet information"""
    model_config = ConfigDict(from_attributes=True)
    
    id: int = Field(description="Packet ID")
    timestamp: datetime = Field(description="Packet timestamp")
    src_ip: str = Field(description="Source IP address")
    dst_ip: str = Field(description="Destination IP address")
    src_port: Optional[int] = Field(None, description="Source port")
    dst_port: Optional[int] = Field(None, description="Destination port")
    protocol: str = Field(description="Network protocol")
    size: int = Field(description="Packet size in bytes")
    tcp_flags: Optional[str] = Field(None, description="TCP flags")
    payload_size: int = Field(description="Payload size in bytes")


class SystemStatusResponse(BaseModel):
    """Response model for system status"""
    status: str = Field(description="Overall system status")
    timestamp: datetime = Field(description="Status timestamp")
    statistics: Dict[str, Any] = Field(description="System statistics")
    websocket_connections: int = Field(description="Number of active WebSocket connections")


class WebSocketMessage(BaseModel):
    """Model for WebSocket messages"""
    type: str = Field(description="Message type")
    data: Optional[Dict[str, Any]] = Field(None, description="Message data")
    timestamp: datetime = Field(description="Message timestamp")


class SubscriptionRequest(BaseModel):
    """Model for WebSocket subscription requests"""
    type: str = Field(default="subscribe", description="Message type")
    data_types: List[str] = Field(description="List of data types to subscribe to")


class PingRequest(BaseModel):
    """Model for WebSocket ping requests"""
    type: str = Field(default="ping", description="Message type")