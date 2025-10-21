# SpyNet API Documentation

## Overview

The SpyNet API provides comprehensive endpoints for network traffic analysis, security alert management, and real-time monitoring. Built with FastAPI, it offers automatic OpenAPI documentation, WebSocket support for real-time data streaming, and robust error handling.

## Base URL

```
http://localhost:8000
```

## API Documentation

- **Interactive API Docs (Swagger UI)**: http://localhost:8000/docs
- **ReDoc Documentation**: http://localhost:8000/redoc
- **OpenAPI Schema**: http://localhost:8000/openapi.json

## Authentication

Currently, the API does not require authentication. In production, implement proper authentication mechanisms.

## CORS Configuration

The API is configured to accept requests from:
- `http://localhost:3000` (Next.js frontend)
- `http://127.0.0.1:3000`

## Endpoints

### System Endpoints

#### GET /
Root endpoint providing basic API information.

**Response:**
```json
{
  "message": "SpyNet API is running",
  "version": "1.0.0",
  "status": "healthy",
  "endpoints": {
    "docs": "/docs",
    "redoc": "/redoc",
    "health": "/health",
    "api": "/api/v1"
  }
}
```

#### GET /health
Health check endpoint for monitoring API status.

**Response:**
```json
{
  "status": "healthy",
  "service": "spynet-api",
  "database": "healthy",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

### Traffic Analysis Endpoints

#### GET /api/v1/traffic/stats
Get comprehensive network traffic statistics.

**Parameters:**
- `hours` (query, optional): Hours of data to analyze (1-168, default: 24)

**Response:**
```json
{
  "total_packets": 15420,
  "total_bytes": 2048576,
  "time_period_hours": 24,
  "avg_packets_per_hour": 642.5,
  "avg_bytes_per_hour": 85357.33,
  "protocol_distribution": [
    {"protocol": "TCP", "count": 12000},
    {"protocol": "UDP", "count": 2800},
    {"protocol": "ICMP", "count": 620}
  ],
  "top_sources": [
    {
      "ip": "192.168.1.100",
      "packet_count": 1500,
      "total_bytes": 204800
    }
  ]
}
```

#### GET /api/v1/traffic/top-talkers
Get the most active IP addresses by traffic volume.

**Parameters:**
- `limit` (query, optional): Number of top talkers to return (1-100, default: 10)
- `hours` (query, optional): Hours of data to analyze (1-168, default: 24)

**Response:**
```json
{
  "top_talkers": [
    {
      "ip": "192.168.1.100",
      "packet_count": 1500,
      "total_bytes": 204800
    }
  ],
  "time_period_hours": 24,
  "total_unique_sources": 45
}
```

### Security Alert Endpoints

#### GET /api/v1/alerts
Get security alerts with optional filtering.

**Parameters:**
- `limit` (query, optional): Maximum alerts to return (1-1000, default: 50)
- `severity` (query, optional): Filter by severity (Low, Medium, High, Critical)
- `resolved` (query, optional): Filter by resolution status (true/false)
- `hours` (query, optional): Only show alerts from last N hours (1-168)

**Response:**
```json
[
  {
    "id": 1,
    "timestamp": "2024-01-01T12:00:00.000Z",
    "alert_type": "port_scan",
    "severity": "Medium",
    "source_ip": "192.168.1.100",
    "destination_ip": "192.168.1.1",
    "description": "Port scan detected from 192.168.1.100",
    "details": {
      "ports_scanned": [22, 80, 443, 8080],
      "scan_duration": 30
    },
    "resolved": false,
    "resolved_at": null,
    "resolved_by": null
  }
]
```

#### GET /api/v1/alerts/unresolved
Get all unresolved security alerts.

**Response:** Same format as `/api/v1/alerts` but filtered to unresolved alerts only.

#### POST /api/v1/alerts/{alert_id}/resolve
Mark a specific alert as resolved.

**Parameters:**
- `alert_id` (path): ID of the alert to resolve

**Request Body:**
```json
{
  "resolved_by": "admin_user"
}
```

**Response:**
```json
{
  "message": "Alert resolved successfully",
  "alert_id": 1
}
```

### Connection Monitoring Endpoints

#### GET /api/v1/connections/active
Get currently active network connections.

**Parameters:**
- `limit` (query, optional): Maximum connections to return (1-1000, default: 100)

**Response:**
```json
[
  {
    "id": 1,
    "src_ip": "192.168.1.100",
    "dst_ip": "8.8.8.8",
    "src_port": 54321,
    "dst_port": 53,
    "protocol": "UDP",
    "first_seen": "2024-01-01T11:30:00.000Z",
    "last_seen": "2024-01-01T12:00:00.000Z",
    "packet_count": 25,
    "bytes_sent": 1250,
    "bytes_received": 1500,
    "state": "ACTIVE",
    "avg_packet_size": 110.0,
    "connection_duration": 1800.0
  }
]
```

### System Status Endpoints

#### GET /api/v1/system/status
Get comprehensive system status and statistics.

**Response:**
```json
{
  "status": "operational",
  "timestamp": "2024-01-01T12:00:00.000Z",
  "statistics": {
    "last_24h": {
      "packets": 15420,
      "bytes": 2048576,
      "unique_sources": 45
    },
    "last_1h": {
      "packets": 642,
      "bytes": 85357,
      "unique_sources": 12
    },
    "alerts": {
      "unresolved_count": 3,
      "critical_unresolved": 1
    },
    "connections": {
      "active_count": 28
    }
  },
  "websocket_connections": 2
}
```

## WebSocket Endpoint

### WS /ws/realtime
Real-time data streaming via WebSocket connection.

**Connection URL:**
```
ws://localhost:8000/ws/realtime
```

**Message Types:**

#### Client to Server Messages

**Subscribe to Data Types:**
```json
{
  "type": "subscribe",
  "data_types": ["alerts", "traffic", "connections"]
}
```

**Ping:**
```json
{
  "type": "ping"
}
```

#### Server to Client Messages

**Welcome Message:**
```json
{
  "type": "welcome",
  "message": "Connected to SpyNet real-time data stream",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

**Traffic Update:**
```json
{
  "type": "traffic_update",
  "data": {
    "total_packets": 15420,
    "total_bytes": 2048576,
    "protocol_distribution": [...]
  },
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

**Alert Count Update:**
```json
{
  "type": "alert_count",
  "data": {
    "unresolved_count": 3,
    "critical_count": 1
  },
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

**Alert Resolution Notification:**
```json
{
  "type": "alert_resolved",
  "alert_id": 1,
  "resolved_by": "admin_user",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

**Pong Response:**
```json
{
  "type": "pong",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

## Error Responses

All endpoints return appropriate HTTP status codes and error messages:

**400 Bad Request:**
```json
{
  "detail": "Invalid parameter value"
}
```

**404 Not Found:**
```json
{
  "detail": "Alert not found"
}
```

**500 Internal Server Error:**
```json
{
  "detail": "Failed to retrieve traffic statistics"
}
```

## Rate Limiting

Currently, no rate limiting is implemented. Consider adding rate limiting for production use.

## Data Models

### TrafficStatsResponse
- `total_packets`: Total number of packets
- `total_bytes`: Total bytes of traffic
- `time_period_hours`: Analysis time period
- `avg_packets_per_hour`: Average packets per hour
- `avg_bytes_per_hour`: Average bytes per hour
- `protocol_distribution`: Array of protocol counts
- `top_sources`: Array of top source IPs

### AlertResponse
- `id`: Alert ID
- `timestamp`: Alert creation time
- `alert_type`: Type of security alert
- `severity`: Alert severity level
- `source_ip`: Source IP address
- `destination_ip`: Destination IP (optional)
- `description`: Alert description
- `details`: Additional alert details (optional)
- `resolved`: Resolution status
- `resolved_at`: Resolution timestamp (optional)
- `resolved_by`: Who resolved the alert (optional)

### ConnectionResponse
- `id`: Connection ID
- `src_ip`: Source IP address
- `dst_ip`: Destination IP address
- `src_port`: Source port (optional)
- `dst_port`: Destination port (optional)
- `protocol`: Network protocol
- `first_seen`: First observation time
- `last_seen`: Last observation time
- `packet_count`: Number of packets
- `bytes_sent`: Bytes sent from source
- `bytes_received`: Bytes received from destination
- `state`: Connection state
- `avg_packet_size`: Average packet size
- `connection_duration`: Duration in seconds

## Usage Examples

### Python Client Example

```python
import requests
import websocket
import json

# Get traffic stats
response = requests.get("http://localhost:8000/api/v1/traffic/stats?hours=1")
stats = response.json()
print(f"Packets in last hour: {stats['total_packets']}")

# Get unresolved alerts
response = requests.get("http://localhost:8000/api/v1/alerts/unresolved")
alerts = response.json()
print(f"Unresolved alerts: {len(alerts)}")

# WebSocket connection
def on_message(ws, message):
    data = json.loads(message)
    print(f"Received: {data['type']}")

ws = websocket.WebSocketApp("ws://localhost:8000/ws/realtime",
                          on_message=on_message)
ws.run_forever()
```

### JavaScript Client Example

```javascript
// Fetch traffic stats
fetch('http://localhost:8000/api/v1/traffic/stats')
  .then(response => response.json())
  .then(data => console.log('Traffic stats:', data));

// WebSocket connection
const ws = new WebSocket('ws://localhost:8000/ws/realtime');

ws.onmessage = function(event) {
  const data = JSON.parse(event.data);
  console.log('Received:', data.type, data);
};

ws.onopen = function() {
  // Subscribe to alerts and traffic updates
  ws.send(JSON.stringify({
    type: 'subscribe',
    data_types: ['alerts', 'traffic']
  }));
};
```

## Development and Testing

1. **Start the API server:**
   ```bash
   cd backend
   python main.py
   ```

2. **Access API documentation:**
   - Swagger UI: http://localhost:8000/docs
   - ReDoc: http://localhost:8000/redoc

3. **Test endpoints:**
   ```bash
   # Test basic connectivity
   curl http://localhost:8000/health
   
   # Test traffic stats
   curl http://localhost:8000/api/v1/traffic/stats
   
   # Test alerts
   curl http://localhost:8000/api/v1/alerts?limit=10
   ```

4. **Test WebSocket connection:**
   ```bash
   # Using websocat (install with: cargo install websocat)
   websocat ws://localhost:8000/ws/realtime
   ```

## Production Considerations

1. **Security:**
   - Implement authentication and authorization
   - Add rate limiting
   - Use HTTPS in production
   - Validate and sanitize all inputs

2. **Performance:**
   - Add caching for frequently accessed data
   - Implement database connection pooling
   - Consider using async database drivers
   - Add monitoring and logging

3. **Scalability:**
   - Use load balancers for multiple API instances
   - Implement horizontal scaling for WebSocket connections
   - Consider using Redis for WebSocket session management
   - Add database read replicas for heavy read workloads