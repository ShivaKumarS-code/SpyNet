# SpyNet Integrated System

This document describes the integrated SpyNet Network Intrusion Detection System that coordinates all components into a unified application.

## Architecture Overview

The integrated system consists of:

1. **SpyNet Core Application** (`spynet_app.py`) - Main coordinator
2. **FastAPI Web Interface** (`main.py`) - REST API and WebSocket endpoints
3. **Unified Runner** (`run_spynet.py`) - Single entry point for the complete system

## Components Integration

### Core Components
- **Packet Capture** - Network interface monitoring using Scapy
- **Packet Analyzer** - Protocol parsing and connection tracking
- **Threat Detector** - Port scan and DDoS detection
- **Anomaly Detector** - Machine learning-based anomaly detection
- **Alert Manager** - Alert processing, storage, and notifications

### Integration Features
- **Centralized Configuration** - Single configuration system for all components
- **Coordinated Startup/Shutdown** - Proper initialization and cleanup procedures
- **Real-time Statistics** - Live monitoring of system performance
- **Dynamic Configuration** - Runtime adjustment of detection thresholds
- **Comprehensive Logging** - Structured logging across all components

## Running the System

### Quick Start
```bash
# Start the complete system with default settings
python run_spynet.py

# Start with custom interface and port
python run_spynet.py -i eth1 --port 8080

# Start with email notifications disabled
python run_spynet.py --no-email
```

### Using Batch File (Windows)
```cmd
start_backend.bat
```

### Configuration Options

#### Command Line Arguments
- `-i, --interface` - Network interface to monitor
- `--host` - API server host (default: 0.0.0.0)
- `--port` - API server port (default: 8000)
- `--port-scan-threshold` - Port scan detection threshold
- `--ddos-threshold` - DDoS detection threshold
- `--no-email` - Disable email notifications
- `--debug` - Enable debug mode
- `--log-level` - Set logging level

#### Configuration File
Use `spynet_config.json` for persistent configuration:

```json
{
  "system": {
    "capture_interface": "auto",
    "log_level": "INFO"
  },
  "detection": {
    "port_scan_threshold": 10,
    "ddos_threshold": 100
  },
  "alerts": {
    "enable_email": true,
    "smtp_server": "smtp.gmail.com",
    "alert_emails": ["admin@example.com"]
  }
}
```

## API Endpoints

### System Control
- `GET /api/v1/system/status` - Get system status and statistics
- `GET /api/v1/system/activity` - Get recent activity summary
- `POST /api/v1/system/configure` - Update detection thresholds
- `POST /api/v1/system/reset-stats` - Reset system statistics

### Data Endpoints
- `GET /api/v1/traffic/stats` - Network traffic statistics
- `GET /api/v1/alerts` - Security alerts with filtering
- `GET /api/v1/traffic/top-talkers` - Most active IP addresses
- `GET /api/v1/connections/active` - Active network connections

### Real-time Data
- `WebSocket /ws/realtime` - Live data streaming

## System Status

The integrated system provides comprehensive status monitoring:

### Core System Status
- Packet capture status and interface information
- Analysis engine performance metrics
- Threat detection activity
- Anomaly detection model status
- Alert processing statistics

### Performance Metrics
- Packets captured and analyzed per second
- Memory usage and connection tracking
- Database performance
- API response times

## Error Handling

The system implements robust error handling:

1. **Component Isolation** - Failure in one component doesn't crash others
2. **Graceful Degradation** - System continues operating with reduced functionality
3. **Automatic Recovery** - Components attempt to recover from transient errors
4. **Comprehensive Logging** - All errors are logged with context

## Shutdown Procedures

The system supports graceful shutdown:

1. **Signal Handling** - Responds to SIGINT (Ctrl+C) and SIGTERM
2. **Component Cleanup** - Stops all threads and releases resources
3. **Final Statistics** - Logs comprehensive statistics on shutdown
4. **Database Cleanup** - Ensures all data is properly saved

## Troubleshooting

### Common Issues

1. **Permission Errors** - Run as administrator for packet capture
2. **Interface Detection** - Specify interface manually if auto-detection fails
3. **Database Connection** - Check database configuration and connectivity
4. **Email Notifications** - Verify SMTP settings and credentials

### Log Files
- `logs/spynet_main.log` - Core system logs
- `logs/spynet_runner.log` - Integrated system runner logs
- `logs/alerts.log` - Security alert logs

### Debug Mode
Enable debug mode for detailed logging:
```bash
python run_spynet.py --debug --log-level DEBUG
```

## Security Considerations

1. **Network Access** - Requires appropriate network interface permissions
2. **Database Security** - Use secure database credentials
3. **Email Security** - Use secure SMTP authentication
4. **API Security** - Consider adding authentication for production use

## Performance Tuning

### Buffer Sizes
- Increase `packet_buffer_size` for high-traffic networks
- Adjust `connection_timeout` based on network characteristics

### Detection Thresholds
- Tune `port_scan_threshold` to reduce false positives
- Adjust `ddos_threshold` based on normal traffic patterns
- Configure `anomaly_contamination` based on expected anomaly rate

### Database Optimization
- Regular cleanup of old alerts and packet data
- Proper indexing for query performance
- Connection pooling for concurrent access

## Integration with Frontend

The system provides WebSocket endpoints for real-time frontend integration:

1. **Live Statistics** - Real-time traffic and threat statistics
2. **Alert Notifications** - Immediate alert delivery to web interface
3. **System Status** - Live system health monitoring
4. **Interactive Control** - Dynamic configuration through web interface

This integrated system provides a complete, production-ready network intrusion detection solution with comprehensive monitoring, alerting, and management capabilities.