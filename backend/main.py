"""
SpyNet Backend - Main application entry point
"""
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json
import asyncio
import logging

from config import settings
from models import get_db, Alert, PacketInfo, Connection
from database import db_ops
from api_models import (
    TrafficStatsResponse, AlertResponse, TopTalkersResponse, 
    ConnectionResponse, AlertCreateRequest, AlertResolveRequest
)
from config_api import get_config_router

# Configure logging
logging.basicConfig(level=getattr(logging, settings.log_level.upper()))
logger = logging.getLogger(__name__)

# Create FastAPI application
app = FastAPI(
    title="SpyNet API",
    description="Network Traffic Analyzer and Intrusion Detection System API",
    version="1.0.0",
    debug=settings.debug,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # Frontend URLs
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include configuration API router
app.include_router(get_config_router())

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except Exception as e:
            logger.error(f"Error sending personal message: {e}")
            self.disconnect(websocket)

    async def broadcast(self, message: str):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Error broadcasting to connection: {e}")
                disconnected.append(connection)
        
        # Remove disconnected connections
        for conn in disconnected:
            self.disconnect(conn)

manager = ConnectionManager()


# Root and health endpoints
@app.get("/")
async def root():
    """Root endpoint"""
    return {
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


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        stats = db_ops.get_traffic_stats(hours=1)
        db_status = "healthy"
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = "unhealthy"
    
    return {
        "status": "healthy" if db_status == "healthy" else "degraded",
        "service": "spynet-api",
        "database": db_status,
        "timestamp": datetime.utcnow().isoformat()
    }


# API v1 endpoints
@app.get("/api/v1/traffic/stats", response_model=TrafficStatsResponse)
async def get_traffic_stats(
    hours: int = Query(24, ge=1, le=168, description="Hours of data to analyze (1-168)")
):
    """
    Get network traffic statistics for the specified time period.
    
    - **hours**: Number of hours to analyze (default: 24, max: 168 for 1 week)
    
    Returns comprehensive traffic statistics including:
    - Total packets and bytes
    - Protocol distribution
    - Top source IPs
    - Traffic trends
    """
    try:
        stats = db_ops.get_traffic_stats(hours=hours)
        
        # Add additional computed metrics
        stats['time_period_hours'] = hours
        stats['avg_packets_per_hour'] = stats['total_packets'] / hours if hours > 0 else 0
        stats['avg_bytes_per_hour'] = stats['total_bytes'] / hours if hours > 0 else 0
        
        return TrafficStatsResponse(**stats)
    except Exception as e:
        logger.error(f"Error getting traffic stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve traffic statistics")


@app.get("/api/v1/alerts", response_model=List[AlertResponse])
async def get_alerts(
    limit: int = Query(50, ge=1, le=1000, description="Maximum number of alerts to return"),
    severity: Optional[str] = Query(None, description="Filter by severity (Low, Medium, High, Critical)"),
    resolved: Optional[bool] = Query(None, description="Filter by resolution status"),
    hours: Optional[int] = Query(None, ge=1, le=168, description="Only show alerts from last N hours")
):
    """
    Get security alerts with optional filtering.
    
    - **limit**: Maximum number of alerts to return (1-1000)
    - **severity**: Filter by severity level
    - **resolved**: Filter by resolution status
    - **hours**: Only show alerts from the last N hours
    
    Returns a list of security alerts with detailed information.
    """
    try:
        if resolved is not None:
            if resolved:
                alerts = db_ops.get_resolved_alerts(limit=limit)
            else:
                alerts = db_ops.get_unresolved_alerts()
                alerts = alerts[:limit]  # Apply limit
        else:
            alerts = db_ops.get_recent_alerts(limit=limit, severity=severity)
        
        # Filter by time if specified
        if hours:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            alerts = [alert for alert in alerts if alert.timestamp >= cutoff]
        
        return [AlertResponse.from_orm(alert) for alert in alerts]
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve alerts")


@app.get("/api/v1/alerts/unresolved", response_model=List[AlertResponse])
async def get_unresolved_alerts():
    """
    Get all unresolved security alerts.
    
    Returns all alerts that haven't been marked as resolved.
    """
    try:
        alerts = db_ops.get_unresolved_alerts()
        return [AlertResponse.from_orm(alert) for alert in alerts]
    except Exception as e:
        logger.error(f"Error getting unresolved alerts: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve unresolved alerts")


@app.post("/api/v1/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: int,
    request: AlertResolveRequest
):
    """
    Mark an alert as resolved.
    
    - **alert_id**: ID of the alert to resolve
    - **resolved_by**: Optional username of who resolved the alert
    """
    try:
        success = db_ops.resolve_alert(alert_id, request.resolved_by)
        if not success:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Broadcast alert resolution to WebSocket clients
        await manager.broadcast(json.dumps({
            "type": "alert_resolved",
            "alert_id": alert_id,
            "resolved_by": request.resolved_by,
            "timestamp": datetime.utcnow().isoformat()
        }))
        
        return {"message": "Alert resolved successfully", "alert_id": alert_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resolving alert {alert_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to resolve alert")


@app.get("/api/v1/traffic/top-talkers", response_model=TopTalkersResponse)
async def get_top_talkers(
    limit: int = Query(10, ge=1, le=100, description="Number of top talkers to return"),
    hours: int = Query(24, ge=1, le=168, description="Hours of data to analyze")
):
    """
    Get the most active IP addresses (top talkers) by packet count and bytes.
    
    - **limit**: Number of top talkers to return (1-100)
    - **hours**: Hours of data to analyze (1-168)
    
    Returns the most active source IPs with their traffic statistics.
    """
    try:
        stats = db_ops.get_traffic_stats(hours=hours)
        top_sources = stats.get('top_sources', [])[:limit]
        
        return TopTalkersResponse(
            top_talkers=top_sources,
            time_period_hours=hours,
            total_unique_sources=len(top_sources)
        )
    except Exception as e:
        logger.error(f"Error getting top talkers: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve top talkers")


@app.get("/api/v1/connections/active", response_model=List[ConnectionResponse])
async def get_active_connections(
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of connections to return")
):
    """
    Get currently active network connections.
    
    - **limit**: Maximum number of connections to return (1-1000)
    
    Returns a list of active network connections with flow statistics.
    """
    try:
        connections = db_ops.get_active_connections(limit=limit)
        return [ConnectionResponse.from_orm(conn) for conn in connections]
    except Exception as e:
        logger.error(f"Error getting active connections: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve active connections")


@app.get("/api/v1/system/status")
async def get_system_status():
    """
    Get overall system status and statistics.
    
    Returns comprehensive system health and performance metrics.
    """
    try:
        # Get basic stats from database
        stats_24h = db_ops.get_traffic_stats(hours=24)
        stats_1h = db_ops.get_traffic_stats(hours=1)
        unresolved_alerts = db_ops.get_unresolved_alerts()
        active_connections = db_ops.get_active_connections(limit=1000)
        
        # Get SpyNet core system status if available
        spynet_status = {}
        if spynet_app:
            try:
                spynet_status = spynet_app.get_status()
            except Exception as e:
                logger.warning(f"Could not get SpyNet core status: {e}")
        
        return {
            "status": "operational" if spynet_status.get("running", False) else "degraded",
            "timestamp": datetime.utcnow().isoformat(),
            "core_system": spynet_status,
            "statistics": {
                "last_24h": {
                    "packets": stats_24h['total_packets'],
                    "bytes": stats_24h['total_bytes'],
                    "unique_sources": len(stats_24h['top_sources'])
                },
                "last_1h": {
                    "packets": stats_1h['total_packets'],
                    "bytes": stats_1h['total_bytes'],
                    "unique_sources": len(stats_1h['top_sources'])
                },
                "alerts": {
                    "unresolved_count": len(unresolved_alerts),
                    "critical_unresolved": len([a for a in unresolved_alerts if a.severity == 'Critical'])
                },
                "connections": {
                    "active_count": len(active_connections)
                }
            },
            "websocket_connections": len(manager.active_connections)
        }
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve system status")


@app.get("/api/v1/system/activity")
async def get_system_activity(
    minutes: int = Query(60, ge=1, le=1440, description="Time window in minutes")
):
    """
    Get recent system activity summary.
    
    - **minutes**: Time window in minutes (1-1440 for up to 24 hours)
    
    Returns recent activity including threat detection, anomalies, and network analysis.
    """
    try:
        if spynet_app:
            activity = spynet_app.get_recent_activity(minutes=minutes)
            return activity
        else:
            return {
                "error": "SpyNet core system not available",
                "time_window_minutes": minutes,
                "timestamp": datetime.utcnow().isoformat()
            }
    except Exception as e:
        logger.error(f"Error getting system activity: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve system activity")


@app.post("/api/v1/system/configure")
async def configure_system(
    port_scan_threshold: Optional[int] = None,
    ddos_threshold: Optional[int] = None,
    anomaly_contamination: Optional[float] = None
):
    """
    Configure system detection thresholds dynamically.
    
    - **port_scan_threshold**: Number of ports scanned before triggering alert
    - **ddos_threshold**: Connection rate threshold for DDoS detection
    - **anomaly_contamination**: Expected proportion of anomalies (0.0-1.0)
    
    Updates detection parameters without restarting the system.
    """
    try:
        if not spynet_app:
            raise HTTPException(status_code=503, detail="SpyNet core system not available")
        
        config_params = {}
        if port_scan_threshold is not None:
            config_params["port_scan_threshold"] = port_scan_threshold
        if ddos_threshold is not None:
            config_params["ddos_threshold"] = ddos_threshold
        if anomaly_contamination is not None:
            config_params["anomaly_contamination"] = anomaly_contamination
        
        if not config_params:
            raise HTTPException(status_code=400, detail="No configuration parameters provided")
        
        success = spynet_app.configure_detection_thresholds(**config_params)
        
        if success:
            return {
                "message": "Configuration updated successfully",
                "updated_parameters": config_params,
                "timestamp": datetime.utcnow().isoformat()
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to update configuration")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error configuring system: {e}")
        raise HTTPException(status_code=500, detail="Failed to configure system")


@app.post("/api/v1/system/reset-stats")
async def reset_system_statistics():
    """
    Reset all system statistics and counters.
    
    Clears packet counts, threat detection statistics, and connection tracking
    while keeping the system running.
    """
    try:
        if not spynet_app:
            raise HTTPException(status_code=503, detail="SpyNet core system not available")
        
        spynet_app.reset_statistics()
        
        return {
            "message": "System statistics reset successfully",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error resetting statistics: {e}")
        raise HTTPException(status_code=500, detail="Failed to reset statistics")


# WebSocket endpoint for real-time data streaming
@app.websocket("/ws/realtime")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time data streaming.
    
    Provides live updates for:
    - New security alerts
    - Traffic statistics
    - System status changes
    - Active connections
    
    Send JSON messages with 'type' field to subscribe to specific data types:
    - {"type": "subscribe", "data_types": ["alerts", "traffic", "connections"]}
    """
    await manager.connect(websocket)
    
    # Send welcome message
    await manager.send_personal_message(json.dumps({
        "type": "welcome",
        "message": "Connected to SpyNet real-time data stream",
        "timestamp": datetime.utcnow().isoformat()
    }), websocket)
    
    try:
        # Send initial data
        initial_stats = db_ops.get_traffic_stats(hours=1)
        await manager.send_personal_message(json.dumps({
            "type": "traffic_stats",
            "data": initial_stats,
            "timestamp": datetime.utcnow().isoformat()
        }), websocket)
        
        # Keep connection alive and handle incoming messages
        while True:
            try:
                # Wait for messages from client
                data = await websocket.receive_text()
                message = json.loads(data)
                
                # Handle subscription requests
                if message.get("type") == "subscribe":
                    data_types = message.get("data_types", [])
                    await manager.send_personal_message(json.dumps({
                        "type": "subscription_confirmed",
                        "data_types": data_types,
                        "timestamp": datetime.utcnow().isoformat()
                    }), websocket)
                
                # Handle ping requests
                elif message.get("type") == "ping":
                    await manager.send_personal_message(json.dumps({
                        "type": "pong",
                        "timestamp": datetime.utcnow().isoformat()
                    }), websocket)
                
            except WebSocketDisconnect:
                break
            except json.JSONDecodeError:
                await manager.send_personal_message(json.dumps({
                    "type": "error",
                    "message": "Invalid JSON format",
                    "timestamp": datetime.utcnow().isoformat()
                }), websocket)
            except Exception as e:
                logger.error(f"WebSocket message handling error: {e}")
                await manager.send_personal_message(json.dumps({
                    "type": "error",
                    "message": "Message processing error",
                    "timestamp": datetime.utcnow().isoformat()
                }), websocket)
                
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket connection error: {e}")
    finally:
        manager.disconnect(websocket)


# Background task for real-time data broadcasting
async def broadcast_realtime_data():
    """Background task to broadcast real-time data to WebSocket clients"""
    while True:
        try:
            if manager.active_connections:
                # Get current stats
                stats = db_ops.get_traffic_stats(hours=1)
                unresolved_alerts = db_ops.get_unresolved_alerts()
                
                # Broadcast traffic stats
                await manager.broadcast(json.dumps({
                    "type": "traffic_update",
                    "data": stats,
                    "timestamp": datetime.utcnow().isoformat()
                }))
                
                # Broadcast alert count
                await manager.broadcast(json.dumps({
                    "type": "alert_count",
                    "data": {
                        "unresolved_count": len(unresolved_alerts),
                        "critical_count": len([a for a in unresolved_alerts if a.severity == 'Critical'])
                    },
                    "timestamp": datetime.utcnow().isoformat()
                }))
            
            # Wait 30 seconds before next broadcast
            await asyncio.sleep(30)
            
        except Exception as e:
            logger.error(f"Error in real-time broadcast: {e}")
            await asyncio.sleep(30)


# Global SpyNet application instance
spynet_app = None

# Startup event to initialize background tasks
@app.on_event("startup")
async def startup_event():
    """Initialize background tasks and SpyNet core system on startup"""
    global spynet_app
    logger.info("SpyNet API starting up...")
    
    try:
        # Initialize SpyNet core application
        from spynet_app import SpyNetApp
        spynet_app = SpyNetApp()
        
        # Start SpyNet in a separate thread to avoid blocking the API
        import threading
        def start_spynet():
            if not spynet_app.start():
                logger.error("Failed to start SpyNet core system")
        
        spynet_thread = threading.Thread(target=start_spynet, daemon=True)
        spynet_thread.start()
        
        logger.info("SpyNet core system initialization started")
        
    except Exception as e:
        logger.error(f"Error initializing SpyNet core system: {e}")
    
    # Start background task for real-time data broadcasting
    asyncio.create_task(broadcast_realtime_data())
    
    logger.info("SpyNet API startup complete")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    global spynet_app
    logger.info("SpyNet API shutting down...")
    
    try:
        # Stop SpyNet core system
        if spynet_app:
            spynet_app.stop()
            logger.info("SpyNet core system stopped")
    except Exception as e:
        logger.error(f"Error stopping SpyNet core system: {e}")
    
    logger.info("SpyNet API shutdown complete")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug
    )