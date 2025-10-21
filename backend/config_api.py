"""
SpyNet Configuration API

This module provides REST API endpoints for configuration management,
including detection thresholds, alert settings, interface configuration,
and custom rule management.
"""

from fastapi import APIRouter, HTTPException, Depends, Query, Body
from fastapi.responses import JSONResponse
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime
import logging

from config_manager import config_manager, CustomRule, DetectionThresholds, AlertConfiguration, InterfaceConfiguration


# Pydantic models for API requests/responses
class DetectionThresholdsRequest(BaseModel):
    """Request model for updating detection thresholds"""
    port_scan_threshold: Optional[int] = Field(None, ge=1, le=1000)
    ddos_threshold: Optional[int] = Field(None, ge=1, le=10000)
    anomaly_contamination: Optional[float] = Field(None, ge=0.001, le=0.999)
    scan_time_window: Optional[int] = Field(None, ge=60, le=3600)
    ddos_time_window: Optional[int] = Field(None, ge=10, le=600)
    connection_timeout: Optional[int] = Field(None, ge=60, le=7200)
    brute_force_threshold: Optional[int] = Field(None, ge=1, le=100)
    brute_force_time_window: Optional[int] = Field(None, ge=60, le=3600)


class AlertConfigurationRequest(BaseModel):
    """Request model for updating alert configuration"""
    enable_email: Optional[bool] = None
    enable_syslog: Optional[bool] = None
    enable_webhook: Optional[bool] = None
    critical_only: Optional[bool] = None
    dedup_window_minutes: Optional[int] = Field(None, ge=1, le=60)
    max_alerts_per_hour: Optional[int] = Field(None, ge=1, le=1000)
    alert_retention_days: Optional[int] = Field(None, ge=1, le=365)
    smtp_server: Optional[str] = None
    smtp_port: Optional[int] = Field(None, ge=1, le=65535)
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_use_tls: Optional[bool] = None
    alert_emails: Optional[List[str]] = None
    webhook_url: Optional[str] = None
    webhook_timeout: Optional[int] = Field(None, ge=1, le=300)
    syslog_server: Optional[str] = None
    syslog_port: Optional[int] = Field(None, ge=1, le=65535)
    syslog_facility: Optional[str] = None


class InterfaceConfigurationRequest(BaseModel):
    """Request model for updating interface configuration"""
    capture_interface: Optional[str] = None
    packet_buffer_size: Optional[int] = Field(None, ge=100, le=100000)
    capture_timeout: Optional[int] = Field(None, ge=1, le=60)
    promiscuous_mode: Optional[bool] = None
    packet_filters: Optional[List[str]] = None
    excluded_ips: Optional[List[str]] = None
    included_ips: Optional[List[str]] = None
    excluded_ports: Optional[List[int]] = None
    included_ports: Optional[List[int]] = None
    max_packet_size: Optional[int] = Field(None, ge=64, le=65535)


class CustomRuleRequest(BaseModel):
    """Request model for custom rule operations"""
    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field(..., min_length=1, max_length=500)
    pattern: str = Field(..., min_length=1, max_length=1000)
    pattern_type: str = Field(..., regex="^(regex|string|bytes)$")
    severity: str = Field(..., regex="^(Low|Medium|High|Critical)$")
    enabled: bool = True
    protocol: str = Field("any", regex="^(tcp|udp|icmp|any)$")
    ports: List[int] = Field(default_factory=list)


class CustomRuleUpdateRequest(BaseModel):
    """Request model for updating custom rules"""
    description: Optional[str] = Field(None, min_length=1, max_length=500)
    pattern: Optional[str] = Field(None, min_length=1, max_length=1000)
    pattern_type: Optional[str] = Field(None, regex="^(regex|string|bytes)$")
    severity: Optional[str] = Field(None, regex="^(Low|Medium|High|Critical)$")
    enabled: Optional[bool] = None
    protocol: Optional[str] = Field(None, regex="^(tcp|udp|icmp|any)$")
    ports: Optional[List[int]] = None


class ConfigurationExportRequest(BaseModel):
    """Request model for configuration export"""
    format: str = Field("json", regex="^(json|yaml)$")
    include_sensitive: bool = Field(False, description="Include sensitive data like passwords")


class ConfigurationImportRequest(BaseModel):
    """Request model for configuration import"""
    config_data: Dict[str, Any]
    merge_with_existing: bool = Field(False, description="Merge with existing configuration")


# Create API router
router = APIRouter(prefix="/api/v1/config", tags=["Configuration"])

# Setup logging
logger = logging.getLogger(__name__)


@router.get("/summary")
async def get_configuration_summary():
    """
    Get a summary of the current configuration.
    
    Returns overview of detection thresholds, alert settings, interface configuration,
    and custom rules without sensitive information.
    """
    try:
        summary = config_manager.get_configuration_summary()
        return JSONResponse(content={
            "status": "success",
            "data": summary,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting configuration summary: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve configuration summary")


@router.get("/detection/thresholds")
async def get_detection_thresholds():
    """
    Get current detection thresholds.
    
    Returns all detection threshold settings including port scan, DDoS,
    and anomaly detection parameters.
    """
    try:
        thresholds = config_manager.get_detection_thresholds()
        return JSONResponse(content={
            "status": "success",
            "data": {
                "port_scan_threshold": thresholds.port_scan_threshold,
                "ddos_threshold": thresholds.ddos_threshold,
                "anomaly_contamination": thresholds.anomaly_contamination,
                "scan_time_window": thresholds.scan_time_window,
                "ddos_time_window": thresholds.ddos_time_window,
                "connection_timeout": thresholds.connection_timeout,
                "brute_force_threshold": thresholds.brute_force_threshold,
                "brute_force_time_window": thresholds.brute_force_time_window
            },
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting detection thresholds: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve detection thresholds")


@router.put("/detection/thresholds")
async def update_detection_thresholds(request: DetectionThresholdsRequest):
    """
    Update detection thresholds.
    
    Updates one or more detection threshold parameters. Only provided
    parameters will be updated, others remain unchanged.
    """
    try:
        # Convert request to dictionary, excluding None values
        update_data = {k: v for k, v in request.dict().items() if v is not None}
        
        if not update_data:
            raise HTTPException(status_code=400, detail="No valid parameters provided")
        
        success = config_manager.update_detection_thresholds(**update_data)
        
        if success:
            return JSONResponse(content={
                "status": "success",
                "message": "Detection thresholds updated successfully",
                "updated_parameters": update_data,
                "timestamp": datetime.now().isoformat()
            })
        else:
            raise HTTPException(status_code=500, detail="Failed to update detection thresholds")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating detection thresholds: {e}")
        raise HTTPException(status_code=500, detail="Failed to update detection thresholds")


@router.get("/alerts")
async def get_alert_configuration():
    """
    Get current alert configuration.
    
    Returns alert settings including email, webhook, and syslog configuration.
    Sensitive information like passwords are masked.
    """
    try:
        alert_config = config_manager.get_alert_configuration()
        
        # Mask sensitive information
        response_data = {
            "severity_levels": alert_config.severity_levels,
            "enable_email": alert_config.enable_email,
            "enable_syslog": alert_config.enable_syslog,
            "enable_webhook": alert_config.enable_webhook,
            "critical_only": alert_config.critical_only,
            "dedup_window_minutes": alert_config.dedup_window_minutes,
            "max_alerts_per_hour": alert_config.max_alerts_per_hour,
            "alert_retention_days": alert_config.alert_retention_days,
            "smtp_server": alert_config.smtp_server,
            "smtp_port": alert_config.smtp_port,
            "smtp_username": alert_config.smtp_username,
            "smtp_password": "***" if alert_config.smtp_password else "",
            "smtp_use_tls": alert_config.smtp_use_tls,
            "alert_emails": alert_config.alert_emails,
            "webhook_url": alert_config.webhook_url,
            "webhook_timeout": alert_config.webhook_timeout,
            "syslog_server": alert_config.syslog_server,
            "syslog_port": alert_config.syslog_port,
            "syslog_facility": alert_config.syslog_facility
        }
        
        return JSONResponse(content={
            "status": "success",
            "data": response_data,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting alert configuration: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve alert configuration")


@router.put("/alerts")
async def update_alert_configuration(request: AlertConfigurationRequest):
    """
    Update alert configuration.
    
    Updates one or more alert configuration parameters. Only provided
    parameters will be updated, others remain unchanged.
    """
    try:
        # Convert request to dictionary, excluding None values
        update_data = {k: v for k, v in request.dict().items() if v is not None}
        
        if not update_data:
            raise HTTPException(status_code=400, detail="No valid parameters provided")
        
        success = config_manager.update_alert_configuration(**update_data)
        
        if success:
            return JSONResponse(content={
                "status": "success",
                "message": "Alert configuration updated successfully",
                "updated_parameters": list(update_data.keys()),
                "timestamp": datetime.now().isoformat()
            })
        else:
            raise HTTPException(status_code=500, detail="Failed to update alert configuration")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating alert configuration: {e}")
        raise HTTPException(status_code=500, detail="Failed to update alert configuration")


@router.get("/interface")
async def get_interface_configuration():
    """
    Get current interface configuration.
    
    Returns network interface settings including capture interface,
    packet filters, and IP/port exclusions.
    """
    try:
        interface_config = config_manager.get_interface_configuration()
        
        response_data = {
            "capture_interface": interface_config.capture_interface,
            "packet_buffer_size": interface_config.packet_buffer_size,
            "capture_timeout": interface_config.capture_timeout,
            "promiscuous_mode": interface_config.promiscuous_mode,
            "packet_filters": interface_config.packet_filters,
            "excluded_ips": interface_config.excluded_ips,
            "included_ips": interface_config.included_ips,
            "excluded_ports": interface_config.excluded_ports,
            "included_ports": interface_config.included_ports,
            "max_packet_size": interface_config.max_packet_size
        }
        
        return JSONResponse(content={
            "status": "success",
            "data": response_data,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting interface configuration: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve interface configuration")


@router.put("/interface")
async def update_interface_configuration(request: InterfaceConfigurationRequest):
    """
    Update interface configuration.
    
    Updates one or more interface configuration parameters. Only provided
    parameters will be updated, others remain unchanged.
    """
    try:
        # Convert request to dictionary, excluding None values
        update_data = {k: v for k, v in request.dict().items() if v is not None}
        
        if not update_data:
            raise HTTPException(status_code=400, detail="No valid parameters provided")
        
        success = config_manager.update_interface_configuration(**update_data)
        
        if success:
            return JSONResponse(content={
                "status": "success",
                "message": "Interface configuration updated successfully",
                "updated_parameters": list(update_data.keys()),
                "timestamp": datetime.now().isoformat()
            })
        else:
            raise HTTPException(status_code=500, detail="Failed to update interface configuration")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating interface configuration: {e}")
        raise HTTPException(status_code=500, detail="Failed to update interface configuration")


@router.get("/rules")
async def get_custom_rules(
    enabled_only: bool = Query(False, description="Return only enabled rules")
):
    """
    Get custom threat detection rules.
    
    Returns list of custom rules with optional filtering for enabled rules only.
    """
    try:
        rules = config_manager.get_custom_rules(enabled_only=enabled_only)
        
        # Convert rules to dictionaries
        rules_data = []
        for rule in rules:
            rules_data.append({
                "name": rule.name,
                "description": rule.description,
                "pattern": rule.pattern,
                "pattern_type": rule.pattern_type,
                "severity": rule.severity,
                "enabled": rule.enabled,
                "protocol": rule.protocol,
                "ports": rule.ports,
                "created_date": rule.created_date,
                "last_modified": rule.last_modified
            })
        
        return JSONResponse(content={
            "status": "success",
            "data": {
                "rules": rules_data,
                "total_count": len(rules_data),
                "enabled_only": enabled_only
            },
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting custom rules: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve custom rules")


@router.post("/rules")
async def add_custom_rule(request: CustomRuleRequest):
    """
    Add a new custom threat detection rule.
    
    Creates a new custom rule with the provided parameters. Rule names must be unique.
    """
    try:
        # Create CustomRule object
        rule = CustomRule(
            name=request.name,
            description=request.description,
            pattern=request.pattern,
            pattern_type=request.pattern_type,
            severity=request.severity,
            enabled=request.enabled,
            protocol=request.protocol,
            ports=request.ports
        )
        
        success = config_manager.add_custom_rule(rule)
        
        if success:
            return JSONResponse(content={
                "status": "success",
                "message": f"Custom rule '{request.name}' added successfully",
                "rule_name": request.name,
                "timestamp": datetime.now().isoformat()
            }, status_code=201)
        else:
            raise HTTPException(status_code=400, detail="Failed to add custom rule")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding custom rule: {e}")
        raise HTTPException(status_code=500, detail="Failed to add custom rule")


@router.put("/rules/{rule_name}")
async def update_custom_rule(rule_name: str, request: CustomRuleUpdateRequest):
    """
    Update an existing custom threat detection rule.
    
    Updates the specified rule with provided parameters. Only provided
    parameters will be updated, others remain unchanged.
    """
    try:
        # Convert request to dictionary, excluding None values
        update_data = {k: v for k, v in request.dict().items() if v is not None}
        
        if not update_data:
            raise HTTPException(status_code=400, detail="No valid parameters provided")
        
        success = config_manager.update_custom_rule(rule_name, **update_data)
        
        if success:
            return JSONResponse(content={
                "status": "success",
                "message": f"Custom rule '{rule_name}' updated successfully",
                "rule_name": rule_name,
                "updated_parameters": list(update_data.keys()),
                "timestamp": datetime.now().isoformat()
            })
        else:
            raise HTTPException(status_code=404, detail=f"Rule '{rule_name}' not found")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating custom rule: {e}")
        raise HTTPException(status_code=500, detail="Failed to update custom rule")


@router.delete("/rules/{rule_name}")
async def remove_custom_rule(rule_name: str):
    """
    Remove a custom threat detection rule.
    
    Permanently removes the specified custom rule from the configuration.
    """
    try:
        success = config_manager.remove_custom_rule(rule_name)
        
        if success:
            return JSONResponse(content={
                "status": "success",
                "message": f"Custom rule '{rule_name}' removed successfully",
                "rule_name": rule_name,
                "timestamp": datetime.now().isoformat()
            })
        else:
            raise HTTPException(status_code=404, detail=f"Rule '{rule_name}' not found")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing custom rule: {e}")
        raise HTTPException(status_code=500, detail="Failed to remove custom rule")


@router.post("/export")
async def export_configuration(request: ConfigurationExportRequest):
    """
    Export current configuration.
    
    Returns the current configuration in the specified format (JSON or YAML).
    Optionally includes or excludes sensitive information.
    """
    try:
        # Get current configuration
        config_data = config_manager._config_to_dict(config_manager.config)
        
        # Remove sensitive information if requested
        if not request.include_sensitive:
            if "alerts" in config_data:
                if "smtp_password" in config_data["alerts"]:
                    config_data["alerts"]["smtp_password"] = ""
        
        return JSONResponse(content={
            "status": "success",
            "data": {
                "configuration": config_data,
                "format": request.format,
                "include_sensitive": request.include_sensitive,
                "exported_at": datetime.now().isoformat()
            },
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error exporting configuration: {e}")
        raise HTTPException(status_code=500, detail="Failed to export configuration")


@router.post("/import")
async def import_configuration(request: ConfigurationImportRequest):
    """
    Import configuration from provided data.
    
    Imports configuration from the provided data. Can either replace current
    configuration or merge with existing settings.
    """
    try:
        if request.merge_with_existing:
            # TODO: Implement configuration merging logic
            raise HTTPException(status_code=501, detail="Configuration merging not yet implemented")
        
        # Convert dictionary to configuration object
        imported_config = config_manager._dict_to_config(request.config_data)
        
        # Backup current configuration
        backup_config = config_manager.config
        config_manager.config = imported_config
        
        # Validate imported configuration
        if config_manager._validate_configuration():
            # Save imported configuration
            if config_manager.save_configuration():
                return JSONResponse(content={
                    "status": "success",
                    "message": "Configuration imported successfully",
                    "merge_with_existing": request.merge_with_existing,
                    "timestamp": datetime.now().isoformat()
                })
            else:
                # Restore backup on save failure
                config_manager.config = backup_config
                raise HTTPException(status_code=500, detail="Failed to save imported configuration")
        else:
            # Restore backup on validation failure
            config_manager.config = backup_config
            raise HTTPException(status_code=400, detail="Imported configuration failed validation")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error importing configuration: {e}")
        raise HTTPException(status_code=500, detail="Failed to import configuration")


@router.post("/reset")
async def reset_configuration():
    """
    Reset configuration to default values.
    
    Resets all configuration settings to their default values.
    This action cannot be undone.
    """
    try:
        # Create backup of current configuration
        backup_path = f"config/backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        if config_manager.export_configuration(backup_path, "json"):
            logger.info(f"Configuration backup created: {backup_path}")
        
        # Reset to default configuration
        config_manager.config = config_manager._dict_to_config({})
        
        # Save default configuration
        if config_manager.save_configuration():
            return JSONResponse(content={
                "status": "success",
                "message": "Configuration reset to defaults successfully",
                "backup_created": backup_path,
                "timestamp": datetime.now().isoformat()
            })
        else:
            raise HTTPException(status_code=500, detail="Failed to save default configuration")
            
    except Exception as e:
        logger.error(f"Error resetting configuration: {e}")
        raise HTTPException(status_code=500, detail="Failed to reset configuration")


@router.get("/validate")
async def validate_configuration():
    """
    Validate current configuration.
    
    Checks the current configuration for validity and returns any issues found.
    """
    try:
        is_valid = config_manager._validate_configuration()
        
        return JSONResponse(content={
            "status": "success",
            "data": {
                "is_valid": is_valid,
                "validation_timestamp": datetime.now().isoformat()
            },
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error validating configuration: {e}")
        raise HTTPException(status_code=500, detail="Failed to validate configuration")


# Include router in main application
def get_config_router():
    """Get the configuration API router"""
    return router