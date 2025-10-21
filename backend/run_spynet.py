#!/usr/bin/env python3
"""
SpyNet Integrated System Runner

This script provides a unified way to run the complete SpyNet system including
the core packet analysis engine and the FastAPI web interface.
"""

import asyncio
import logging
import signal
import sys
import threading
import time
from pathlib import Path
import argparse
import uvicorn

from spynet_app import SpyNetApp
from config import settings


class SpyNetRunner:
    """
    Unified runner for the complete SpyNet system.
    
    Manages both the core packet analysis system and the web API interface
    with proper coordination and shutdown procedures.
    """
    
    def __init__(self, config_override=None):
        """Initialize the SpyNet runner"""
        self.config = config_override or {}
        self.spynet_app = None
        self.api_server = None
        self.running = False
        
        # Setup logging
        self.logger = self._setup_logging()
        
        # Setup signal handlers
        self._setup_signal_handlers()
    
    def _setup_logging(self):
        """Setup logging for the runner"""
        logging.basicConfig(
            level=getattr(logging, self.config.get("log_level", settings.log_level).upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler("logs/spynet_runner.log"),
                logging.StreamHandler(sys.stdout)
            ]
        )
        return logging.getLogger("spynet.runner")
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        try:
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        except Exception as e:
            self.logger.warning(f"Could not setup signal handlers: {e}")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        self.stop()
    
    def start(self):
        """Start the complete SpyNet system"""
        try:
            self.logger.info("Starting SpyNet Integrated System...")
            self.running = True
            
            # Create logs directory
            Path("logs").mkdir(exist_ok=True)
            
            # Initialize SpyNet core application
            self.logger.info("Initializing SpyNet core system...")
            self.spynet_app = SpyNetApp(config_override=self.config)
            
            # Start SpyNet core in a separate thread
            def start_core():
                if not self.spynet_app.start():
                    self.logger.error("Failed to start SpyNet core system")
                    self.running = False
            
            core_thread = threading.Thread(target=start_core, daemon=True)
            core_thread.start()
            
            # Give core system time to initialize
            time.sleep(2)
            
            if not self.running:
                self.logger.error("SpyNet core system failed to start")
                return False
            
            # Start FastAPI server
            self.logger.info("Starting SpyNet API server...")
            api_host = self.config.get("api_host", settings.api_host)
            api_port = self.config.get("api_port", settings.api_port)
            debug_mode = self.config.get("debug", settings.debug)
            
            # Run API server in the main thread
            uvicorn.run(
                "main:app",
                host=api_host,
                port=api_port,
                reload=debug_mode,
                log_level=self.config.get("log_level", settings.log_level).lower(),
                access_log=True
            )
            
            return True
            
        except KeyboardInterrupt:
            self.logger.info("Shutdown requested by user")
            self.stop()
            return True
        except Exception as e:
            self.logger.error(f"Error starting SpyNet system: {e}")
            self.stop()
            return False
    
    def stop(self):
        """Stop the complete SpyNet system"""
        try:
            if not self.running:
                return
            
            self.logger.info("Stopping SpyNet Integrated System...")
            self.running = False
            
            # Stop SpyNet core system
            if self.spynet_app:
                self.spynet_app.stop()
                self.logger.info("SpyNet core system stopped")
            
            self.logger.info("SpyNet Integrated System stopped successfully")
            
        except Exception as e:
            self.logger.error(f"Error stopping SpyNet system: {e}")


def create_cli_parser():
    """Create command-line interface parser"""
    parser = argparse.ArgumentParser(
        description="SpyNet Integrated Network Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_spynet.py                         # Start with default settings
  python run_spynet.py -i eth1 --port 8080     # Custom interface and API port
  python run_spynet.py --no-email --debug      # Disable email, enable debug mode
        """
    )
    
    # Network configuration
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to monitor (default: auto-detect)"
    )
    
    # API configuration
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="API server host (default: 0.0.0.0)"
    )
    
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="API server port (default: 8000)"
    )
    
    # Detection thresholds
    parser.add_argument(
        "--port-scan-threshold",
        type=int,
        help="Port scan detection threshold (default: 10)"
    )
    
    parser.add_argument(
        "--ddos-threshold",
        type=int,
        help="DDoS detection threshold (default: 100)"
    )
    
    parser.add_argument(
        "--anomaly-contamination",
        type=float,
        help="Anomaly detection contamination rate (default: 0.1)"
    )
    
    # Email configuration
    parser.add_argument(
        "--no-email",
        action="store_true",
        help="Disable email notifications"
    )
    
    parser.add_argument(
        "--smtp-server",
        help="SMTP server for email notifications"
    )
    
    parser.add_argument(
        "--smtp-username",
        help="SMTP username for email notifications"
    )
    
    parser.add_argument(
        "--smtp-password",
        help="SMTP password for email notifications"
    )
    
    parser.add_argument(
        "--alert-emails",
        nargs="+",
        help="Email addresses for alert notifications"
    )
    
    # System configuration
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode"
    )
    
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)"
    )
    
    parser.add_argument(
        "--buffer-size",
        type=int,
        help="Packet buffer size (default: 1000)"
    )
    
    return parser


def main():
    """Main entry point"""
    parser = create_cli_parser()
    args = parser.parse_args()
    
    # Build configuration from command line arguments
    config = {}
    
    # Network configuration
    if args.interface:
        config["capture_interface"] = args.interface
    
    # API configuration
    config["api_host"] = args.host
    config["api_port"] = args.port
    config["debug"] = args.debug
    
    # Detection thresholds
    if args.port_scan_threshold:
        config["port_scan_threshold"] = args.port_scan_threshold
    
    if args.ddos_threshold:
        config["ddos_threshold"] = args.ddos_threshold
    
    if args.anomaly_contamination:
        config["anomaly_contamination"] = args.anomaly_contamination
    
    # Email configuration
    if args.no_email:
        config["enable_email"] = False
    
    if args.smtp_server:
        config["smtp_server"] = args.smtp_server
    
    if args.smtp_username:
        config["smtp_username"] = args.smtp_username
    
    if args.smtp_password:
        config["smtp_password"] = args.smtp_password
    
    if args.alert_emails:
        config["alert_emails"] = args.alert_emails
    
    # System configuration
    if args.log_level:
        config["log_level"] = args.log_level
    
    if args.buffer_size:
        config["packet_buffer_size"] = args.buffer_size
    
    # Create and start the integrated system
    runner = SpyNetRunner(config_override=config)
    
    try:
        success = runner.start()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
        runner.stop()
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()