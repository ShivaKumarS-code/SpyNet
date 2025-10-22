#!/usr/bin/env python3
"""
SpyNet Reporting CLI Tool
Command-line interface for generating reports and performing forensic analysis
"""
import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any

from reporting import report_generator
from models import create_tables


def setup_argparser():
    """Setup command line argument parser"""
    parser = argparse.ArgumentParser(
        description="SpyNet Reporting and Forensics CLI Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate security summary for last 24 hours
  python report_cli.py security-summary --hours 24 --format json

  # Perform forensic search for specific IP
  python report_cli.py forensic-search --src-ip 192.168.1.100 --format csv

  # Generate trend analysis for last week
  python report_cli.py trend-analysis --days 7 --granularity hour

  # Export compliance report
  python report_cli.py compliance --type security_audit --days 30
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Security Summary command
    summary_parser = subparsers.add_parser('security-summary', help='Generate security summary report')
    summary_parser.add_argument('--hours', type=int, default=24, help='Hours of data to analyze (default: 24)')
    summary_parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Output format')
    summary_parser.add_argument('--output', type=str, help='Output file path')
    
    # Forensic Search command
    search_parser = subparsers.add_parser('forensic-search', help='Perform forensic search')
    search_parser.add_argument('--src-ip', type=str, help='Source IP address')
    search_parser.add_argument('--dst-ip', type=str, help='Destination IP address')
    search_parser.add_argument('--protocol', type=str, help='Protocol (TCP, UDP, ICMP)')
    search_parser.add_argument('--src-port', type=int, help='Source port')
    search_parser.add_argument('--dst-port', type=int, help='Destination port')
    search_parser.add_argument('--start-time', type=str, help='Start time (YYYY-MM-DD HH:MM:SS)')
    search_parser.add_argument('--end-time', type=str, help='End time (YYYY-MM-DD HH:MM:SS)')
    search_parser.add_argument('--alert-type', type=str, help='Alert type filter')
    search_parser.add_argument('--severity', type=str, help='Alert severity filter')
    search_parser.add_argument('--limit', type=int, default=1000, help='Maximum results (default: 1000)')
    search_parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Output format')
    search_parser.add_argument('--output', type=str, help='Output file path')
    
    # Trend Analysis command
    trend_parser = subparsers.add_parser('trend-analysis', help='Generate trend analysis')
    trend_parser.add_argument('--days', type=int, default=7, help='Days of data to analyze (default: 7)')
    trend_parser.add_argument('--granularity', choices=['hour', 'day'], default='hour', help='Time granularity')
    trend_parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Output format')
    trend_parser.add_argument('--output', type=str, help='Output file path')
    
    # Compliance Report command
    compliance_parser = subparsers.add_parser('compliance', help='Generate compliance report')
    compliance_parser.add_argument('--type', choices=['security_audit', 'incident_summary', 'network_activity'], 
                                  required=True, help='Report type')
    compliance_parser.add_argument('--days', type=int, default=30, help='Days of data to analyze (default: 30)')
    compliance_parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Output format')
    compliance_parser.add_argument('--output', type=str, help='Output file path')
    
    # Packet Search command
    packet_parser = subparsers.add_parser('packet-search', help='Search packets with detailed filtering')
    packet_parser.add_argument('--src-ip', type=str, help='Source IP address')
    packet_parser.add_argument('--dst-ip', type=str, help='Destination IP address')
    packet_parser.add_argument('--protocol', type=str, help='Protocol (TCP, UDP, ICMP)')
    packet_parser.add_argument('--src-port', type=int, help='Source port')
    packet_parser.add_argument('--dst-port', type=int, help='Destination port')
    packet_parser.add_argument('--start-time', type=str, help='Start time (YYYY-MM-DD HH:MM:SS)')
    packet_parser.add_argument('--end-time', type=str, help='End time (YYYY-MM-DD HH:MM:SS)')
    packet_parser.add_argument('--min-size', type=int, help='Minimum packet size')
    packet_parser.add_argument('--max-size', type=int, help='Maximum packet size')
    packet_parser.add_argument('--limit', type=int, default=1000, help='Maximum results (default: 1000)')
    packet_parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Output format')
    packet_parser.add_argument('--output', type=str, help='Output file path')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export existing data')
    export_parser.add_argument('--data-type', choices=['packets', 'alerts', 'connections'], 
                              required=True, help='Data type to export')
    export_parser.add_argument('--hours', type=int, default=24, help='Hours of data to export (default: 24)')
    export_parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Output format')
    export_parser.add_argument('--output', type=str, help='Output file path')
    
    return parser


def parse_datetime(date_str: str) -> datetime:
    """Parse datetime string in various formats"""
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ"
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    
    raise ValueError(f"Unable to parse datetime: {date_str}")


def generate_security_summary(args):
    """Generate security summary report"""
    print(f"Generating security summary for last {args.hours} hours...")
    
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=args.hours)
    
    try:
        summary = report_generator.generate_security_summary(start_time, end_time)
        
        # Export the data
        filename = args.output or f"security_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        filepath = report_generator.export_data(summary, args.format, filename)
        
        print(f"Security summary generated successfully!")
        print(f"File saved: {filepath}")
        print(f"Total packets analyzed: {summary.total_packets}")
        print(f"Risk score: {summary.risk_score}")
        
    except Exception as e:
        print(f"Error generating security summary: {e}")
        sys.exit(1)


def perform_forensic_search(args):
    """Perform forensic search"""
    print("Performing forensic search...")
    
    # Build search criteria
    criteria = {}
    if args.src_ip:
        criteria["src_ip"] = args.src_ip
    if args.dst_ip:
        criteria["dst_ip"] = args.dst_ip
    if args.protocol:
        criteria["protocol"] = args.protocol.upper()
    if args.src_port:
        criteria["src_port"] = args.src_port
    if args.dst_port:
        criteria["dst_port"] = args.dst_port
    if args.alert_type:
        criteria["alert_type"] = args.alert_type
    if args.severity:
        criteria["severity"] = args.severity
    
    # Parse time parameters
    if args.start_time:
        criteria["start_time"] = parse_datetime(args.start_time)
    if args.end_time:
        criteria["end_time"] = parse_datetime(args.end_time)
    
    try:
        results = report_generator.forensic_search(criteria, args.limit)
        
        # Export the data
        filename = args.output or f"forensic_search_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        filepath = report_generator.export_data(results, args.format, filename)
        
        print(f"Forensic search completed successfully!")
        print(f"File saved: {filepath}")
        print(f"Total matches found: {results.total_matches}")
        print(f"Packets: {len(results.packets)}")
        print(f"Connections: {len(results.connections)}")
        print(f"Alerts: {len(results.alerts)}")
        print(f"Execution time: {results.execution_time:.2f} seconds")
        
    except Exception as e:
        print(f"Error performing forensic search: {e}")
        sys.exit(1)


def generate_trend_analysis(args):
    """Generate trend analysis"""
    print(f"Generating trend analysis for {args.days} days with {args.granularity} granularity...")
    
    try:
        trends = report_generator.generate_trend_analysis(args.days, args.granularity)
        
        # Export the data
        filename = args.output or f"trend_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        filepath = report_generator.export_data(trends, args.format, filename)
        
        print(f"Trend analysis generated successfully!")
        print(f"File saved: {filepath}")
        print(f"Analysis period: {args.days} days")
        print(f"Granularity: {args.granularity}")
        
    except Exception as e:
        print(f"Error generating trend analysis: {e}")
        sys.exit(1)


def generate_compliance_report(args):
    """Generate compliance report"""
    print(f"Generating {args.type} compliance report for {args.days} days...")
    
    try:
        report = report_generator.generate_compliance_report(args.type, args.days)
        
        # Export the data
        filename = args.output or f"{args.type}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        filepath = report_generator.export_data(report, args.format, filename)
        
        print(f"Compliance report generated successfully!")
        print(f"File saved: {filepath}")
        print(f"Report type: {args.type}")
        print(f"Analysis period: {args.days} days")
        
    except Exception as e:
        print(f"Error generating compliance report: {e}")
        sys.exit(1)


def search_packets(args):
    """Search packets with detailed filtering"""
    print("Searching packets...")
    
    # Build search criteria
    criteria = {}
    if args.src_ip:
        criteria["src_ip"] = args.src_ip
    if args.dst_ip:
        criteria["dst_ip"] = args.dst_ip
    if args.protocol:
        criteria["protocol"] = args.protocol.upper()
    if args.src_port:
        criteria["src_port"] = args.src_port
    if args.dst_port:
        criteria["dst_port"] = args.dst_port
    if args.min_size:
        criteria["min_size"] = args.min_size
    if args.max_size:
        criteria["max_size"] = args.max_size
    
    # Parse time parameters
    if args.start_time:
        criteria["start_time"] = parse_datetime(args.start_time)
    if args.end_time:
        criteria["end_time"] = parse_datetime(args.end_time)
    
    try:
        # Use the reporting module's packet search
        from models import db_manager
        db = db_manager.get_session()
        try:
            packets = report_generator._search_packets(db, criteria, args.limit)
            
            # Export the data
            filename = args.output or f"packet_search_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            filepath = report_generator.export_data(packets, args.format, filename)
            
            print(f"Packet search completed successfully!")
            print(f"File saved: {filepath}")
            print(f"Packets found: {len(packets)}")
            
        finally:
            db.close()
        
    except Exception as e:
        print(f"Error searching packets: {e}")
        sys.exit(1)


def export_data(args):
    """Export existing data"""
    print(f"Exporting {args.data_type} data for last {args.hours} hours...")
    
    try:
        from models import db_manager
        from database import db_ops
        
        if args.data_type == "packets":
            data = db_ops.get_recent_packets(limit=10000, hours=args.hours)
            export_data = [
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
                for p in data
            ]
            
        elif args.data_type == "alerts":
            data = db_ops.get_recent_alerts(limit=10000)
            export_data = [
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
                for a in data
            ]
            
        elif args.data_type == "connections":
            data = db_ops.get_active_connections(limit=10000)
            export_data = [
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
                for c in data
            ]
        
        # Export the data
        filename = args.output or f"{args.data_type}_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        filepath = report_generator.export_data(export_data, args.format, filename)
        
        print(f"Data export completed successfully!")
        print(f"File saved: {filepath}")
        print(f"Records exported: {len(export_data)}")
        
    except Exception as e:
        print(f"Error exporting data: {e}")
        sys.exit(1)


def main():
    """Main CLI entry point"""
    parser = setup_argparser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Ensure database tables exist
    try:
        create_tables()
    except Exception as e:
        print(f"Warning: Could not verify database tables: {e}")
    
    # Execute the requested command
    try:
        if args.command == 'security-summary':
            generate_security_summary(args)
        elif args.command == 'forensic-search':
            perform_forensic_search(args)
        elif args.command == 'trend-analysis':
            generate_trend_analysis(args)
        elif args.command == 'compliance':
            generate_compliance_report(args)
        elif args.command == 'packet-search':
            search_packets(args)
        elif args.command == 'export':
            export_data(args)
        else:
            print(f"Unknown command: {args.command}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()