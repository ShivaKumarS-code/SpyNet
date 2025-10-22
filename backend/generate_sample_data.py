#!/usr/bin/env python3
"""
Generate sample network data for SpyNet testing
This creates realistic network traffic data for demonstration purposes
"""
import sys
import random
from datetime import datetime, timedelta
from pathlib import Path

# Add backend directory to path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

from models import db_manager
from database import db_ops

def generate_sample_packets(count=100):
    """Generate sample packet data"""
    print(f"Generating {count} sample packets...")
    
    # Common protocols and ports
    protocols = ['TCP', 'UDP', 'ICMP']
    common_ports = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995]
    
    # Realistic IP ranges (using public IP ranges for demo)
    external_ips = [
        '8.8.8.8', '1.1.1.1', '208.67.222.222', '9.9.9.9',
        '74.125.224.72', '151.101.193.140', '104.16.132.229'
    ]
    
    internal_ips = [f'192.168.1.{i}' for i in range(1, 50)]
    
    packets_created = 0
    
    for i in range(count):
        # Create realistic packet data
        protocol = random.choice(protocols)
        
        # Mix of internal to external and external to internal traffic
        if random.choice([True, False]):
            src_ip = random.choice(internal_ips)
            dst_ip = random.choice(external_ips)
        else:
            src_ip = random.choice(external_ips)
            dst_ip = random.choice(internal_ips)
        
        # Realistic packet sizes
        if protocol == 'TCP':
            size = random.randint(64, 1500)
            src_port = random.randint(1024, 65535)
            dst_port = random.choice(common_ports)
            tcp_flags = random.choice(['SYN', 'ACK', 'SYN,ACK', 'FIN', 'RST'])
        elif protocol == 'UDP':
            size = random.randint(64, 1024)
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([53, 123, 161, 514])
            tcp_flags = None
        else:  # ICMP
            size = random.randint(64, 128)
            src_port = None
            dst_port = None
            tcp_flags = None
        
        # Timestamp within last hour
        timestamp = datetime.now() - timedelta(minutes=random.randint(0, 60))
        
        packet_data = {
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'size': size,
            'tcp_flags': tcp_flags,
            'payload_size': random.randint(0, size - 64)
        }
        
        try:
            db_ops.store_packet(packet_data)
            packets_created += 1
        except Exception as e:
            print(f"Error creating packet {i}: {e}")
    
    print(f"✅ Created {packets_created} sample packets")
    return packets_created

def generate_sample_alerts(count=20):
    """Generate sample security alerts"""
    print(f"Generating {count} sample alerts...")
    
    alert_types = ['port_scan', 'ddos_attempt', 'suspicious_payload', 'anomaly_detected', 'brute_force']
    severities = ['Low', 'Medium', 'High', 'Critical']
    source_ips = ['203.0.113.10', '198.51.100.25', '192.0.2.100', '203.0.113.50']
    
    alerts_created = 0
    
    for i in range(count):
        alert_type = random.choice(alert_types)
        severity = random.choice(severities)
        source_ip = random.choice(source_ips)
        
        # Create realistic descriptions
        descriptions = {
            'port_scan': f'Port scan detected from {source_ip} - {random.randint(10, 100)} ports scanned',
            'ddos_attempt': f'Potential DDoS attack from {source_ip} - {random.randint(100, 1000)} requests/sec',
            'suspicious_payload': f'Suspicious payload detected in traffic from {source_ip}',
            'anomaly_detected': f'Network anomaly detected involving {source_ip}',
            'brute_force': f'Brute force login attempt detected from {source_ip}'
        }
        
        # Timestamp within last 2 hours
        timestamp = datetime.now() - timedelta(minutes=random.randint(0, 120))
        
        alert_data = {
            'timestamp': timestamp,
            'alert_type': alert_type,
            'severity': severity,
            'source_ip': source_ip,
            'destination_ip': f'192.168.1.{random.randint(1, 50)}',
            'description': descriptions[alert_type],
            'details': {
                'confidence': round(random.uniform(0.7, 0.99), 2),
                'rule_id': f'R{random.randint(1000, 9999)}',
                'protocol': random.choice(['TCP', 'UDP', 'ICMP'])
            }
        }
        
        try:
            db_ops.create_alert(alert_data)
            alerts_created += 1
        except Exception as e:
            print(f"Error creating alert {i}: {e}")
    
    print(f"✅ Created {alerts_created} sample alerts")
    return alerts_created

def generate_sample_connections(count=50):
    """Generate sample connection data"""
    print(f"Generating {count} sample connections...")
    
    external_ips = ['8.8.8.8', '1.1.1.1', '74.125.224.72', '151.101.193.140']
    internal_ips = [f'192.168.1.{i}' for i in range(1, 30)]
    
    connections_created = 0
    
    for i in range(count):
        src_ip = random.choice(internal_ips)
        dst_ip = random.choice(external_ips)
        
        # Connection started within last 3 hours
        first_seen = datetime.now() - timedelta(minutes=random.randint(0, 180))
        duration = random.randint(1, 3600)  # 1 second to 1 hour
        last_seen = first_seen + timedelta(seconds=duration)
        
        connection_data = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 22, 21, 25]),
            'protocol': 'TCP',
            'bytes_sent': random.randint(1024, 1048576),  # 1KB to 1MB
            'bytes_received': random.randint(512, 524288),  # 512B to 512KB
            'tcp_flags': 'SYN,ACK,FIN'
        }
        
        try:
            db_ops.update_connection(connection_data)
            connections_created += 1
        except Exception as e:
            print(f"Error creating connection {i}: {e}")
    
    print(f"✅ Created {connections_created} sample connections")
    return connections_created

def main():
    """Generate all sample data"""
    print("SpyNet Sample Data Generator")
    print("=" * 40)
    print("This will create realistic network traffic data for demonstration.")
    print()
    
    try:
        # Generate sample data
        packets = generate_sample_packets(150)
        alerts = generate_sample_alerts(25)
        connections = generate_sample_connections(75)
        
        print("\n" + "=" * 40)
        print("🎉 Sample data generation completed!")
        print(f"Summary:")
        print(f"  - Packets: {packets}")
        print(f"  - Alerts: {alerts}")
        print(f"  - Connections: {connections}")
        print()
        print("Your SpyNet dashboard should now show realistic network data.")
        print("Refresh your browser to see the updated information.")
        
    except Exception as e:
        print(f"❌ Error generating sample data: {e}")
        return False
    
    return True

if __name__ == "__main__":
    main()