#!/usr/bin/env python3
"""
Cleanup script to remove mock/test data from SpyNet database
"""
import sys
from pathlib import Path

# Add backend directory to path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

from models import db_manager
from sqlalchemy import text

def cleanup_mock_data():
    """Remove all mock/test data from the database"""
    print("SpyNet Mock Data Cleanup")
    print("=" * 30)
    
    db = db_manager.get_session()
    try:
        # Remove mock alerts
        print("1. Removing mock alerts...")
        result = db.execute(text("""
            DELETE FROM alerts 
            WHERE description LIKE '%Mock%' 
               OR description LIKE '%mock%' 
               OR description LIKE '%test%' 
               OR description LIKE '%development%'
               OR description LIKE '%Test%'
               OR description LIKE '%demo%'
               OR description LIKE '%Demo%'
        """))
        alerts_removed = result.rowcount
        print(f"   ✅ Removed {alerts_removed} mock alerts")
        
        # Remove mock packets (if any)
        print("2. Removing mock packets...")
        result = db.execute(text("""
            DELETE FROM packets 
            WHERE src_ip LIKE '192.168.%' 
               OR src_ip LIKE '10.0.%'
               OR dst_ip LIKE '192.168.%' 
               OR dst_ip LIKE '10.0.%'
        """))
        packets_removed = result.rowcount
        print(f"   ✅ Removed {packets_removed} mock packets")
        
        # Remove mock connections
        print("3. Removing mock connections...")
        result = db.execute(text("""
            DELETE FROM connections 
            WHERE src_ip LIKE '192.168.%' 
               OR src_ip LIKE '10.0.%'
               OR dst_ip LIKE '192.168.%' 
               OR dst_ip LIKE '10.0.%'
        """))
        connections_removed = result.rowcount
        print(f"   ✅ Removed {connections_removed} mock connections")
        
        # Commit all changes
        db.commit()
        
        print("\n" + "=" * 30)
        print("🎉 Mock data cleanup completed!")
        print(f"Summary:")
        print(f"  - Alerts removed: {alerts_removed}")
        print(f"  - Packets removed: {packets_removed}")
        print(f"  - Connections removed: {connections_removed}")
        print("\nYour SpyNet system now contains only real data.")
        
    except Exception as e:
        db.rollback()
        print(f"❌ Error during cleanup: {e}")
        return False
    finally:
        db.close()
    
    return True

def verify_cleanup():
    """Verify that mock data has been removed"""
    print("\nVerifying cleanup...")
    
    db = db_manager.get_session()
    try:
        # Check remaining alerts
        result = db.execute(text("SELECT COUNT(*) FROM alerts"))
        alert_count = result.scalar()
        
        # Check remaining packets
        result = db.execute(text("SELECT COUNT(*) FROM packets"))
        packet_count = result.scalar()
        
        # Check remaining connections
        result = db.execute(text("SELECT COUNT(*) FROM connections"))
        connection_count = result.scalar()
        
        print(f"Current database contents:")
        print(f"  - Alerts: {alert_count}")
        print(f"  - Packets: {packet_count}")
        print(f"  - Connections: {connection_count}")
        
        if alert_count == 0 and packet_count == 0 and connection_count == 0:
            print("✅ Database is clean - ready for real network monitoring!")
        else:
            print("ℹ️  Database contains some data - verify it's legitimate traffic")
            
    except Exception as e:
        print(f"Error verifying cleanup: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    if cleanup_mock_data():
        verify_cleanup()