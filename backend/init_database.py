#!/usr/bin/env python3
"""
Database initialization script for SpyNet
"""
import sys
import os
from pathlib import Path

# Add the backend directory to Python path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

from models import create_tables, init_default_config, db_manager
from migrations import run_migrations, get_migration_status
from config import settings


def main():
    """Initialize the SpyNet database"""
    print("SpyNet Database Initialization")
    print("=" * 40)
    
    try:
        # Check database connection
        print("1. Testing database connection...")
        db = db_manager.get_session()
        db.execute("SELECT 1")
        db.close()
        print("   ✅ Database connection successful")
        
        # Run migrations
        print("\n2. Running database migrations...")
        run_migrations()
        print("   ✅ Migrations completed")
        
        # Show migration status
        print("\n3. Migration status:")
        for status in get_migration_status():
            status_icon = "✅" if status['status'] == 'SUCCESS' else "⏳" if status['status'] == 'PENDING' else "❌"
            print(f"   {status_icon} {status['version']}: {status['status']}")
        
        # Create tables (if not already created by migrations)
        print("\n4. Ensuring all tables exist...")
        create_tables()
        print("   ✅ Tables verified")
        
        # Initialize default configuration
        print("\n5. Initializing default configuration...")
        init_default_config()
        print("   ✅ Configuration initialized")
        
        print("\n" + "=" * 40)
        print("🎉 Database initialization completed successfully!")
        print("\nYour SpyNet database is ready to use.")
        print(f"Database URL: {settings.neon_database_url or settings.database_url}")
        
        # Show next steps
        print("\nNext steps:")
        print("1. Run 'python test_db_connection.py' to verify everything works")
        print("2. Start the SpyNet application with 'python main.py'")
        
    except Exception as e:
        print(f"\n❌ Database initialization failed: {e}")
        print("\nTroubleshooting:")
        print("1. Check your .env file has the correct database URL")
        print("2. Verify your database instance is running and accessible")
        print("3. Ensure you have the required permissions to create tables")
        print("4. Check your internet connection if using a cloud database")
        sys.exit(1)


if __name__ == "__main__":
    main()