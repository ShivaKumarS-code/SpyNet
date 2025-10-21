"""
Database migration system for SpyNet
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from models import db_manager, Base
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Migration tracking table
class Migration(Base):
    """Track applied database migrations"""
    __tablename__ = 'migrations'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    version = Column(String(50), nullable=False, unique=True)
    description = Column(Text, nullable=False)
    applied_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    success = Column(Boolean, nullable=False, default=True)


class MigrationManager:
    """Manage database migrations"""
    
    def __init__(self):
        self.db_manager = db_manager
        self.migrations = [
            {
                'version': '001_initial_schema',
                'description': 'Create initial database schema with packets, alerts, connections, and config tables',
                'migration_func': self._migration_001_initial_schema
            },
            {
                'version': '002_add_indexes',
                'description': 'Add performance indexes for timestamp and IP queries',
                'migration_func': self._migration_002_add_indexes
            }
        ]
    
    def run_migrations(self):
        """Run all pending migrations"""
        # First ensure migration table exists
        self._ensure_migration_table()
        
        db = self.db_manager.get_session()
        try:
            # Get applied migrations
            applied_migrations = {m.version for m in db.query(Migration).all()}
            
            # Run pending migrations
            for migration in self.migrations:
                if migration['version'] not in applied_migrations:
                    logger.info(f"Running migration: {migration['version']} - {migration['description']}")
                    
                    try:
                        # Run the migration
                        migration['migration_func'](db)
                        
                        # Record successful migration
                        migration_record = Migration(
                            version=migration['version'],
                            description=migration['description'],
                            success=True
                        )
                        db.add(migration_record)
                        db.commit()
                        
                        logger.info(f"Migration {migration['version']} completed successfully")
                        
                    except Exception as e:
                        db.rollback()
                        
                        # Record failed migration
                        migration_record = Migration(
                            version=migration['version'],
                            description=migration['description'],
                            success=False
                        )
                        db.add(migration_record)
                        db.commit()
                        
                        logger.error(f"Migration {migration['version']} failed: {e}")
                        raise
                else:
                    logger.info(f"Migration {migration['version']} already applied, skipping")
                    
        finally:
            db.close()
    
    def _ensure_migration_table(self):
        """Ensure the migration tracking table exists"""
        try:
            # Create just the migration table
            Migration.__table__.create(self.db_manager.engine, checkfirst=True)
        except Exception as e:
            logger.error(f"Error creating migration table: {e}")
            raise
    
    def _migration_001_initial_schema(self, db):
        """Migration 001: Create initial database schema"""
        # Create all tables defined in models
        Base.metadata.create_all(bind=self.db_manager.engine)
        
        # Initialize default configuration
        from models import init_default_config
        init_default_config()
    
    def _migration_002_add_indexes(self, db):
        """Migration 002: Add performance indexes"""
        # Indexes are already defined in the model classes
        # This migration ensures they are created if not already present
        
        # Execute raw SQL to create any missing indexes
        index_queries = [
            """
            CREATE INDEX IF NOT EXISTS idx_packet_timestamp_hour 
            ON packets (DATE_TRUNC('hour', timestamp));
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_alert_recent 
            ON alerts (timestamp DESC) 
            WHERE resolved = false;
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_connection_active 
            ON connections (last_seen DESC) 
            WHERE state = 'ACTIVE';
            """
        ]
        
        for query in index_queries:
            try:
                db.execute(query)
                db.commit()
            except Exception as e:
                logger.warning(f"Index creation warning: {e}")
                db.rollback()
    
    def get_migration_status(self):
        """Get status of all migrations"""
        self._ensure_migration_table()
        
        db = self.db_manager.get_session()
        try:
            applied_migrations = {m.version: m for m in db.query(Migration).all()}
            
            status = []
            for migration in self.migrations:
                version = migration['version']
                if version in applied_migrations:
                    record = applied_migrations[version]
                    status.append({
                        'version': version,
                        'description': migration['description'],
                        'status': 'SUCCESS' if record.success else 'FAILED',
                        'applied_at': record.applied_at
                    })
                else:
                    status.append({
                        'version': version,
                        'description': migration['description'],
                        'status': 'PENDING',
                        'applied_at': None
                    })
            
            return status
            
        finally:
            db.close()


# Global migration manager
migration_manager = MigrationManager()


def run_migrations():
    """Run all pending database migrations"""
    migration_manager.run_migrations()


def get_migration_status():
    """Get migration status"""
    return migration_manager.get_migration_status()


if __name__ == "__main__":
    # Run migrations when executed directly
    print("Running database migrations...")
    run_migrations()
    
    print("\nMigration Status:")
    for status in get_migration_status():
        print(f"  {status['version']}: {status['status']} - {status['description']}")
        if status['applied_at']:
            print(f"    Applied at: {status['applied_at']}")
    
    print("\nDatabase migrations completed!")