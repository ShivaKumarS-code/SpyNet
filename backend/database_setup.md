# Database Setup Instructions

## NeonDB PostgreSQL Setup

### 1. Create NeonDB Account and Database

1. Go to [NeonDB](https://neon.tech/) and create a free account
2. Create a new project/database
3. Copy the connection string from the dashboard
4. The connection string format will be:
   ```
   postgresql://username:password@ep-hostname.region.neon.tech/database_name?sslmode=require
   ```

### 2. Configure Environment Variables

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Update the `.env` file with your NeonDB connection string:
   ```
   NEON_DATABASE_URL=postgresql://username:password@ep-hostname.region.neon.tech/database_name?sslmode=require
   ```

### 3. Database Schema

The database uses SQLAlchemy ORM with the following main tables:

- **`packets`** - Stores captured packet information with performance indexes
- **`alerts`** - Stores security alerts with severity levels and resolution tracking
- **`connections`** - Tracks network connections and flow statistics
- **`config`** - System configuration settings stored as JSON
- **`migrations`** - Tracks applied database schema migrations

### 4. Initialize Database

Run the database initialization script to set up tables and default configuration:
```bash
python init_database.py
```

This script will:
- Test the database connection
- Run all pending migrations
- Create database tables with proper indexes
- Initialize default configuration settings

### 5. Test Database Connection and Models

Run comprehensive database tests:
```bash
python test_db_connection.py
```

This will test:
- Basic database connectivity
- SQLAlchemy model operations
- Database table creation
- Sample data insertion and retrieval

### 6. Database Migrations

The system includes an automated migration system:

```bash
# Run all pending migrations
python migrations.py

# Check migration status
python -c "from migrations import get_migration_status; print(get_migration_status())"
```

### 7. Database Operations

The system provides high-level database operations through the `database.py` module:

```python
from database import store_packet, create_alert, get_traffic_stats

# Store a packet
packet_data = {
    'src_ip': '192.168.1.100',
    'dst_ip': '8.8.8.8',
    'protocol': 'TCP',
    'size': 1500
}
packet = store_packet(packet_data)

# Create an alert
alert_data = {
    'alert_type': 'PORT_SCAN',
    'severity': 'High',
    'source_ip': '192.168.1.100',
    'description': 'Port scan detected'
}
alert = create_alert(alert_data)

# Get traffic statistics
stats = get_traffic_stats(hours=24)
```

## Database Performance Features

### Indexes
- Timestamp-based indexes for efficient time-range queries
- IP address indexes for fast source/destination lookups
- Composite indexes for common query patterns
- Partial indexes for active connections and unresolved alerts

### Connection Pooling
- SQLAlchemy connection pooling with configurable pool size
- Automatic connection recycling to handle long-running connections
- Connection health checks with pre-ping validation

### Data Cleanup
- Automated cleanup of old packet data to manage database size
- Configurable retention policies for different data types
- Efficient bulk deletion operations

## Local PostgreSQL Setup (Alternative)

If you prefer to use a local PostgreSQL instance:

1. Install PostgreSQL locally
2. Create a database named `spynet`
3. Update the `DATABASE_URL` in `.env`:
   ```
   DATABASE_URL=postgresql://username:password@localhost:5432/spynet
   ```
4. Run the same initialization steps as above

## Troubleshooting

### Common Issues

1. **Connection timeout**: Ensure your database instance is running and accessible
2. **SSL errors**: Make sure to include `?sslmode=require` for NeonDB connections
3. **Permission errors**: Verify your database user has CREATE TABLE permissions
4. **Migration failures**: Check the `migrations` table for failed migration records

### Performance Tuning

1. **Index usage**: Monitor query performance and add indexes as needed
2. **Connection pool size**: Adjust based on your application's concurrency needs
3. **Data retention**: Configure appropriate cleanup intervals for your use case