# MySQL Migration Guide

## ⚠️ Why Was MySQL Removed?

As of **v0.5.0**, PII-Radar no longer supports MySQL/MariaDB database scanning due to an unfixable security vulnerability in one of its dependencies.

### Security Details

- **Vulnerability**: [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) - Marvin Attack on RSA decryption
- **Affected Crate**: `rsa 0.9.10` (transitive dependency via `sqlx-mysql`)
- **Severity**: Critical timing attack vulnerability
- **Status**: No fix available from upstream maintainers
- **Impact**: Could allow attackers to decrypt RSA-encrypted data through timing analysis
- **Decision**: Removed MySQL support entirely to maintain our zero-vulnerability policy

### What This Means for You

If you were using PII-Radar's MySQL database scanning feature (`--db-type mysql`), you will need to migrate to one of the supported alternatives:

1. **PostgreSQL** (Recommended for SQL databases)
2. **MongoDB** (NoSQL alternative)

---

## 🚀 Migration Options

### Option 1: Migrate to PostgreSQL (Recommended)

**Best for**: Users who need relational database compatibility with minimal migration effort

#### Why PostgreSQL?

- ✅ Most SQL-compatible with MySQL
- ✅ Excellent performance and scalability
- ✅ Strong ACID compliance
- ✅ Active development and security updates
- ✅ Wide industry adoption

#### Migration Steps

##### 1. Install PostgreSQL

```bash
# Ubuntu/Debian
sudo apt-get install postgresql postgresql-contrib

# macOS
brew install postgresql

# Start PostgreSQL service
sudo systemctl start postgresql  # Linux
brew services start postgresql   # macOS
```

##### 2. Migrate Your Data

**Option A: Using pg_loader (Recommended)**

```bash
# Install pgloader
sudo apt-get install pgloader  # Debian/Ubuntu
brew install pgloader          # macOS

# Create migration config
cat > migration.load << 'PGLOADER'
LOAD DATABASE
    FROM mysql://user:password@localhost:3306/mydb
    INTO postgresql://pguser:pgpass@localhost:5432/mydb
WITH include drop, create tables, create indexes, reset sequences
SET maintenance_work_mem to '128MB', work_mem to '12MB'
CAST type datetime to timestamptz drop default drop not null using zero-dates-to-null;
PGLOADER

# Run migration
pgloader migration.load
```

**Option B: Manual mysqldump + psql**

```bash
# Export from MySQL
mysqldump -u user -p --compatible=postgresql \
  --default-character-set=utf8 mydb > mysql_dump.sql

# Edit the dump file to fix PostgreSQL incompatibilities
# (auto_increment → serial, backticks, etc.)

# Import to PostgreSQL
psql -U pguser -d mydb -f mysql_dump.sql
```

##### 3. Update PII-Radar Commands

**Before (MySQL):**
```bash
pii-radar scan-db \
  --db-type mysql \
  --connection "mysql://user:pass@localhost:3306/mydb" \
  --tables "users,orders" \
  --exclude-columns "id,created_at"
```

**After (PostgreSQL):**
```bash
pii-radar scan-db \
  --db-type postgres \
  --connection "postgresql://user:pass@localhost:5432/mydb" \
  --tables "users,orders" \
  --exclude-columns "id,created_at"
```

##### 4. Key Differences to Note

| MySQL | PostgreSQL | Notes |
|-------|------------|-------|
| `mysql://` | `postgresql://` | Connection string prefix |
| Port 3306 | Port 5432 | Default ports |
| `LIMIT n OFFSET m` | `LIMIT n OFFSET m` | ✅ Same syntax |
| Backticks \`table\` | Double quotes "table" | Case-sensitive identifiers |
| `AUTO_INCREMENT` | `SERIAL` | Auto-incrementing IDs |

---

### Option 2: Migrate to MongoDB

**Best for**: Users who prefer NoSQL flexibility or have semi-structured data

#### Why MongoDB?

- ✅ Flexible schema - no migrations needed
- ✅ Great for JSON-like documents
- ✅ Horizontal scalability
- ✅ Easy to get started
- ⚠️ Different query model (not SQL)

#### Migration Steps

##### 1. Install MongoDB

```bash
# Ubuntu 22.04
wget -qO - https://www.mongodb.org/static/pgp/server-7.0.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
sudo apt-get update
sudo apt-get install -y mongodb-org

# macOS
brew tap mongodb/brew
brew install mongodb-community

# Start MongoDB
sudo systemctl start mongod  # Linux
brew services start mongodb-community  # macOS
```

##### 2. Migrate Your Data

**Using mysql-mongodb-migrator:**

```bash
# Install Node.js tool
npm install -g mysql-to-mongodb

# Run migration
mysql-to-mongodb \
  --mysql-host localhost \
  --mysql-port 3306 \
  --mysql-user user \
  --mysql-password pass \
  --mysql-database mydb \
  --mongodb-uri "mongodb://localhost:27017" \
  --mongodb-database mydb
```

**Manual Python script:**

```python
import mysql.connector
from pymongo import MongoClient

# Connect to MySQL
mysql_conn = mysql.connector.connect(
    host="localhost", user="user", password="pass", database="mydb"
)
mysql_cursor = mysql_conn.cursor(dictionary=True)

# Connect to MongoDB
mongo_client = MongoClient("mongodb://localhost:27017")
mongo_db = mongo_client["mydb"]

# Migrate each table
tables = ["users", "orders", "products"]
for table in tables:
    mysql_cursor.execute(f"SELECT * FROM {table}")
    rows = mysql_cursor.fetchall()
    
    # Convert rows to MongoDB documents
    if rows:
        mongo_db[table].insert_many(rows)
        print(f"Migrated {len(rows)} rows from {table}")

mysql_conn.close()
mongo_client.close()
```

##### 3. Update PII-Radar Commands

**Before (MySQL):**
```bash
pii-radar scan-db \
  --db-type mysql \
  --connection "mysql://user:pass@localhost:3306/mydb" \
  --tables "users,orders"
```

**After (MongoDB):**
```bash
pii-radar scan-db \
  --db-type mongodb \
  --connection "mongodb://localhost:27017" \
  --database mydb \
  --tables "users,orders"
```

##### 4. Key Differences

| Concept | MySQL | MongoDB |
|---------|-------|---------|
| Structure | Tables with fixed schemas | Collections with flexible documents |
| Rows | Rows | Documents (JSON-like) |
| Columns | Fixed columns | Fields (can vary per document) |
| Query | SQL | MongoDB Query Language (MQL) |
| Relationships | Foreign keys | Embedded documents or references |

---

## 📊 Comparison Table

| Feature | PostgreSQL | MongoDB |
|---------|------------|---------|
| **SQL Compatibility** | ✅ High | ❌ No (uses MQL) |
| **Migration Effort** | Low | Medium |
| **Schema** | Structured (tables) | Flexible (documents) |
| **ACID Transactions** | ✅ Full support | ✅ (with replica sets) |
| **Performance** | Excellent for complex queries | Excellent for simple queries |
| **Scalability** | Vertical (with replication) | Horizontal (built-in sharding) |
| **Learning Curve** | Low (if you know SQL) | Medium |
| **Community** | Large | Large |
| **PII-Radar Support** | ✅ Full | ✅ Full |

---

## 🔧 Testing Your Migration

After migrating, test PII-Radar to ensure it works correctly:

### PostgreSQL Test

```bash
# Quick connectivity test
pii-radar scan-db \
  --db-type postgres \
  --connection "postgresql://user:pass@localhost:5432/mydb" \
  --tables "users" \
  --row-limit 100 \
  --format terminal

# Full scan with output
pii-radar scan-db \
  --db-type postgres \
  --connection "postgresql://user:pass@localhost:5432/mydb" \
  --format json \
  --output pii_results.json
```

### MongoDB Test

```bash
# Quick connectivity test
pii-radar scan-db \
  --db-type mongodb \
  --connection "mongodb://localhost:27017" \
  --database mydb \
  --tables "users" \
  --row-limit 100 \
  --format terminal

# Full scan with output
pii-radar scan-db \
  --db-type mongodb \
  --connection "mongodb://localhost:27017" \
  --database mydb \
  --format json \
  --output pii_results.json
```

---

## 🆘 Need Help?

### Common Issues

**Q: I can't migrate my MySQL database right now. Can I use an older version?**

A: Yes, you can use PII-Radar v0.4.0 which still has MySQL support:

```bash
cargo install --git https://github.com/silv3rshi3ld/gdpr-pii-scanner --tag v0.4.0
```

⚠️ **Warning**: v0.4.0 contains known security vulnerabilities. Use at your own risk.

**Q: My connection string doesn't work in PostgreSQL**

A: Check these common issues:
- Port changed from 3306 → 5432
- Prefix changed from `mysql://` → `postgresql://`
- PostgreSQL requires explicit database name in connection string
- Check username/password are correct for PostgreSQL (different from MySQL users)

**Q: Performance is slower after migration**

A: Run these optimizations:

**PostgreSQL:**
```sql
-- Analyze tables for query planning
ANALYZE;

-- Create indexes on frequently scanned columns
CREATE INDEX idx_users_email ON users(email);

-- Adjust work_mem for large scans
SET work_mem = '256MB';
```

**MongoDB:**
```javascript
// Create indexes
db.users.createIndex({ email: 1 });
db.users.createIndex({ phone: 1 });

// Check query performance
db.users.find({ email: /pattern/ }).explain("executionStats");
```

### Getting Support

- 📖 [Database Scanning Guide](docs/DATABASE_SCANNING.md)
- 🐛 [Report Issues](https://github.com/silv3rshi3ld/gdpr-pii-scanner/issues)
- 💬 [Discussions](https://github.com/silv3rshi3ld/gdpr-pii-scanner/discussions)
- 📧 Email: (if available)

---

## 📅 Timeline

- **v0.4.0** (2026-01-28): Last version with MySQL support
- **v0.5.0** (2026-01-28): MySQL removed, PostgreSQL/MongoDB only
- **Future**: SQLite support planned for v0.5.x

---

## ✅ Migration Checklist

- [ ] Choose migration target (PostgreSQL or MongoDB)
- [ ] Install target database
- [ ] Backup MySQL data
- [ ] Run migration tool/script
- [ ] Verify data integrity
- [ ] Update PII-Radar connection strings
- [ ] Test PII scanning on new database
- [ ] Update application code (if using MySQL for other purposes)
- [ ] Update CI/CD pipelines
- [ ] Document changes for your team
- [ ] Decommission MySQL (optional)

---

*Last updated: 2026-01-28*  
*For questions or issues with this guide, please [open an issue](https://github.com/silv3rshi3ld/gdpr-pii-scanner/issues).*
