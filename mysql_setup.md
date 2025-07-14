# MySQL Database Setup Guide

## Current Status: ✅ WORKING WITH SQLITE

Your app is now successfully running with a **real database** (SQLite) instead of in-memory storage!

### 🎉 **Working Database Endpoints:**

1. **GET /api/db/init** - Initialize database tables
2. **POST /api/db/register** - Register users in database
3. **POST /api/db/login** - Login with database authentication
4. **GET /api/db/users** - Get all users from database
5. **GET /api/db/status** - Check database connection status

## Switch to MySQL Database

### Option 1: Local MySQL Server

1. **Install MySQL Server:**

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install mysql-server

# macOS
brew install mysql

# Windows
# Download from https://dev.mysql.com/downloads/mysql/
```

2. **Start MySQL and Create Database:**

```bash
sudo mysql -u root -p

CREATE DATABASE userdb;
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'secure_password';
GRANT ALL PRIVILEGES ON userdb.* TO 'app_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

3. **Update .env file:**

```env
DATABASE_URL=mysql+pymysql://app_user:secure_password@localhost:3306/userdb
```

### Option 2: Cloud MySQL (Recommended)

#### A. **AWS RDS MySQL**

```env
DATABASE_URL=mysql+pymysql://username:password@your-rds-endpoint:3306/userdb
```

#### B. **Google Cloud SQL**

```env
DATABASE_URL=mysql+pymysql://username:password@your-cloudsql-ip:3306/userdb
```

#### C. **PlanetScale (Serverless MySQL)**

```env
DATABASE_URL=mysql+pymysql://username:password@aws.connect.psdb.cloud/userdb?ssl_disabled=true
```

#### D. **Railway/Render/DigitalOcean**

```env
DATABASE_URL=mysql+pymysql://username:password@your-host:3306/userdb
```

### Option 3: Docker MySQL (Development)

```yaml
# docker-compose.yml
version: "3.8"
services:
  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: rootpassword
      MYSQL_DATABASE: userdb
      MYSQL_USER: app_user
      MYSQL_PASSWORD: secure_password
    ports:
      - "3306:3306"
    volumes:
      - mysql_data:/var/lib/mysql

volumes:
  mysql_data:
```

```bash
docker-compose up -d
```

Then use:

```env
DATABASE_URL=mysql+pymysql://app_user:secure_password@localhost:3306/userdb
```

## Testing the Switch

1. **Update your .env file** with MySQL connection string
2. **Restart the server** - it will automatically detect MySQL
3. **Initialize the database**: `curl -X GET http://localhost:8003/api/db/init`
4. **Check status**: `curl -X GET http://localhost:8003/api/db/status`

You should see:

```json
{
  "status": "connected",
  "database_type": "mysql",
  "connection_test": true,
  "user_count": 1
}
```

## Current Working Endpoints

### ✅ **Authentication Endpoints** (In-Memory - Legacy)

- `POST /api/auth/register` - Register (in-memory)
- `POST /api/auth/login` - Login (in-memory)

### ✅ **Database Endpoints** (Real Database)

- `GET /api/db/init` - Initialize database
- `POST /api/db/register` - Register in database
- `POST /api/db/login` - Login with database
- `GET /api/db/users` - List database users
- `GET /api/db/status` - Database status

### Example Usage

```bash
# Initialize database
curl -X GET http://localhost:8003/api/db/init

# Register user in database
curl -X POST http://localhost:8003/api/db/register \
  -H "Content-Type: application/json" \
  -d '{"username": "john", "password": "password123!", "role": "user"}'

# Login
curl -X POST "http://localhost:8003/api/db/login?username=john&password=password123!"

# Get all users
curl -X GET http://localhost:8003/api/db/users
```

## Migration Path

1. **Current**: Mixed system (legacy in-memory + new database endpoints)
2. **Next Step**: Migrate all legacy endpoints to use database
3. **Final**: Pure database-driven application

Your app is now **database-ready** and can easily switch between SQLite and MySQL! 🚀
