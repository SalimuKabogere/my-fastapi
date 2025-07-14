# Database Design & Architecture Improvements

## Current Issues

1. **Data Loss**: In-memory storage loses all data on restart
2. **No Relationships**: No way to track user sessions, activity, or relationships
3. **Limited Audit**: No logging of who did what when
4. **No Session Management**: JWT tokens can't be revoked
5. **Poor Scalability**: Dictionary lookups don't scale
6. **Security Gaps**: No password history, account lockout, or session tracking

## Proposed Database Schema

### 1. Users Table (Enhanced)

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP NULL,
    last_login TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by UUID REFERENCES users(id),
    updated_by UUID REFERENCES users(id)
);
```

### 2. Roles & Permissions (RBAC)

```sql
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    description TEXT
);

CREATE TABLE role_permissions (
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    assigned_by UUID REFERENCES users(id),
    PRIMARY KEY (user_id, role_id)
);
```

### 3. Session Management

```sql
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 4. Security & Audit

```sql
CREATE TABLE password_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    old_values JSONB,
    new_values JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE login_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50),
    ip_address INET,
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 5. User Profiles & Settings

```sql
CREATE TABLE user_profiles (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    avatar_url VARCHAR(500),
    bio TEXT,
    phone VARCHAR(20),
    timezone VARCHAR(50),
    language VARCHAR(10) DEFAULT 'en',
    theme VARCHAR(20) DEFAULT 'light',
    notifications_enabled BOOLEAN DEFAULT TRUE,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Entity Relationship Diagram (ERD)

```mermaid
erDiagram
    USERS {
        uuid id PK
        varchar(50) username UK
        varchar(255) email UK
        varchar(255) password_hash
        varchar(100) first_name
        varchar(100) last_name
        boolean is_active
        boolean is_verified
        integer failed_login_attempts
        timestamp locked_until
        timestamp last_login
        timestamp created_at
        timestamp updated_at
        uuid created_by FK
        uuid updated_by FK
    }

    ROLES {
        uuid id PK
        varchar(50) name UK
        text description
        boolean is_active
        timestamp created_at
    }

    PERMISSIONS {
        uuid id PK
        varchar(100) name UK
        varchar(50) resource
        varchar(50) action
        text description
    }

    USER_ROLES {
        uuid user_id PK,FK
        uuid role_id PK,FK
        timestamp assigned_at
        uuid assigned_by FK
    }

    ROLE_PERMISSIONS {
        uuid role_id PK,FK
        uuid permission_id PK,FK
    }

    USER_SESSIONS {
        uuid id PK
        uuid user_id FK
        varchar(255) token_hash
        varchar(45) ip_address
        text user_agent
        boolean is_active
        timestamp expires_at
        timestamp created_at
        timestamp last_accessed
    }

    PASSWORD_HISTORY {
        uuid id PK
        uuid user_id FK
        varchar(255) password_hash
        timestamp created_at
    }

    AUDIT_LOGS {
        uuid id PK
        uuid user_id FK
        varchar(100) action
        varchar(50) resource_type
        varchar(255) resource_id
        json old_values
        json new_values
        varchar(45) ip_address
        text user_agent
        timestamp created_at
    }

    LOGIN_ATTEMPTS {
        uuid id PK
        varchar(50) username
        varchar(45) ip_address
        boolean success
        varchar(255) failure_reason
        timestamp created_at
    }

    USER_PROFILES {
        uuid user_id PK,FK
        varchar(500) avatar_url
        text bio
        varchar(20) phone
        varchar(50) timezone
        varchar(10) language
        varchar(20) theme
        boolean notifications_enabled
        boolean two_factor_enabled
        varchar(255) two_factor_secret
        timestamp updated_at
    }

    %% Core User Management
    USERS ||--o{ USER_ROLES : "has"
    ROLES ||--o{ USER_ROLES : "assigned to"
    ROLES ||--o{ ROLE_PERMISSIONS : "has"
    PERMISSIONS ||--o{ ROLE_PERMISSIONS : "belongs to"

    %% User Profile and Sessions
    USERS ||--|| USER_PROFILES : "has profile"
    USERS ||--o{ USER_SESSIONS : "has sessions"

    %% Security and Audit
    USERS ||--o{ PASSWORD_HISTORY : "tracks"
    USERS ||--o{ AUDIT_LOGS : "generates"

    %% Self-referential relationships
    USERS ||--o{ USERS : "created_by"
    USERS ||--o{ USERS : "updated_by"
    USERS ||--o{ USER_ROLES : "assigned_by"
```

## Database Indexes and Performance

```sql
-- Primary performance indexes
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_is_active ON users(is_active);
CREATE INDEX idx_users_last_login ON users(last_login);

-- Session management indexes
CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_token_hash ON user_sessions(token_hash);
CREATE INDEX idx_user_sessions_expires_at ON user_sessions(expires_at);
CREATE INDEX idx_user_sessions_is_active ON user_sessions(is_active);

-- Audit and security indexes
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_login_attempts_username ON login_attempts(username);
CREATE INDEX idx_login_attempts_ip_address ON login_attempts(ip_address);
CREATE INDEX idx_login_attempts_created_at ON login_attempts(created_at);

-- RBAC indexes
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX idx_role_permissions_role_id ON role_permissions(role_id);
```

## Connecting to Real Databases

### PostgreSQL Configuration

1. **Install PostgreSQL driver:**

```bash
pip install psycopg2-binary
```

2. **Environment Variables:**

```bash
export DATABASE_URL="postgresql://username:password@localhost:5432/dbname"
export DB_POOL_SIZE=10
export DB_MAX_OVERFLOW=20
export SQL_DEBUG=false
```

3. **Docker PostgreSQL Setup:**

```yaml
# docker-compose.yml
version: "3.8"
services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: userdb
      POSTGRES_USER: admin
      POSTGRES_PASSWORD: your_password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql

volumes:
  postgres_data:
```

### MySQL Configuration

1. **Install MySQL driver:**

```bash
pip install mysqlclient
# or
pip install PyMySQL
```

2. **Environment Variables:**

```bash
export DATABASE_URL="mysql+pymysql://username:password@localhost:3306/dbname"
```

### Production Database Setup

```sql
-- PostgreSQL production setup script
-- Create database
CREATE DATABASE userdb;
CREATE USER app_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE userdb TO app_user;

-- Enable UUID extension
\c userdb;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create tables (run the schema from above)
-- Add production indexes
-- Set up backup jobs
```

### Environment Configuration

Create a `.env` file:

```env
# Database Configuration
DATABASE_URL=postgresql://app_user:secure_password@localhost:5432/userdb
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=30
SQL_DEBUG=false

# JWT Configuration
JWT_SECRET_KEY=your-super-secret-jwt-key
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30

# Email Configuration (for verification)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# Security Configuration
PASSWORD_MIN_LENGTH=8
MAX_FAILED_LOGIN_ATTEMPTS=5
ACCOUNT_LOCKOUT_DURATION_MINUTES=30
```

### Migration Commands

```bash
# Initialize database
python backend/database_init.py --reset --seed

# Create migration (future feature)
python manage.py create_migration "add_user_preferences"

# Apply migrations
python manage.py migrate

# Rollback migration
python manage.py rollback 1
```

## Key Improvements

### 1. **Persistent Storage**

- SQLite/PostgreSQL instead of in-memory dictionaries
- Data survives server restarts

### 2. **Enhanced Security**

- Account lockout after failed attempts
- Password history to prevent reuse
- Session management with revocation
- Audit logging for compliance
- Two-factor authentication support

### 3. **Role-Based Access Control (RBAC)**

- Granular permissions system
- Multiple roles per user
- Dynamic permission assignment

### 4. **User Experience**

- User profiles with preferences
- Email verification
- Password reset functionality
- Session management across devices

### 5. **Observability**

- Comprehensive audit logging
- Login attempt tracking
- Session monitoring
- User activity analytics

### 6. **Scalability**

- Proper database indexes
- Efficient query patterns
- Support for database clustering

## Migration Strategy

1. **Phase 1**: Core user management with persistent storage
2. **Phase 2**: RBAC implementation
3. **Phase 3**: Security enhancements (audit, sessions)
4. **Phase 4**: User experience features
5. **Phase 5**: Advanced analytics and monitoring

## API Enhancements

### New Endpoints

- `POST /auth/verify-email`
- `POST /auth/resend-verification`
- `POST /auth/enable-2fa`
- `GET /users/me/sessions`
- `DELETE /users/me/sessions/{session_id}`
- `GET /users/me/audit-logs`
- `PUT /users/me/profile`
- `GET /admin/audit-logs`
- `GET /admin/login-attempts`

### Enhanced Existing Endpoints

- Add pagination to user lists
- Include user profiles in responses
- Add filtering and search capabilities
- Include last login and status information
