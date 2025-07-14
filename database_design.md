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
