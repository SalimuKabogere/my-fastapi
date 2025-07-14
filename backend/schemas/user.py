from typing import Optional, List
from pydantic import BaseModel, Field, EmailStr
from uuid import UUID
from datetime import datetime

# Base schemas for common fields
class TimestampMixin(BaseModel):
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

# User related schemas
class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    first_name: Optional[str] = Field(None, max_length=100)
    last_name: Optional[str] = Field(None, max_length=100)

class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=128)

class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    first_name: Optional[str] = Field(None, max_length=100)
    last_name: Optional[str] = Field(None, max_length=100)
    password: Optional[str] = Field(None, min_length=8, max_length=128)
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None

class UserResponse(UserBase, TimestampMixin):
    id: UUID
    is_active: bool
    is_verified: bool
    failed_login_attempts: int
    locked_until: Optional[datetime] = None
    last_login: Optional[datetime] = None
    
    class Config:
        from_attributes = True

class UserWithRoles(UserResponse):
    roles: List["RoleResponse"] = []

class UserWithProfile(UserResponse):
    profile: Optional["UserProfileResponse"] = None

# Legacy schemas for backward compatibility
class UserRequest(BaseModel):
    username: str
    role: str = Field(..., description="User role, must be 'admin' or 'user'") 
    password: str

class UserStored(BaseModel):
    uuid: UUID
    username: str
    role: str = Field(..., description="User role, must be 'admin' or 'user'")
    password: str

    class Config:
        from_attributes = True

# Role related schemas
class RoleBase(BaseModel):
    name: str = Field(..., max_length=50)
    description: Optional[str] = None

class RoleCreate(RoleBase):
    pass

class RoleUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=50)
    description: Optional[str] = None
    is_active: Optional[bool] = None

class RoleResponse(RoleBase, TimestampMixin):
    id: UUID
    is_active: bool
    
    class Config:
        from_attributes = True

class RoleWithPermissions(RoleResponse):
    permissions: List["PermissionResponse"] = []

# Permission related schemas
class PermissionBase(BaseModel):
    name: str = Field(..., max_length=100)
    resource: str = Field(..., max_length=50)
    action: str = Field(..., max_length=50)
    description: Optional[str] = None

class PermissionCreate(PermissionBase):
    pass

class PermissionResponse(PermissionBase):
    id: UUID
    
    class Config:
        from_attributes = True

# User Role assignment schemas
class UserRoleAssign(BaseModel):
    user_id: UUID
    role_id: UUID

class UserRoleResponse(BaseModel):
    user_id: UUID
    role_id: UUID
    assigned_at: datetime
    assigned_by: Optional[UUID] = None
    
    class Config:
        from_attributes = True

# User Profile schemas
class UserProfileBase(BaseModel):
    avatar_url: Optional[str] = Field(None, max_length=500)
    bio: Optional[str] = None
    phone: Optional[str] = Field(None, max_length=20)
    timezone: Optional[str] = Field(None, max_length=50)
    language: Optional[str] = Field("en", max_length=10)
    theme: Optional[str] = Field("light", max_length=20)
    notifications_enabled: Optional[bool] = True
    two_factor_enabled: Optional[bool] = False

class UserProfileUpdate(UserProfileBase):
    pass

class UserProfileResponse(UserProfileBase):
    user_id: UUID
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

# Session related schemas
class UserSessionResponse(BaseModel):
    id: UUID
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    is_active: bool
    expires_at: datetime
    created_at: datetime
    last_accessed: datetime
    
    class Config:
        from_attributes = True

# Authentication schemas
class Token(BaseModel):
    access_token: str
    token_type: str
    user_id: Optional[UUID] = None
    role: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str
    role: Optional[str] = Field(None, description="User role, must be 'admin' or 'user'")

class LoginResponse(Token):
    user: UserResponse
    session_id: UUID

# Audit log schemas
class AuditLogResponse(BaseModel):
    id: UUID
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    old_values: Optional[dict] = None
    new_values: Optional[dict] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: datetime
    
    class Config:
        from_attributes = True

class AuditLogWithUser(AuditLogResponse):
    user: Optional[UserResponse] = None

# Password related schemas
class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=128)

class PasswordReset(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8, max_length=128)

class PasswordResetRequest(BaseModel):
    email: EmailStr

# Pagination schemas
class PaginationParams(BaseModel):
    page: int = Field(1, ge=1)
    size: int = Field(10, ge=1, le=100)

class PaginatedResponse(BaseModel):
    items: List[dict]
    total: int
    page: int
    size: int
    pages: int

# Response schemas with status
class UserResponseWithStatus(BaseModel):
    status_code: int
    message: str
    error: Optional[str] = None
    data: Optional[UserResponse] = None

# Batch operations
class UserIDsUpdateRequest(BaseModel):
    user_ids: List[UUID]

class RolesUpdateRequest(BaseModel):
    roles: List[str]

# Two-factor authentication
class TwoFactorSetup(BaseModel):
    secret: str
    qr_code: str

class TwoFactorVerify(BaseModel):
    token: str

# Admin dashboard schemas
class UserStats(BaseModel):
    total_users: int
    active_users: int
    verified_users: int
    locked_users: int
    recent_registrations: int

class LoginStats(BaseModel):
    successful_logins: int
    failed_logins: int
    unique_ips: int
    top_failure_reasons: List[dict]

# Forward references for circular imports
UserWithRoles.model_rebuild()
RoleWithPermissions.model_rebuild()
