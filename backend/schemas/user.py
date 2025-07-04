from typing import Optional
from pydantic import BaseModel, Field
from uuid import UUID

class CreateUser(BaseModel):
    username: str
    password: str
    role: str = Field(..., description="User role, must be 'admin' or 'user'")

class UserLogin(BaseModel):
    username: str
    password: str

    class Config:
        from_attributes = True

class ShowUser(BaseModel):
    user_id: UUID
    username: str
    role: str = Field(..., description="User role, must be 'admin' or 'user'")

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

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

class UserResponse(BaseModel):
    user_id: UUID
    username: str
    role: str = Field(..., description="User role, must be 'admin' or 'user'")

    class Config:
        from_attributes = True 
    

class UserResponseWithStatus(BaseModel):
    status_code: int
    message: str
    error: Optional[str] = None
    data: Optional[UserResponse] = None

class LoginRequest(BaseModel):
    username: str
    password: str
    role: str = Field(..., description="User role, must be 'admin' or 'user'")