from fastapi import FastAPI, Depends, HTTPException, status, Form
from backend.utils.authentication import create_access_token, get_current_user, hash_password, verify_password, role_checker
from backend.models.database import engine, SessionLocal, Base
from fastapi.security import OAuth2PasswordBearer
from typing import List, Tuple
from uuid import UUID, uuid4
from backend.schemas.user import UserRequest, UserResponse, UserResponseWithStatus, UserStored, Token
from backend.models.storage import user_db, username_map
import re
import html
from urllib.parse import unquote
from backend.utils.sanitization import sanitize_username, validate_password, sanitize_free_text
import logging
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html, get_swagger_ui_oauth2_redirect_html
from fastapi import APIRouter

Base.metadata.create_all(bind=engine)

# logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(docs_url=None, redoc_url=None, swagger_ui_oauth2_redirect_url="/oauth2-redirect")



app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Add your frontend URLs here
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth_scheme = OAuth2PasswordBearer(tokenUrl='login')
redirect_path = app.swagger_ui_oauth2_redirect_url or "/oauth2-redirect"
openapi_url = app.openapi_url or "/openapi.json"

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Input sanitization function
def sanitize_input(input_str: str) -> str:
    """Sanitize user input to prevent XSS and injection attacks"""
    if not input_str:
        return ""
    # Decode URL encoding
    decoded = unquote(input_str)
    # Remove script tags (case-insensitive)
    no_script = re.sub(r'<script.*?</script>', '', decoded, flags=re.IGNORECASE | re.DOTALL)
    # Remove all HTML tags
    no_tags = re.sub(r'<.*?>', '', no_script)
    # Escape any remaining HTML special characters
    escaped = html.escape(no_tags)
    return escaped.strip()

# Validate UUID format
def validate_uuid(uuid_str: str) -> bool:
    """Validate if string is a valid UUID format"""
    uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
    return bool(uuid_pattern.match(uuid_str))

@app.get("/", include_in_schema=False)
async def custom_swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url= openapi_url,
        title="My API - Swagger UI",
        oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
        swagger_ui_parameters={"defaultModelsExpandDepth": -1}
    )

@app.get(redirect_path, include_in_schema=False)
async def swagger_ui_redirect():
    return get_swagger_ui_oauth2_redirect_html()

# Create an APIRouter for auth endpoints
auth_router = APIRouter(prefix="/api/auth", tags=["auth"])

# Auth endpoints grouped together in logical order
@auth_router.post("/register", response_model=UserResponse)
def register_user(user: UserRequest) -> UserResponse:
    # Sanitize input
    sanitized_username = sanitize_username(user.username)
    sanitized_role = sanitize_free_text(user.role, max_length=16)
    # Validate role
    if sanitized_role not in ["admin", "user"]:
        logging.error(f"Invalid role: {sanitized_role}")
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'user'")
    # Check for duplicate username
    if sanitized_username in username_map:
        logging.error(f"Username already exists: {sanitized_username}")
        raise HTTPException(status_code=400, detail=f"Username '{sanitized_username}' already exists")
    # Validate password
    if not validate_password(user.password):
        logging.error(f"Invalid password: {user.password}")
        raise HTTPException(status_code=400, detail="Password must be 8-128 characters and include a letter, number, and symbol.")
    # Generate user ID
    user_id = uuid4()
    username_map[sanitized_username] = user_id
    # Store user with hashed password
    stored = UserStored(
        uuid=user_id,
        username=sanitized_username,
        role=sanitized_role,
        password=hash_password(user.password)
    )
    user_db[user_id] = stored
    # Prepare response
    response = UserResponse(
        user_id=user_id,
        username=sanitized_username,
        role=sanitized_role
    )
    logging.info(f"User registered successfully: {sanitized_username}")
    return response

@auth_router.post("/login", response_model=Token)
def login_user(
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form(...)
):
    # Sanitize input
    sanitized_username = sanitize_username(username)
    sanitized_role = sanitize_free_text(role, max_length=16)
    user_id = username_map.get(sanitized_username)
    if not user_id:
        logging.error(f"User not found: {sanitized_username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user = user_db.get(user_id)
    if not user or not verify_password(password, user.password):
        logging.error(f"Invalid credentials: {sanitized_username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.role != sanitized_role:
        logging.error(f"Role does not match user: {sanitized_username}")
        raise HTTPException(status_code=401, detail="Role does not match user")
    token = create_access_token(data={"sub": sanitized_username})
    logging.info(f"User logged in successfully: {sanitized_username}")
    return {"access_token": token, "token_type": "bearer"}

@auth_router.post("/logout")
def logout_user(current: Tuple[UUID, UserStored] = Depends(get_current_user)):
    # For JWT, logout is typically handled client-side by deleting the token.
    # If using token blacklisting, add token to blacklist here.
    return {"message": "Logged out successfully"}

@auth_router.post("/forgot-password")
def forgot_password(username: str = Form(...)):
    # Simulate sending a password reset link or code to the user's email.
    # In production, look up user by username/email and send email with token.
    if username not in username_map:
        raise HTTPException(status_code=404, detail="User not found")
    # Here, you would generate a reset token and send it via email.
    return {"message": f"Password reset instructions sent to the email for {username}"}

@auth_router.post("/reset-password")
def reset_password(username: str = Form(...), new_password: str = Form(...), reset_token: str = Form(...)):
    # In production, validate the reset_token and ensure it matches the user.
    if username not in username_map:
        raise HTTPException(status_code=404, detail="User not found")
    if not new_password or new_password.strip() == "":
        raise HTTPException(status_code=400, detail="Password cannot be empty.")
    if not validate_password(new_password):
        raise HTTPException(status_code=400, detail="Password must be 8-128 characters and include a letter, number, and symbol.")
    user_id = username_map[username]
    user = user_db[user_id]
    # Check if new password is the same as the current password
    if verify_password(new_password, user.password):
        raise HTTPException(status_code=400, detail="New password must be different from the current password.")
    # Optionally, add more criteria here (e.g., password history, common passwords, etc.)
    user.password = hash_password(new_password)
    # Invalidate the reset token here in production.
    return {"message": "Password reset successful"}


@app.get("/users/", response_model=List[UserResponse])
def get_all_users(current: Tuple[UUID, UserStored]=Depends(get_current_user)):
    return [
        UserResponse(
            user_id=uid,
            username=user.username,
            role=user.role
        )
        for uid, user in user_db.items()
    ]


@app.get("/users/{user_id}", response_model=UserResponse)
def get_user_by_id(user_id: UUID, current: Tuple[UUID, UserStored]=Depends(get_current_user)):
    # Validate UUID format
    if not validate_uuid(str(user_id)):
        raise HTTPException(status_code=400, detail="Invalid user ID format")
    
    user = user_db.get(user_id)
    if not user:
        logging.error(f"User not found: {user_id}")
        raise HTTPException(status_code=404, detail="User not found")
    logging.info(f"User retrieved successfully: {user.username}")
    return UserResponse(
        user_id=user_id,
        username=user.username,
        role=user.role
    )


@app.delete("/users_del/{user_id}")
def delete_user(user_id: UUID, current: Tuple[UUID, UserStored]=Depends(get_current_user)):
    # Validate UUID format
    if not validate_uuid(str(user_id)):
        raise HTTPException(status_code=400, detail="Invalid user ID format")
    
    _, user = current
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can delete users")

    if user_id not in user_db:
        raise HTTPException(status_code=404, detail="User not found")

    del user_db[user_id]
    return {"message": "User deleted successfully"}


# admin dashboard
@app.get("/admin/dashboard", response_model=UserResponseWithStatus)
def admin_dashboard(current: Tuple[UUID, UserStored] = Depends(role_checker(["admin"]))):
    user_id, user = current

    user_data = UserResponse(
        user_id=user_id,
        username=user.username,
        role=user.role
    )

    return UserResponseWithStatus(
        status_code=status.HTTP_200_OK,
        message="Welcome to the admin dashboard",
        error=None,
        data=user_data
    )

# user dashboard
@app.get("/user/dashboard", response_model=UserResponseWithStatus)
def user_dashboard(current: Tuple[UUID, UserStored] = Depends(role_checker(["user"]))):
    user_id, user = current
    user_data = UserResponse(
        user_id=user_id, 
        username=user.username, 
        role=user.role
    )
    
    return UserResponseWithStatus(
        status_code=200,
        message="Welcome to the user dashboard",
        error=None,
        data=user_data
    )

@app.options("/test")
def options_test():
    return {"message": "OPTIONS works"}

# Include the auth_router in the main app
app.include_router(auth_router)