import os
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from typing import Any, Dict, Tuple, List
from jose import jwt, JWTError
from uuid import UUID
from fastapi import Depends, HTTPException, status
from backend.schemas.user import UserStored
from backend.models.storage import user_db, username_map



load_dotenv()
SECRET_KEY_ENV = os.getenv("SECRET_KEY")
PASSWORD_EXPIRE_MINUTES = 30
ALGORITHM = 'HS256'
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login") 

# ensure secret key is given
if SECRET_KEY_ENV is None:
    raise ValueError("A secret key must be provided")
SECRET_KEY= str(SECRET_KEY_ENV)

# Password hashing
pwd_context = CryptContext(schemes=['bcrypt'], deprecated = "auto")
def hash_password(password:str) ->str:
    return pwd_context.hash(password)

# verify password
def verify_password(plain_password:str, hashed_password:str)->bool:
    return pwd_context.verify(plain_password, hashed_password)

# create access_token
def create_access_token(data:Dict[str, Any], expires_delta:timedelta=timedelta(minutes=15)) ->str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc)+ expires_delta
    to_encode.update({"exp":expire})
    encode_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encode_jwt

def get_current_user(token: str = Depends(oauth2_scheme)) -> Tuple[UUID, UserStored]:
    credentials_exception = HTTPException(status_code=401, detail="Invalid authentication")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    # Find user_id from username
    user_id = username_map.get(username)
    

    if not user_id:
        raise credentials_exception

    user = user_db.get(user_id)
    if not user:
        raise credentials_exception
    return user_id, user 

# role checker
def role_checker(allowed_roles: List[str]):
    def checker(current: Tuple[UUID, UserStored] = Depends(get_current_user)):
        _, user = current
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation requires one of the following roles: " + ", ".join(allowed_roles)
            )
        return current
    return checker

