from uuid import UUID
from typing import Dict
from backend.schemas.user import UserStored

user_db: Dict[UUID, UserStored] = {}
username_map: Dict[str, UUID] = {} 