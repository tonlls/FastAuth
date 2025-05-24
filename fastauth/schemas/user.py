"""
User schemas.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, ConfigDict

if TYPE_CHECKING:
    from .role import RoleResponse


class UserBase(BaseModel):
    """Base user schema."""
    
    email: EmailStr
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    is_active: bool = True
    is_verified: bool = False
    auth_provider: Optional[str] = None
    external_id: Optional[str] = None
    user_metadata: Optional[Dict[str, Any]] = None


class UserCreate(UserBase):
    """User creation schema."""
    
    password: Optional[str] = None  # Optional for external auth
    is_superuser: bool = False


class UserUpdate(BaseModel):
    """User update schema."""
    
    email: Optional[EmailStr] = None
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    is_superuser: Optional[bool] = None
    password: Optional[str] = None
    user_metadata: Optional[Dict[str, Any]] = None


class UserInDB(UserBase):
    """User schema for database operations."""
    
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    hashed_password: Optional[str] = None
    is_superuser: bool = False
    created_at: datetime
    updated_at: Optional[datetime] = None
    last_login: Optional[datetime] = None


class UserResponse(UserBase):
    """User response schema."""
    
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    is_superuser: bool = False
    created_at: datetime
    updated_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    roles: List["RoleResponse"] = Field(default_factory=list)


class UserWithPermissions(UserResponse):
    """User response with permissions."""
    
    permissions: List[str] = Field(default_factory=list)
