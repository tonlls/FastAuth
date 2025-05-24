"""
Permission schemas.
"""

from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


class PermissionBase(BaseModel):
    """Base permission schema."""
    
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    resource: Optional[str] = Field(None, max_length=100)
    action: Optional[str] = Field(None, max_length=50)
    is_active: bool = True
    permission_metadata: Optional[Dict[str, Any]] = None


class PermissionCreate(PermissionBase):
    """Permission creation schema."""
    pass


class PermissionUpdate(BaseModel):
    """Permission update schema."""
    
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    resource: Optional[str] = Field(None, max_length=100)
    action: Optional[str] = Field(None, max_length=50)
    is_active: Optional[bool] = None
    permission_metadata: Optional[Dict[str, Any]] = None


class PermissionInDB(PermissionBase):
    """Permission schema for database operations."""
    
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    created_at: datetime
    updated_at: Optional[datetime] = None
    created_by: Optional[UUID] = None


class PermissionResponse(PermissionBase):
    """Permission response schema."""
    
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    created_at: datetime
    updated_at: Optional[datetime] = None
    created_by: Optional[UUID] = None
    roles_count: Optional[int] = None
