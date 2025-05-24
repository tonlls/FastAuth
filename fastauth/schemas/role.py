"""
Role schemas.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict

if TYPE_CHECKING:
    from .permission import PermissionResponse


class RoleBase(BaseModel):
    """Base role schema."""
    
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    is_active: bool = True
    parent_id: Optional[UUID] = None
    role_metadata: Optional[Dict[str, Any]] = None


class RoleCreate(RoleBase):
    """Role creation schema."""
    pass


class RoleUpdate(BaseModel):
    """Role update schema."""
    
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    is_active: Optional[bool] = None
    parent_id: Optional[UUID] = None
    role_metadata: Optional[Dict[str, Any]] = None


class RoleInDB(RoleBase):
    """Role schema for database operations."""
    
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    created_at: datetime
    updated_at: Optional[datetime] = None
    created_by: Optional[UUID] = None


class RoleResponse(RoleBase):
    """Role response schema."""
    
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    created_at: datetime
    updated_at: Optional[datetime] = None
    created_by: Optional[UUID] = None
    permissions: List["PermissionResponse"] = Field(default_factory=list)
    users_count: Optional[int] = None


class RoleWithPermissions(RoleResponse):
    """Role response with all permissions (including inherited)."""
    
    all_permissions: List[str] = Field(default_factory=list)
