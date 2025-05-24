"""
Association schemas.
"""

from datetime import datetime
from typing import Any, Dict, Optional, TYPE_CHECKING
from uuid import UUID

from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    from .user import UserResponse
    from .role import RoleResponse
    from .permission import PermissionResponse


class UserRoleAssignment(BaseModel):
    """User role assignment schema."""
    
    user_id: UUID
    role_id: UUID
    expires_at: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None


class RolePermissionAssignment(BaseModel):
    """Role permission assignment schema."""
    
    role_id: UUID
    permission_id: UUID
    metadata: Optional[Dict[str, Any]] = None


class UserRoleResponse(BaseModel):
    """User role assignment response."""
    
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    user_id: UUID
    role_id: UUID
    granted_at: datetime
    granted_by: Optional[UUID] = None
    expires_at: Optional[datetime] = None
    is_active: bool = True
    metadata: Optional[Dict[str, Any]] = None
    user: Optional["UserResponse"] = None
    role: Optional["RoleResponse"] = None


class RolePermissionResponse(BaseModel):
    """Role permission assignment response."""
    
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    role_id: UUID
    permission_id: UUID
    granted_at: datetime
    granted_by: Optional[UUID] = None
    is_active: bool = True
    metadata: Optional[Dict[str, Any]] = None
    role: Optional["RoleResponse"] = None
    permission: Optional["PermissionResponse"] = None
