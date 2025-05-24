"""
Pydantic schemas for FastAPI Roles package.
"""

from .token import TokenData
from .auth import (
    LoginRequest,
    LoginResponse,
    RefreshTokenRequest,
    PasswordResetRequest,
    PasswordResetConfirm,
    ChangePasswordRequest,
    AuthConfig,
)
from .permission import (
    PermissionBase,
    PermissionCreate,
    PermissionUpdate,
    PermissionInDB,
    PermissionResponse,
)
from .role import (
    RoleBase,
    RoleCreate,
    RoleUpdate,
    RoleInDB,
    RoleResponse,
    RoleWithPermissions,
)
from .user import (
    UserBase,
    UserCreate,
    UserUpdate,
    UserInDB,
    UserResponse,
    UserWithPermissions,
)
from .associations import (
    UserRoleAssignment,
    RolePermissionAssignment,
    UserRoleResponse,
    RolePermissionResponse,
)

__all__ = [
    # Token
    "TokenData",
    
    # User schemas
    "UserBase",
    "UserCreate",
    "UserUpdate",
    "UserInDB",
    "UserResponse",
    "UserWithPermissions",
    
    # Role schemas
    "RoleBase",
    "RoleCreate",
    "RoleUpdate",
    "RoleInDB",
    "RoleResponse",
    "RoleWithPermissions",
    
    # Permission schemas
    "PermissionBase",
    "PermissionCreate",
    "PermissionUpdate",
    "PermissionInDB",
    "PermissionResponse",
    
    # Association schemas
    "UserRoleAssignment",
    "RolePermissionAssignment",
    "UserRoleResponse",
    "RolePermissionResponse",
    
    # Authentication schemas
    "LoginRequest",
    "LoginResponse",
    "RefreshTokenRequest",
    "PasswordResetRequest",
    "PasswordResetConfirm",
    "ChangePasswordRequest",
    "AuthConfig",
]

# Rebuild models to resolve forward references
# This must be done after all imports to ensure all classes are available
UserResponse.model_rebuild()
RoleResponse.model_rebuild()
UserRoleResponse.model_rebuild()
RolePermissionResponse.model_rebuild()
