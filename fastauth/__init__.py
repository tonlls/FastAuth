"""
FastAPI Roles - A comprehensive role-based access control package for FastAPI.

This package provides:
- User, Role, and Permission management
- Router access control by role, user, and permission
- Compatibility with Auth0, Firebase, and other auth providers
- Support for JWT, custom tokens, and other token standards
- Dynamic user model and token content information
"""

from .auth import AuthManager, TokenValidator
from .database import (
    Base,
    DatabaseConfig,
    DatabaseManager,
    GUID,
    JSON,
    create_database_manager,
    get_database_url_from_env,
    sqlite_url,
    postgresql_url,
    mysql_url,
    oracle_url,
)
from .decorators import require_role, require_permission, require_user, admin_required
from .endpoints import UserManagementRouter, create_user_management_router
from .middleware import RoleMiddleware, setup_role_middleware
from .models import User, Role, Permission, UserRole, RolePermission
from .providers import Auth0Provider, FirebaseProvider, JWTProvider
from .router import RoleRouter
from .schemas import (
    UserCreate,
    UserUpdate,
    UserResponse,
    RoleCreate,
    RoleUpdate,
    PermissionCreate,
    PermissionUpdate,
    TokenData,
    AuthConfig,
    LoginRequest,
    LoginResponse,
    RefreshTokenRequest,
    PasswordResetRequest,
    PasswordResetConfirm,
    ChangePasswordRequest,
)

__version__ = "0.1.0"
__all__ = [
    # Core components
    "AuthManager",
    "TokenValidator",
    
    # Database components
    "Base",
    "DatabaseConfig",
    "DatabaseManager",
    "GUID",
    "JSON",
    "create_database_manager",
    "get_database_url_from_env",
    "sqlite_url",
    "postgresql_url",
    "mysql_url",
    "oracle_url",
    
    # Decorators
    "require_role",
    "require_permission",
    "require_user",
    "admin_required",
    
    # Endpoints
    "UserManagementRouter",
    "create_user_management_router",
    
    # Middleware
    "RoleMiddleware",
    "setup_role_middleware",
    
    # Models
    "User",
    "Role",
    "Permission",
    "UserRole",
    "RolePermission",
    
    # Providers
    "Auth0Provider",
    "FirebaseProvider",
    "JWTProvider",
    
    # Router
    "RoleRouter",
    
    # Schemas
    "UserCreate",
    "UserUpdate",
    "UserResponse",
    "RoleCreate",
    "RoleUpdate",
    "PermissionCreate",
    "PermissionUpdate",
    "TokenData",
    "AuthConfig",
    "LoginRequest",
    "LoginResponse",
    "RefreshTokenRequest",
    "PasswordResetRequest",
    "PasswordResetConfirm",
    "ChangePasswordRequest",
]
