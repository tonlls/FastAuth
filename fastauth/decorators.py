"""
Decorators for FastAPI Roles package.
"""

from functools import wraps
from typing import Any, Awaitable, Callable, List, Optional, TypeVar, Union

from fastapi import Depends, HTTPException, status

from .auth import AuthManager
from .models import User

F = TypeVar('F', bound=Callable[..., Awaitable[Any]])


def require_role(
    roles: Union[str, List[str]],
    auth_manager: Optional[AuthManager] = None
) -> Callable:
    """
    Decorator to require specific roles for a route.
    
    Args:
        roles: Required role(s) - can be a string or list of strings
        auth_manager: AuthManager instance (if not provided, will be injected)
    
    Usage:
        @require_role("admin")
        async def admin_only_route():
            pass
        
        @require_role(["admin", "moderator"])
        async def admin_or_moderator_route():
            pass
    """
    if isinstance(roles, str):
        roles = [roles]
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get current user from dependency injection
            current_user = None
            for key, value in kwargs.items():
                if isinstance(value, User):
                    current_user = value
                    break
            
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            # Check if user is active
            if not current_user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Inactive user"
                )
            
            # Superuser bypasses role checks
            if current_user.is_superuser:
                return await func(*args, **kwargs)
            
            # Check roles
            user_roles = [role.name for role in current_user.roles]
            if not any(role in user_roles for role in roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Required roles: {', '.join(roles)}"
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_permission(
    permissions: Union[str, List[str]],
    auth_manager: Optional[AuthManager] = None
) -> Callable:
    """
    Decorator to require specific permissions for a route.
    
    Args:
        permissions: Required permission(s) - can be a string or list of strings
        auth_manager: AuthManager instance (if not provided, will be injected)
    
    Usage:
        @require_permission("users:read")
        async def read_users_route():
            pass
        
        @require_permission(["users:write", "users:delete"])
        async def modify_users_route():
            pass
    """
    if isinstance(permissions, str):
        permissions = [permissions]
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get current user from dependency injection
            current_user = None
            for key, value in kwargs.items():
                if isinstance(value, User):
                    current_user = value
                    break
            
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            # Check if user is active
            if not current_user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Inactive user"
                )
            
            # Superuser bypasses permission checks
            if current_user.is_superuser:
                return await func(*args, **kwargs)
            
            # Check permissions
            user_permissions = current_user.get_permissions()
            if not any(perm in user_permissions for perm in permissions):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Required permissions: {', '.join(permissions)}"
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_user(
    active_only: bool = True,
    verified_only: bool = False,
    auth_manager: Optional[AuthManager] = None
) -> Callable:
    """
    Decorator to require authenticated user for a route.
    
    Args:
        active_only: Require user to be active (default: True)
        verified_only: Require user to be verified (default: False)
        auth_manager: AuthManager instance (if not provided, will be injected)
    
    Usage:
        @require_user()
        async def authenticated_route():
            pass
        
        @require_user(verified_only=True)
        async def verified_users_only():
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get current user from dependency injection
            current_user = None
            for key, value in kwargs.items():
                if isinstance(value, User):
                    current_user = value
                    break
            
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            # Check if user is active (if required)
            if active_only and not current_user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Inactive user"
                )
            
            # Check if user is verified (if required)
            if verified_only and not current_user.is_verified:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Unverified user"
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_superuser(auth_manager: Optional[AuthManager] = None) -> Callable:
    """
    Decorator to require superuser for a route.
    
    Args:
        auth_manager: AuthManager instance (if not provided, will be injected)
    
    Usage:
        @require_superuser()
        async def superuser_only_route():
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get current user from dependency injection
            current_user = None
            for key, value in kwargs.items():
                if isinstance(value, User):
                    current_user = value
                    break
            
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            # Check if user is active
            if not current_user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Inactive user"
                )
            
            # Check if user is superuser
            if not current_user.is_superuser:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Superuser access required"
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_any_role(
    roles: List[str],
    auth_manager: Optional[AuthManager] = None
) -> Callable:
    """
    Decorator to require any of the specified roles for a route.
    This is an alias for require_role with multiple roles.
    
    Args:
        roles: List of roles (user needs any one of them)
        auth_manager: AuthManager instance (if not provided, will be injected)
    
    Usage:
        @require_any_role(["admin", "moderator", "editor"])
        async def privileged_route():
            pass
    """
    return require_role(roles, auth_manager)


def require_all_roles(
    roles: List[str],
    auth_manager: Optional[AuthManager] = None
) -> Callable:
    """
    Decorator to require all of the specified roles for a route.
    
    Args:
        roles: List of roles (user needs all of them)
        auth_manager: AuthManager instance (if not provided, will be injected)
    
    Usage:
        @require_all_roles(["admin", "security_officer"])
        async def high_security_route():
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get current user from dependency injection
            current_user = None
            for key, value in kwargs.items():
                if isinstance(value, User):
                    current_user = value
                    break
            
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            # Check if user is active
            if not current_user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Inactive user"
                )
            
            # Superuser bypasses role checks
            if current_user.is_superuser:
                return await func(*args, **kwargs)
            
            # Check that user has ALL required roles
            user_roles = [role.name for role in current_user.roles]
            missing_roles = [role for role in roles if role not in user_roles]
            
            if missing_roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing required roles: {', '.join(missing_roles)}"
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_any_permission(
    permissions: List[str],
    auth_manager: Optional[AuthManager] = None
) -> Callable:
    """
    Decorator to require any of the specified permissions for a route.
    This is an alias for require_permission with multiple permissions.
    
    Args:
        permissions: List of permissions (user needs any one of them)
        auth_manager: AuthManager instance (if not provided, will be injected)
    
    Usage:
        @require_any_permission(["users:read", "users:write"])
        async def user_access_route():
            pass
    """
    return require_permission(permissions, auth_manager)


def require_all_permissions(
    permissions: List[str],
    auth_manager: Optional[AuthManager] = None
) -> Callable:
    """
    Decorator to require all of the specified permissions for a route.
    
    Args:
        permissions: List of permissions (user needs all of them)
        auth_manager: AuthManager instance (if not provided, will be injected)
    
    Usage:
        @require_all_permissions(["users:read", "users:write", "users:delete"])
        async def full_user_management_route():
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get current user from dependency injection
            current_user = None
            for key, value in kwargs.items():
                if isinstance(value, User):
                    current_user = value
                    break
            
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            # Check if user is active
            if not current_user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Inactive user"
                )
            
            # Superuser bypasses permission checks
            if current_user.is_superuser:
                return await func(*args, **kwargs)
            
            # Check that user has ALL required permissions
            user_permissions = current_user.get_permissions()
            missing_permissions = [perm for perm in permissions if perm not in user_permissions]
            
            if missing_permissions:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing required permissions: {', '.join(missing_permissions)}"
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


# Convenience decorators for common patterns
def admin_required(auth_manager: Optional[AuthManager] = None) -> Callable:
    """Decorator to require admin role."""
    return require_role("admin", auth_manager)


def moderator_required(auth_manager: Optional[AuthManager] = None) -> Callable:
    """Decorator to require moderator role."""
    return require_role("moderator", auth_manager)


def staff_required(auth_manager: Optional[AuthManager] = None) -> Callable:
    """Decorator to require staff role."""
    return require_role("staff", auth_manager)


def verified_required(auth_manager: Optional[AuthManager] = None) -> Callable:
    """Decorator to require verified user."""
    return require_user(verified_only=True, auth_manager=auth_manager)
