"""
Router utilities for FastAPI Roles package.
"""

from typing import Any, Callable, List, Optional, Union

from fastapi import APIRouter, Depends
from fastapi.routing import APIRoute

from .auth import AuthManager
from .models import User


class RoleRouter(APIRouter):
    """Extended APIRouter with role-based access control."""
    
    def __init__(
        self,
        auth_manager: Optional[AuthManager] = None,
        required_roles: Optional[Union[str, List[str]]] = None,
        required_permissions: Optional[Union[str, List[str]]] = None,
        require_active: bool = True,
        require_verified: bool = False,
        require_superuser: bool = False,
        **kwargs
    ):
        """
        Initialize the role router.
        
        Args:
            auth_manager: AuthManager instance
            required_roles: Default roles required for all routes in this router
            required_permissions: Default permissions required for all routes in this router
            require_active: Require users to be active
            require_verified: Require users to be verified
            require_superuser: Require users to be superusers
            **kwargs: Additional arguments passed to APIRouter
        """
        super().__init__(**kwargs)
        self.auth_manager = auth_manager
        self.required_roles = self._normalize_list(required_roles)
        self.required_permissions = self._normalize_list(required_permissions)
        self.require_active = require_active
        self.require_verified = require_verified
        self.require_superuser = require_superuser
    
    def _normalize_list(self, value: Optional[Union[str, List[str]]]) -> List[str]:
        """Normalize string or list to list."""
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return value
    
    def _create_dependency(
        self,
        roles: Optional[List[str]] = None,
        permissions: Optional[List[str]] = None,
        active_only: Optional[bool] = None,
        verified_only: Optional[bool] = None,
        superuser_only: Optional[bool] = None
    ) -> Callable:
        """Create a dependency function with the specified requirements."""
        # Use router defaults if not specified
        roles = roles or self.required_roles
        permissions = permissions or self.required_permissions
        active_only = active_only if active_only is not None else self.require_active
        verified_only = verified_only if verified_only is not None else self.require_verified
        superuser_only = superuser_only if superuser_only is not None else self.require_superuser
        
        if not self.auth_manager:
            # Return a simple dependency that expects user to be injected
            async def simple_dependency(current_user: User = Depends(lambda: None)) -> User:
                return current_user
            return simple_dependency
        
        # Create appropriate dependency based on requirements
        if superuser_only:
            return self.auth_manager.create_superuser_dependency()
        elif permissions:
            return self.auth_manager.create_permission_dependency(permissions)
        elif roles:
            return self.auth_manager.create_role_dependency(roles)
        elif verified_only:
            dependency = self.auth_manager.create_active_user_dependency()
            
            async def verified_dependency(current_user: User = Depends(dependency)) -> User:
                if not current_user.is_verified:
                    from fastapi import HTTPException, status
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Unverified user"
                    )
                return current_user
            return verified_dependency
        elif active_only:
            return self.auth_manager.create_active_user_dependency()
        else:
            return self.auth_manager.create_dependency(require_auth=True)
    
    def add_api_route(
        self,
        path: str,
        endpoint: Callable,
        *,
        roles: Optional[Union[str, List[str]]] = None,
        permissions: Optional[Union[str, List[str]]] = None,
        require_active: Optional[bool] = None,
        require_verified: Optional[bool] = None,
        require_superuser: Optional[bool] = None,
        **kwargs
    ) -> None:
        """
        Add an API route with role-based access control.
        
        Args:
            path: URL path for the route
            endpoint: Endpoint function
            roles: Required roles for this specific route
            permissions: Required permissions for this specific route
            require_active: Require active user for this route
            require_verified: Require verified user for this route
            require_superuser: Require superuser for this route
            **kwargs: Additional arguments passed to APIRouter.add_api_route
        """
        # Normalize role and permission inputs
        roles = self._normalize_list(roles)
        permissions = self._normalize_list(permissions)
        
        # Create dependency for this route
        dependency = self._create_dependency(
            roles=roles,
            permissions=permissions,
            active_only=require_active,
            verified_only=require_verified,
            superuser_only=require_superuser
        )
        
        # Add the dependency to the route
        if 'dependencies' not in kwargs:
            kwargs['dependencies'] = []
        kwargs['dependencies'].append(Depends(dependency))
        
        # Call parent method
        super().add_api_route(path, endpoint, **kwargs)
    
    def get(
        self,
        path: str,
        *,
        roles: Optional[Union[str, List[str]]] = None,
        permissions: Optional[Union[str, List[str]]] = None,
        require_active: Optional[bool] = None,
        require_verified: Optional[bool] = None,
        require_superuser: Optional[bool] = None,
        **kwargs
    ):
        """Add a GET route with role-based access control."""
        def decorator(func: Callable) -> Callable:
            self.add_api_route(
                path,
                func,
                methods=["GET"],
                roles=roles,
                permissions=permissions,
                require_active=require_active,
                require_verified=require_verified,
                require_superuser=require_superuser,
                **kwargs
            )
            return func
        return decorator
    
    def post(
        self,
        path: str,
        *,
        roles: Optional[Union[str, List[str]]] = None,
        permissions: Optional[Union[str, List[str]]] = None,
        require_active: Optional[bool] = None,
        require_verified: Optional[bool] = None,
        require_superuser: Optional[bool] = None,
        **kwargs
    ):
        """Add a POST route with role-based access control."""
        def decorator(func: Callable) -> Callable:
            self.add_api_route(
                path,
                func,
                methods=["POST"],
                roles=roles,
                permissions=permissions,
                require_active=require_active,
                require_verified=require_verified,
                require_superuser=require_superuser,
                **kwargs
            )
            return func
        return decorator
    
    def put(
        self,
        path: str,
        *,
        roles: Optional[Union[str, List[str]]] = None,
        permissions: Optional[Union[str, List[str]]] = None,
        require_active: Optional[bool] = None,
        require_verified: Optional[bool] = None,
        require_superuser: Optional[bool] = None,
        **kwargs
    ):
        """Add a PUT route with role-based access control."""
        def decorator(func: Callable) -> Callable:
            self.add_api_route(
                path,
                func,
                methods=["PUT"],
                roles=roles,
                permissions=permissions,
                require_active=require_active,
                require_verified=require_verified,
                require_superuser=require_superuser,
                **kwargs
            )
            return func
        return decorator
    
    def patch(
        self,
        path: str,
        *,
        roles: Optional[Union[str, List[str]]] = None,
        permissions: Optional[Union[str, List[str]]] = None,
        require_active: Optional[bool] = None,
        require_verified: Optional[bool] = None,
        require_superuser: Optional[bool] = None,
        **kwargs
    ):
        """Add a PATCH route with role-based access control."""
        def decorator(func: Callable) -> Callable:
            self.add_api_route(
                path,
                func,
                methods=["PATCH"],
                roles=roles,
                permissions=permissions,
                require_active=require_active,
                require_verified=require_verified,
                require_superuser=require_superuser,
                **kwargs
            )
            return func
        return decorator
    
    def delete(
        self,
        path: str,
        *,
        roles: Optional[Union[str, List[str]]] = None,
        permissions: Optional[Union[str, List[str]]] = None,
        require_active: Optional[bool] = None,
        require_verified: Optional[bool] = None,
        require_superuser: Optional[bool] = None,
        **kwargs
    ):
        """Add a DELETE route with role-based access control."""
        def decorator(func: Callable) -> Callable:
            self.add_api_route(
                path,
                func,
                methods=["DELETE"],
                roles=roles,
                permissions=permissions,
                require_active=require_active,
                require_verified=require_verified,
                require_superuser=require_superuser,
                **kwargs
            )
            return func
        return decorator


class AdminRouter(RoleRouter):
    """Router that requires admin role by default."""
    
    def __init__(self, auth_manager: Optional[AuthManager] = None, **kwargs):
        super().__init__(
            auth_manager=auth_manager,
            required_roles=["admin"],
            **kwargs
        )


class ModeratorRouter(RoleRouter):
    """Router that requires moderator role by default."""
    
    def __init__(self, auth_manager: Optional[AuthManager] = None, **kwargs):
        super().__init__(
            auth_manager=auth_manager,
            required_roles=["moderator"],
            **kwargs
        )


class StaffRouter(RoleRouter):
    """Router that requires staff role by default."""
    
    def __init__(self, auth_manager: Optional[AuthManager] = None, **kwargs):
        super().__init__(
            auth_manager=auth_manager,
            required_roles=["staff"],
            **kwargs
        )


class SuperuserRouter(RoleRouter):
    """Router that requires superuser by default."""
    
    def __init__(self, auth_manager: Optional[AuthManager] = None, **kwargs):
        super().__init__(
            auth_manager=auth_manager,
            require_superuser=True,
            **kwargs
        )


class VerifiedRouter(RoleRouter):
    """Router that requires verified users by default."""
    
    def __init__(self, auth_manager: Optional[AuthManager] = None, **kwargs):
        super().__init__(
            auth_manager=auth_manager,
            require_verified=True,
            **kwargs
        )


# Utility functions for creating routers
def create_role_router(
    auth_manager: AuthManager,
    roles: Union[str, List[str]],
    **kwargs
) -> RoleRouter:
    """Create a router that requires specific roles."""
    return RoleRouter(
        auth_manager=auth_manager,
        required_roles=roles,
        **kwargs
    )


def create_permission_router(
    auth_manager: AuthManager,
    permissions: Union[str, List[str]],
    **kwargs
) -> RoleRouter:
    """Create a router that requires specific permissions."""
    return RoleRouter(
        auth_manager=auth_manager,
        required_permissions=permissions,
        **kwargs
    )


def create_admin_router(auth_manager: AuthManager, **kwargs) -> AdminRouter:
    """Create an admin router."""
    return AdminRouter(auth_manager=auth_manager, **kwargs)


def create_moderator_router(auth_manager: AuthManager, **kwargs) -> ModeratorRouter:
    """Create a moderator router."""
    return ModeratorRouter(auth_manager=auth_manager, **kwargs)


def create_staff_router(auth_manager: AuthManager, **kwargs) -> StaffRouter:
    """Create a staff router."""
    return StaffRouter(auth_manager=auth_manager, **kwargs)


def create_superuser_router(auth_manager: AuthManager, **kwargs) -> SuperuserRouter:
    """Create a superuser router."""
    return SuperuserRouter(auth_manager=auth_manager, **kwargs)


def create_verified_router(auth_manager: AuthManager, **kwargs) -> VerifiedRouter:
    """Create a verified users router."""
    return VerifiedRouter(auth_manager=auth_manager, **kwargs)
