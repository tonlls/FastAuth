"""
Middleware for FastAPI Roles package.
"""

from typing import Callable, Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from .auth import AuthManager
from .models import User


class RoleMiddleware(BaseHTTPMiddleware):
    """Middleware to automatically inject user information into requests."""
    
    def __init__(
        self,
        app,
        auth_manager: AuthManager,
        auto_inject: bool = True,
        user_attribute: str = "user"
    ):
        """
        Initialize the role middleware.
        
        Args:
            app: FastAPI application instance
            auth_manager: AuthManager instance
            auto_inject: Whether to automatically inject user into request state
            user_attribute: Attribute name to store user in request state
        """
        super().__init__(app)
        self.auth_manager = auth_manager
        self.auto_inject = auto_inject
        self.user_attribute = user_attribute
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process the request and inject user information."""
        user = None
        
        if self.auto_inject:
            try:
                # Get current user using auth manager
                user = await self.auth_manager.get_current_user(request)
            except Exception:
                # If authentication fails, continue without user
                pass
        
        # Store user in request state
        setattr(request.state, self.user_attribute, user)
        
        # Continue processing the request
        response = await call_next(request)
        
        return response


class RequireRoleMiddleware(BaseHTTPMiddleware):
    """Middleware to require specific roles for all routes."""
    
    def __init__(
        self,
        app,
        auth_manager: AuthManager,
        required_roles: list[str],
        exclude_paths: Optional[list[str]] = None,
        include_paths: Optional[list[str]] = None
    ):
        """
        Initialize the require role middleware.
        
        Args:
            app: FastAPI application instance
            auth_manager: AuthManager instance
            required_roles: List of required roles
            exclude_paths: Paths to exclude from role checking
            include_paths: Paths to include in role checking (if specified, only these paths are checked)
        """
        super().__init__(app)
        self.auth_manager = auth_manager
        self.required_roles = required_roles
        self.exclude_paths = exclude_paths or []
        self.include_paths = include_paths
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process the request and check roles."""
        path = request.url.path
        
        # Check if path should be excluded
        if self.exclude_paths and any(path.startswith(excluded) for excluded in self.exclude_paths):
            return await call_next(request)
        
        # Check if path should be included (if include_paths is specified)
        if self.include_paths and not any(path.startswith(included) for included in self.include_paths):
            return await call_next(request)
        
        # Get current user
        try:
            user = await self.auth_manager.get_current_user(request)
        except Exception:
            user = None
        
        if not user:
            return Response(
                content="Authentication required",
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        if not user.is_active:
            return Response(
                content="Inactive user",
                status_code=400
            )
        
        # Check roles (superuser bypasses)
        if not user.is_superuser:
            user_roles = [role.name for role in user.roles]
            if not any(role in user_roles for role in self.required_roles):
                return Response(
                    content=f"Required roles: {', '.join(self.required_roles)}",
                    status_code=403
                )
        
        return await call_next(request)


class RequirePermissionMiddleware(BaseHTTPMiddleware):
    """Middleware to require specific permissions for all routes."""
    
    def __init__(
        self,
        app,
        auth_manager: AuthManager,
        required_permissions: list[str],
        exclude_paths: Optional[list[str]] = None,
        include_paths: Optional[list[str]] = None
    ):
        """
        Initialize the require permission middleware.
        
        Args:
            app: FastAPI application instance
            auth_manager: AuthManager instance
            required_permissions: List of required permissions
            exclude_paths: Paths to exclude from permission checking
            include_paths: Paths to include in permission checking (if specified, only these paths are checked)
        """
        super().__init__(app)
        self.auth_manager = auth_manager
        self.required_permissions = required_permissions
        self.exclude_paths = exclude_paths or []
        self.include_paths = include_paths
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process the request and check permissions."""
        path = request.url.path
        
        # Check if path should be excluded
        if self.exclude_paths and any(path.startswith(excluded) for excluded in self.exclude_paths):
            return await call_next(request)
        
        # Check if path should be included (if include_paths is specified)
        if self.include_paths and not any(path.startswith(included) for included in self.include_paths):
            return await call_next(request)
        
        # Get current user
        try:
            user = await self.auth_manager.get_current_user(request)
        except Exception:
            user = None
        
        if not user:
            return Response(
                content="Authentication required",
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        if not user.is_active:
            return Response(
                content="Inactive user",
                status_code=400
            )
        
        # Check permissions (superuser bypasses)
        if not user.is_superuser:
            user_permissions = user.get_permissions()
            if not any(perm in user_permissions for perm in self.required_permissions):
                return Response(
                    content=f"Required permissions: {', '.join(self.required_permissions)}",
                    status_code=403
                )
        
        return await call_next(request)


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """Middleware to require authentication for all routes."""
    
    def __init__(
        self,
        app,
        auth_manager: AuthManager,
        exclude_paths: Optional[list[str]] = None,
        include_paths: Optional[list[str]] = None,
        require_active: bool = True,
        require_verified: bool = False
    ):
        """
        Initialize the authentication middleware.
        
        Args:
            app: FastAPI application instance
            auth_manager: AuthManager instance
            exclude_paths: Paths to exclude from authentication
            include_paths: Paths to include in authentication (if specified, only these paths are checked)
            require_active: Require user to be active
            require_verified: Require user to be verified
        """
        super().__init__(app)
        self.auth_manager = auth_manager
        self.exclude_paths = exclude_paths or []
        self.include_paths = include_paths
        self.require_active = require_active
        self.require_verified = require_verified
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process the request and check authentication."""
        path = request.url.path
        
        # Check if path should be excluded
        if self.exclude_paths and any(path.startswith(excluded) for excluded in self.exclude_paths):
            return await call_next(request)
        
        # Check if path should be included (if include_paths is specified)
        if self.include_paths and not any(path.startswith(included) for included in self.include_paths):
            return await call_next(request)
        
        # Get current user
        try:
            user = await self.auth_manager.get_current_user(request)
        except Exception:
            user = None
        
        if not user:
            return Response(
                content="Authentication required",
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        # Check if user is active (if required)
        if self.require_active and not user.is_active:
            return Response(
                content="Inactive user",
                status_code=400
            )
        
        # Check if user is verified (if required)
        if self.require_verified and not user.is_verified:
            return Response(
                content="Unverified user",
                status_code=400
            )
        
        return await call_next(request)


class CORSRoleMiddleware(BaseHTTPMiddleware):
    """Middleware to handle CORS with role-based restrictions."""
    
    def __init__(
        self,
        app,
        auth_manager: AuthManager,
        allowed_origins: list[str] = None,
        role_based_origins: dict[str, list[str]] = None,
        allow_credentials: bool = True,
        allowed_methods: list[str] = None,
        allowed_headers: list[str] = None
    ):
        """
        Initialize the CORS role middleware.
        
        Args:
            app: FastAPI application instance
            auth_manager: AuthManager instance
            allowed_origins: Default allowed origins
            role_based_origins: Dict mapping roles to allowed origins
            allow_credentials: Whether to allow credentials
            allowed_methods: Allowed HTTP methods
            allowed_headers: Allowed headers
        """
        super().__init__(app)
        self.auth_manager = auth_manager
        self.allowed_origins = allowed_origins or ["*"]
        self.role_based_origins = role_based_origins or {}
        self.allow_credentials = allow_credentials
        self.allowed_methods = allowed_methods or ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
        self.allowed_headers = allowed_headers or ["*"]
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process the request and handle CORS with role-based restrictions."""
        origin = request.headers.get("origin")
        
        # Handle preflight requests
        if request.method == "OPTIONS":
            response = Response()
        else:
            response = await call_next(request)
        
        # Get current user for role-based CORS
        user = None
        try:
            user = await self.auth_manager.get_current_user(request)
        except Exception:
            pass
        
        # Determine allowed origins based on user roles
        allowed_origins = self.allowed_origins.copy()
        
        if user and user.is_active:
            user_roles = [role.name for role in user.roles]
            for role in user_roles:
                if role in self.role_based_origins:
                    allowed_origins.extend(self.role_based_origins[role])
        
        # Set CORS headers
        if origin and (origin in allowed_origins or "*" in allowed_origins):
            response.headers["Access-Control-Allow-Origin"] = origin
        
        if self.allow_credentials:
            response.headers["Access-Control-Allow-Credentials"] = "true"
        
        response.headers["Access-Control-Allow-Methods"] = ", ".join(self.allowed_methods)
        response.headers["Access-Control-Allow-Headers"] = ", ".join(self.allowed_headers)
        
        return response


# Utility functions for easy middleware setup
def setup_role_middleware(
    app,
    auth_manager: AuthManager,
    auto_inject: bool = True,
    user_attribute: str = "user"
):
    """Setup basic role middleware."""
    app.add_middleware(
        RoleMiddleware,
        auth_manager=auth_manager,
        auto_inject=auto_inject,
        user_attribute=user_attribute
    )


def setup_authentication_middleware(
    app,
    auth_manager: AuthManager,
    exclude_paths: Optional[list[str]] = None,
    require_active: bool = True,
    require_verified: bool = False
):
    """Setup authentication middleware."""
    app.add_middleware(
        AuthenticationMiddleware,
        auth_manager=auth_manager,
        exclude_paths=exclude_paths,
        require_active=require_active,
        require_verified=require_verified
    )


def setup_role_requirement_middleware(
    app,
    auth_manager: AuthManager,
    required_roles: list[str],
    exclude_paths: Optional[list[str]] = None
):
    """Setup role requirement middleware."""
    app.add_middleware(
        RequireRoleMiddleware,
        auth_manager=auth_manager,
        required_roles=required_roles,
        exclude_paths=exclude_paths
    )


def setup_permission_requirement_middleware(
    app,
    auth_manager: AuthManager,
    required_permissions: list[str],
    exclude_paths: Optional[list[str]] = None
):
    """Setup permission requirement middleware."""
    app.add_middleware(
        RequirePermissionMiddleware,
        auth_manager=auth_manager,
        required_permissions=required_permissions,
        exclude_paths=exclude_paths
    )
