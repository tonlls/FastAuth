"""
User management endpoints for FastAPI Roles.

This module provides ready-to-use authentication and user management endpoints
that can be easily integrated into any FastAPI application.
"""

from datetime import timedelta
from typing import Any, Dict, List, Optional, Union, Sequence, cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .auth import AuthManager
from .models import User, Role
from .schemas import (
    LoginRequest,
    LoginResponse,
    RefreshTokenRequest,
    PasswordResetRequest,
    PasswordResetConfirm,
    ChangePasswordRequest,
    UserCreate,
    UserUpdate,
    UserResponse,
)
from .providers import JWTProvider


class UserManagementRouter:
    """
    User management router with customizable endpoints.
    
    This class provides all the essential user management endpoints including:
    - User registration
    - Login/logout
    - Password management
    - User profile management
    - Admin user management
    
    Users can customize behavior by subclassing or by providing custom handlers.
    """
    
    def __init__(
        self,
        auth_manager: AuthManager,
        get_db: Any,
        prefix: str = "/auth",
        tags: Optional[Sequence[str]] = None,
        enable_registration: bool = True,
        enable_password_reset: bool = True,
        require_email_verification: bool = False,
        default_user_role: str = "user",
    ):
        """
        Initialize the user management router.
        
        Args:
            auth_manager: AuthManager instance
            get_db: Database dependency function
            prefix: URL prefix for all endpoints
            tags: OpenAPI tags for the endpoints
            enable_registration: Whether to enable user registration
            enable_password_reset: Whether to enable password reset
            require_email_verification: Whether to require email verification
            default_user_role: Default role for new users
        """
        self.auth_manager = auth_manager
        self.get_db = get_db
        self.enable_registration = enable_registration
        self.enable_password_reset = enable_password_reset
        self.require_email_verification = require_email_verification
        self.default_user_role = default_user_role
        
        # Create router
        self.router = APIRouter(
            prefix=prefix,
            tags=cast(List[str], tags or ["Authentication"])
        )
        
        # Get JWT provider for password operations
        self.jwt_provider: JWTProvider
        jwt_provider_found = None
        for provider in auth_manager.providers:
            if isinstance(provider, JWTProvider):
                jwt_provider_found = provider
                break
        
        if not jwt_provider_found:
            raise ValueError("JWT provider is required for user management endpoints")
        
        self.jwt_provider = jwt_provider_found
        
        # Register endpoints
        self._register_endpoints()
    
    def _register_endpoints(self):
        """Register all endpoints."""
        # Authentication endpoints
        self.router.add_api_route(
            "/login",
            self.login,
            methods=["POST"],
            response_model=LoginResponse,
            summary="User login",
            description="Authenticate user with email/username and password"
        )
        
        if self.enable_registration:
            self.router.add_api_route(
                "/register",
                self.register,
                methods=["POST"],
                response_model=UserResponse,
                summary="User registration",
                description="Register a new user account"
            )
        
        # Token management
        self.router.add_api_route(
            "/refresh",
            self.refresh_token,
            methods=["POST"],
            response_model=LoginResponse,
            summary="Refresh access token",
            description="Refresh access token using refresh token"
        )
        
        # User profile endpoints
        self.router.add_api_route(
            "/me",
            self.get_current_user_profile,
            methods=["GET"],
            response_model=UserResponse,
            summary="Get current user profile",
            description="Get the current authenticated user's profile"
        )
        
        self.router.add_api_route(
            "/me",
            self.update_current_user_profile,
            methods=["PUT"],
            response_model=UserResponse,
            summary="Update current user profile",
            description="Update the current authenticated user's profile"
        )
        
        # Password management
        self.router.add_api_route(
            "/change-password",
            self.change_password,
            methods=["POST"],
            summary="Change password",
            description="Change the current user's password"
        )
        
        if self.enable_password_reset:
            self.router.add_api_route(
                "/reset-password",
                self.request_password_reset,
                methods=["POST"],
                summary="Request password reset",
                description="Request a password reset email"
            )
            
            self.router.add_api_route(
                "/reset-password/confirm",
                self.confirm_password_reset,
                methods=["POST"],
                summary="Confirm password reset",
                description="Confirm password reset with token"
            )
        
        # Admin endpoints
        self.router.add_api_route(
            "/users",
            self.list_users,
            methods=["GET"],
            response_model=List[UserResponse],
            summary="List users (Admin)",
            description="List all users (admin only)"
        )
        
        self.router.add_api_route(
            "/users/{user_id}",
            self.get_user,
            methods=["GET"],
            response_model=UserResponse,
            summary="Get user (Admin)",
            description="Get user by ID (admin only)"
        )
        
        self.router.add_api_route(
            "/users/{user_id}",
            self.update_user,
            methods=["PUT"],
            response_model=UserResponse,
            summary="Update user (Admin)",
            description="Update user by ID (admin only)"
        )
        
        self.router.add_api_route(
            "/users/{user_id}",
            self.delete_user,
            methods=["DELETE"],
            summary="Delete user (Admin)",
            description="Delete user by ID (admin only)"
        )
    
    async def login(
        self,
        login_data: LoginRequest,
        db: Session = Depends(lambda: None)
    ) -> LoginResponse:
        """User login endpoint."""
        if db is None:
            db = next(self.get_db())
        
        # Determine login field (email or username)
        if login_data.email:
            user = await self.auth_manager.authenticate_user(
                db, login_data.email, login_data.password
            )
        elif login_data.username:
            # Find user by username first
            user = db.query(User).filter(User.username == login_data.username).first()
            if user and user.hashed_password:
                if not self.jwt_provider.verify_password(login_data.password, user.hashed_password):
                    user = None
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email or username is required"
            )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email/username or password"
            )
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inactive user"
            )
        
        # Create access token
        access_token_expires = timedelta(
            minutes=self.auth_manager.config.access_token_expire_minutes
        )
        access_token = self.auth_manager.create_access_token(
            user, expires_delta=access_token_expires
        )
        
        # Create refresh token (optional)
        refresh_token = None
        if self.auth_manager.config.refresh_token_expire_days > 0:
            refresh_token_expires = timedelta(
                days=self.auth_manager.config.refresh_token_expire_days
            )
            refresh_token = self.auth_manager.create_access_token(
                user, expires_delta=refresh_token_expires
            )
        
        return LoginResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=self.auth_manager.config.access_token_expire_minutes * 60,
            refresh_token=refresh_token,
            user=UserResponse.model_validate(user)
        )
    
    async def register(
        self,
        user_data: UserCreate,
        db: Session = Depends(lambda: None)
    ) -> UserResponse:
        """User registration endpoint."""
        if db is None:
            db = next(self.get_db())
        
        # Check if user already exists
        existing_user = db.query(User).filter(User.email == user_data.email).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        if user_data.username:
            existing_username = db.query(User).filter(User.username == user_data.username).first()
            if existing_username:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username already taken"
                )
        
        # Hash password
        if not user_data.password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password is required for local registration"
            )
        hashed_password = self.jwt_provider.get_password_hash(user_data.password)
        
        # Create user
        user = User(
            email=user_data.email,
            username=user_data.username,
            hashed_password=hashed_password,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            is_verified=not self.require_email_verification,
            auth_provider="local"
        )
        
        db.add(user)
        db.commit()
        db.refresh(user)
        
        # Assign default role
        if self.default_user_role:
            default_role = db.query(Role).filter(Role.name == self.default_user_role).first()
            if default_role:
                user.roles.append(default_role)
                db.commit()
        
        return UserResponse.model_validate(user)
    
    async def refresh_token(
        self,
        refresh_data: RefreshTokenRequest,
        db: Session = Depends(lambda: None)
    ) -> LoginResponse:
        """Refresh access token endpoint."""
        if db is None:
            db = next(self.get_db())
        
        # Validate refresh token
        token_data = await self.auth_manager.token_validator.validate_token(
            refresh_data.refresh_token
        )
        
        if not token_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        # Get user
        user = await self.auth_manager._get_or_create_user(db, token_data)
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        # Create new access token
        access_token_expires = timedelta(
            minutes=self.auth_manager.config.access_token_expire_minutes
        )
        access_token = self.auth_manager.create_access_token(
            user, expires_delta=access_token_expires
        )
        
        return LoginResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=self.auth_manager.config.access_token_expire_minutes * 60,
            refresh_token=refresh_data.refresh_token,  # Keep the same refresh token
            user=UserResponse.model_validate(user)
        )
    
    async def get_current_user_profile(
        self,
        current_user: User = Depends(lambda: None)
    ) -> UserResponse:
        """Get current user profile endpoint."""
        if current_user is None:
            current_user = Depends(self.auth_manager.create_active_user_dependency())
        
        return UserResponse.model_validate(current_user)
    
    async def update_current_user_profile(
        self,
        user_update: UserUpdate,
        current_user: User = Depends(lambda: None),
        db: Session = Depends(lambda: None)
    ) -> UserResponse:
        """Update current user profile endpoint."""
        if current_user is None:
            current_user = Depends(self.auth_manager.create_active_user_dependency())
        if db is None:
            db = next(self.get_db())
        
        # Update user fields
        update_data = user_update.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            if hasattr(current_user, field):
                setattr(current_user, field, value)
        
        db.commit()
        db.refresh(current_user)
        
        return UserResponse.model_validate(current_user)
    
    async def change_password(
        self,
        password_data: ChangePasswordRequest,
        current_user: User = Depends(lambda: None),
        db: Session = Depends(lambda: None)
    ):
        """Change password endpoint."""
        if current_user is None:
            current_user = Depends(self.auth_manager.create_active_user_dependency())
        if db is None:
            db = next(self.get_db())
        
        # Verify current password
        if not current_user.hashed_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User has no password set"
            )
        
        if not self.jwt_provider.verify_password(
            password_data.current_password, current_user.hashed_password
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect current password"
            )
        
        # Update password
        current_user.hashed_password = self.jwt_provider.get_password_hash(
            password_data.new_password
        )
        db.commit()
        
        return {"message": "Password updated successfully"}
    
    async def request_password_reset(
        self,
        reset_data: PasswordResetRequest,
        db: Session = Depends(lambda: None)
    ):
        """Request password reset endpoint."""
        if db is None:
            db = next(self.get_db())
        
        user = db.query(User).filter(User.email == reset_data.email).first()
        
        # Always return success to prevent email enumeration
        if user:
            # TODO: Implement email sending logic
            # For now, just create a reset token and log it
            reset_token_expires = timedelta(
                minutes=self.auth_manager.config.password_reset_expire_minutes
            )
            reset_token = self.auth_manager.create_access_token(
                user, expires_delta=reset_token_expires
            )
            print(f"Password reset token for {user.email}: {reset_token}")
        
        return {"message": "If the email exists, a password reset link has been sent"}
    
    async def confirm_password_reset(
        self,
        reset_data: PasswordResetConfirm,
        db: Session = Depends(lambda: None)
    ):
        """Confirm password reset endpoint."""
        if db is None:
            db = next(self.get_db())
        
        # Validate reset token
        token_data = await self.auth_manager.token_validator.validate_token(reset_data.token)
        
        if not token_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )
        
        # Get user
        user = await self.auth_manager._get_or_create_user(db, token_data)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not found"
            )
        
        # Update password
        user.hashed_password = self.jwt_provider.get_password_hash(reset_data.new_password)
        db.commit()
        
        return {"message": "Password reset successfully"}
    
    # Admin endpoints
    async def list_users(
        self,
        current_user: User = Depends(lambda: None),
        db: Session = Depends(lambda: None)
    ) -> List[UserResponse]:
        """List all users (admin only)."""
        if current_user is None:
            current_user = Depends(self.auth_manager.create_superuser_dependency())
        if db is None:
            db = next(self.get_db())
        
        users = db.query(User).all()
        return [UserResponse.model_validate(user) for user in users]
    
    async def get_user(
        self,
        user_id: str,
        current_user: User = Depends(lambda: None),
        db: Session = Depends(lambda: None)
    ) -> UserResponse:
        """Get user by ID (admin only)."""
        if current_user is None:
            current_user = Depends(self.auth_manager.create_superuser_dependency())
        if db is None:
            db = next(self.get_db())
        
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return UserResponse.model_validate(user)
    
    async def update_user(
        self,
        user_id: str,
        user_update: UserUpdate,
        current_user: User = Depends(lambda: None),
        db: Session = Depends(lambda: None)
    ) -> UserResponse:
        """Update user by ID (admin only)."""
        if current_user is None:
            current_user = Depends(self.auth_manager.create_superuser_dependency())
        if db is None:
            db = next(self.get_db())
        
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Update user fields
        update_data = user_update.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            if hasattr(user, field):
                setattr(user, field, value)
        
        db.commit()
        db.refresh(user)
        
        return UserResponse.model_validate(user)
    
    async def delete_user(
        self,
        user_id: str,
        current_user: User = Depends(lambda: None),
        db: Session = Depends(lambda: None)
    ):
        """Delete user by ID (admin only)."""
        if current_user is None:
            current_user = Depends(self.auth_manager.create_superuser_dependency())
        if db is None:
            db = next(self.get_db())
        
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Prevent self-deletion
        if user.id == current_user.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete your own account"
            )
        
        db.delete(user)
        db.commit()
        
        return {"message": "User deleted successfully"}


def create_user_management_router(
    auth_manager: AuthManager,
    get_db: Any,
    **kwargs
) -> APIRouter:
    """
    Create a user management router with default settings.
    
    This is a convenience function for quickly setting up user management endpoints.
    
    Args:
        auth_manager: AuthManager instance
        get_db: Database dependency function
        **kwargs: Additional arguments passed to UserManagementRouter
    
    Returns:
        APIRouter: Configured router with user management endpoints
    
    Example:
        ```python
        from fastapi import FastAPI
        from fastapi_roles import create_user_management_router, AuthManager, AuthConfig
        
        app = FastAPI()
        
        # Setup auth manager
        config = AuthConfig(secret_key="your-secret-key")
        auth_manager = AuthManager(config, get_db)
        
        # Create and include user management router
        user_router = create_user_management_router(auth_manager, get_db)
        app.include_router(user_router)
        ```
    """
    user_mgmt = UserManagementRouter(auth_manager, get_db, **kwargs)
    return user_mgmt.router
