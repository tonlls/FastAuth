"""
Authentication schemas.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr

from .user import UserResponse


class LoginRequest(BaseModel):
    """Login request schema."""
    
    email: Optional[EmailStr] = None
    username: Optional[str] = None
    password: str


class LoginResponse(BaseModel):
    """Login response schema."""
    
    access_token: str
    token_type: str = "bearer"
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None
    user: UserResponse


class RefreshTokenRequest(BaseModel):
    """Refresh token request schema."""
    
    refresh_token: str


class PasswordResetRequest(BaseModel):
    """Password reset request schema."""
    
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Password reset confirmation schema."""
    
    token: str
    new_password: str


class ChangePasswordRequest(BaseModel):
    """Change password request schema."""
    
    current_password: str
    new_password: str


class AuthConfig(BaseModel):
    """Authentication configuration schema."""
    
    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    password_reset_expire_minutes: int = 15
    
    # External provider settings
    auth0_domain: Optional[str] = None
    auth0_client_id: Optional[str] = None
    auth0_client_secret: Optional[str] = None
    
    firebase_project_id: Optional[str] = None
    firebase_private_key: Optional[str] = None
    firebase_client_email: Optional[str] = None
    
    # Token validation settings
    verify_signature: bool = True
    verify_exp: bool = True
    verify_aud: bool = False
    require_exp: bool = True
    
    # User model customization
    user_model_fields: Optional[Dict[str, Any]] = None
    token_fields: Optional[List[str]] = None
