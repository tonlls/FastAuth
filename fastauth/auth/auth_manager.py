"""
Main authentication manager.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Generator, List, Optional, Union
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from ..models import User
from ..providers import BaseAuthProvider, JWTProvider, create_provider
from ..schemas import AuthConfig, TokenData
from .token_validator import TokenValidator


class AuthManager:
    """Main authentication manager."""
    
    def __init__(
        self,
        config: AuthConfig,
        get_db: Callable[[], Generator[Session, None, None]],
        providers: Optional[List[str]] = None
    ):
        self.config: AuthConfig = config
        self.get_db: Callable[[], Generator[Session, None, None]] = get_db
        self.security: HTTPBearer = HTTPBearer(auto_error=False)
        
        # Initialize providers
        self.providers: List[BaseAuthProvider] = []
        if providers is None:
            providers = ["jwt"]  # Default to JWT
        
        for provider_type in providers:
            try:
                provider = create_provider(provider_type, config.model_dump())
                self.providers.append(provider)
            except Exception as e:
                print(f"Warning: Could not initialize {provider_type} provider: {e}")
        
        self.token_validator: TokenValidator = TokenValidator(self.providers)
    
    async def get_current_user(
        self,
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
        db: Session = Depends(lambda: None)
    ) -> Optional[User]:
        """Get current user from token."""
        if db is None:
            db = next(self.get_db())
        
        token = None
        
        # Try to get token from Authorization header
        if credentials:
            token = credentials.credentials
        
        # Try to get token from cookies
        if not token:
            token = request.cookies.get("access_token")
        
        # Try to get token from query parameters (for WebSocket connections)
        if not token:
            token = request.query_params.get("token")
        
        if not token:
            return None
        
        # Validate token
        token_data = await self.token_validator.validate_token(token)
        if not token_data:
            return None
        
        # Get or create user
        user = await self._get_or_create_user(db, token_data)
        
        # Update last login
        if user:
            user.last_login = datetime.now(timezone.utc)  # type: ignore
            db.commit()
        
        return user
    
    async def get_current_active_user(
        self,
        current_user: User = Depends(lambda: None)
    ) -> User:
        """Get current active user or raise exception."""
        if current_user is None:
            # This will be properly injected by the dependency system
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        if not current_user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inactive user"
            )
        
        return current_user
    
    async def get_current_superuser(
        self,
        current_user: User = Depends(lambda: None)
    ) -> User:
        """Get current superuser or raise exception."""
        current_user = await self.get_current_active_user(current_user)
        
        if not current_user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
        
        return current_user
    
    async def _get_or_create_user(self, db: Session, token_data: TokenData) -> Optional[User]:
        """Get existing user or create new one from token data."""
        user = None
        
        # Try to find user by ID first
        if token_data.user_id:
            user = db.query(User).filter(User.id == token_data.user_id).first()
        
        # Try to find by external ID
        if not user and token_data.external_id and token_data.auth_provider:
            user = db.query(User).filter(
                User.external_id == token_data.external_id,
                User.auth_provider == token_data.auth_provider
            ).first()
        
        # Try to find by email
        if not user and token_data.email:
            user = db.query(User).filter(User.email == token_data.email).first()
        
        # Create new user if not found
        if not user and token_data.email:
            user = User(
                email=token_data.email,
                username=token_data.username,
                auth_provider=token_data.auth_provider,
                external_id=token_data.external_id,
                is_verified=True,  # External auth providers are trusted
                user_metadata=token_data.metadata or {}
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        
        # Update user metadata if needed
        if user and token_data.metadata:
            if not user.user_metadata:
                user.user_metadata = {}
            user.user_metadata.update(token_data.metadata)
            db.commit()
        
        return user
    
    def create_dependency(self, require_auth: bool = True):
        """Create a dependency function for FastAPI."""
        async def dependency(
            request: Request,
            credentials: Optional[HTTPAuthorizationCredentials] = Depends(self.security),
            db: Session = Depends(self.get_db)
        ) -> Optional[User]:
            user = await self.get_current_user(request, credentials, db)
            
            if require_auth and not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            return user
        
        return dependency
    
    def create_active_user_dependency(self):
        """Create a dependency for active users only."""
        async def dependency(
            current_user: User = Depends(self.create_dependency(require_auth=True))
        ) -> User:
            if not current_user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Inactive user"
                )
            return current_user
        
        return dependency
    
    def create_superuser_dependency(self):
        """Create a dependency for superusers only."""
        async def dependency(
            current_user: User = Depends(self.create_active_user_dependency())
        ) -> User:
            if not current_user.is_superuser:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not enough permissions"
                )
            return current_user
        
        return dependency
    
    def create_role_dependency(self, required_roles: Union[str, List[str]]):
        """Create a dependency that requires specific roles."""
        if isinstance(required_roles, str):
            required_roles = [required_roles]
        
        async def dependency(
            current_user: User = Depends(self.create_active_user_dependency())
        ) -> User:
            user_roles = [role.name for role in current_user.roles]
            
            # Superuser bypasses role checks
            if current_user.is_superuser:
                return current_user
            
            # Check if user has any of the required roles
            if not any(role in user_roles for role in required_roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Required roles: {', '.join(required_roles)}"
                )
            
            return current_user
        
        return dependency
    
    def create_permission_dependency(self, required_permissions: Union[str, List[str]]):
        """Create a dependency that requires specific permissions."""
        if isinstance(required_permissions, str):
            required_permissions = [required_permissions]
        
        async def dependency(
            current_user: User = Depends(self.create_active_user_dependency())
        ) -> User:
            # Superuser bypasses permission checks
            if current_user.is_superuser:
                return current_user
            
            # Get all user permissions
            user_permissions = current_user.get_permissions()
            
            # Check if user has any of the required permissions
            if not any(perm in user_permissions for perm in required_permissions):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Required permissions: {', '.join(required_permissions)}"
                )
            
            return current_user
        
        return dependency
    
    async def authenticate_user(
        self,
        db: Session,
        email: str,
        password: str
    ) -> Optional[User]:
        """Authenticate user with email and password."""
        user = db.query(User).filter(User.email == email).first()
        
        if not user or not user.hashed_password:
            return None
        
        # Use JWT provider for password verification
        jwt_provider: Optional[JWTProvider] = None
        for provider in self.providers:
            if isinstance(provider, JWTProvider):
                jwt_provider = provider
                break
        
        if not jwt_provider:
            return None
        
        if not jwt_provider.verify_password(password, user.hashed_password):
            return None
        
        return user
    
    def create_access_token(
        self,
        user: User,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create access token for user."""
        # Use JWT provider for token creation
        jwt_provider: Optional[JWTProvider] = None
        for provider in self.providers:
            if isinstance(provider, JWTProvider):
                jwt_provider = provider
                break
        
        if not jwt_provider:
            raise ValueError("JWT provider not available")
        
        # Prepare token data
        token_data: Dict[str, Any] = {
            "sub": str(user.id),
            "email": user.email,
            "username": user.username,
            "roles": [role.name for role in user.roles],
            "permissions": user.get_permissions(),
            "metadata": user.user_metadata,
        }
        
        return jwt_provider.create_access_token(token_data, expires_delta)
