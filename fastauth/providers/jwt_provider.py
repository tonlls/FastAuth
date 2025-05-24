"""
JWT authentication provider.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, Optional
from uuid import UUID

from jose import JWTError, jwt
from passlib.context import CryptContext

from .base import BaseAuthProvider
from ..schemas import TokenData


class JWTProvider(BaseAuthProvider):
    """JWT authentication provider."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.secret_key = config["secret_key"]
        self.algorithm = config.get("algorithm", "HS256")
        self.verify_signature = config.get("verify_signature", True)
        self.verify_exp = config.get("verify_exp", True)
        self.verify_aud = config.get("verify_aud", False)
        self.require_exp = config.get("require_exp", True)
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    
    async def validate_token(self, token: str) -> Optional[TokenData]:
        """Validate JWT token."""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={
                    "verify_signature": self.verify_signature,
                    "verify_exp": self.verify_exp,
                    "verify_aud": self.verify_aud,
                    "require_exp": self.require_exp,
                }
            )
            
            # Extract standard JWT claims
            user_id = payload.get("sub")
            if user_id:
                try:
                    user_id = UUID(user_id)
                except ValueError:
                    # If sub is not a UUID, use it as external_id
                    user_id = None
            
            exp = payload.get("exp")
            if exp:
                exp = datetime.fromtimestamp(exp)
            
            iat = payload.get("iat")
            if iat:
                iat = datetime.fromtimestamp(iat)
            
            # Extract custom claims
            roles = payload.get("roles", [])
            permissions = payload.get("permissions", [])
            
            if isinstance(roles, str):
                roles = [roles]
            if isinstance(permissions, str):
                permissions = [permissions]
            
            return TokenData(
                user_id=user_id,
                email=payload.get("email"),
                username=payload.get("username"),
                roles=roles,
                permissions=permissions,
                auth_provider="jwt",
                external_id=payload.get("sub") if not user_id else None,
                metadata=payload.get("metadata"),
                exp=exp,
                iat=iat,
                sub=payload.get("sub"),
                aud=payload.get("aud"),
                iss=payload.get("iss"),
            )
            
        except JWTError:
            return None
    
    async def get_user_info(self, token_data: TokenData) -> Optional[Dict[str, Any]]:
        """Get user info from token data (JWT is self-contained)."""
        return {
            "user_id": str(token_data.user_id) if token_data.user_id else None,
            "email": token_data.email,
            "username": token_data.username,
            "roles": token_data.roles,
            "permissions": token_data.permissions,
            "metadata": token_data.metadata,
        }
    
    def create_access_token(
        self,
        data: Dict[str, Any],
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create a JWT access token."""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        
        to_encode.update({"exp": expire, "iat": datetime.utcnow()})
        
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        """Hash a password."""
        return self.pwd_context.hash(password)
