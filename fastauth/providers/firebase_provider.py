"""
Firebase authentication provider.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import httpx
from jose import jwt

from .base import BaseAuthProvider
from ..schemas import TokenData


class FirebaseProvider(BaseAuthProvider):
    """Firebase authentication provider."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.project_id = config["firebase_project_id"]
        self._certificates_cache = None
        self._certificates_cache_time = None
        self._cache_duration = timedelta(hours=1)
    
    async def _get_certificates(self) -> Dict[str, str]:
        """Get Firebase certificates."""
        now = datetime.utcnow()
        
        if (self._certificates_cache is None or 
            self._certificates_cache_time is None or 
            now - self._certificates_cache_time > self._cache_duration):
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
                )
                response.raise_for_status()
                self._certificates_cache = response.json()
                self._certificates_cache_time = now
        
        return self._certificates_cache
    
    async def validate_token(self, token: str) -> Optional[TokenData]:
        """Validate Firebase ID token."""
        try:
            # Get the key ID from token header
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            
            if not kid:
                return None
            
            # Get certificates and find the key
            certificates = await self._get_certificates()
            certificate = certificates.get(kid)
            
            if not certificate:
                return None
            
            # Verify token
            payload = jwt.decode(
                token,
                certificate,
                algorithms=["RS256"],
                audience=self.project_id,
                issuer=f"https://securetoken.google.com/{self.project_id}"
            )
            
            # Extract user information
            user_id = payload.get("sub")
            exp = payload.get("exp")
            if exp:
                exp = datetime.fromtimestamp(exp)
            
            iat = payload.get("iat")
            if iat:
                iat = datetime.fromtimestamp(iat)
            
            # Firebase custom claims
            custom_claims = payload.get("custom_claims", {})
            roles = custom_claims.get("roles", [])
            permissions = custom_claims.get("permissions", [])
            
            return TokenData(
                user_id=None,  # Firebase uses external_id
                email=payload.get("email"),
                username=payload.get("name"),
                roles=roles if isinstance(roles, list) else [roles] if roles else [],
                permissions=permissions if isinstance(permissions, list) else [permissions] if permissions else [],
                auth_provider="firebase",
                external_id=user_id,
                metadata={
                    "name": payload.get("name"),
                    "picture": payload.get("picture"),
                    "email_verified": payload.get("email_verified"),
                    "phone_number": payload.get("phone_number"),
                    "firebase": payload.get("firebase", {}),
                },
                exp=exp,
                iat=iat,
                sub=payload.get("sub"),
                aud=payload.get("aud"),
                iss=payload.get("iss"),
            )
            
        except Exception:
            return None
    
    async def get_user_info(self, token_data: TokenData) -> Optional[Dict[str, Any]]:
        """Get user info from Firebase (token is self-contained)."""
        return {
            "user_id": token_data.external_id,
            "email": token_data.email,
            "username": token_data.username,
            "roles": token_data.roles,
            "permissions": token_data.permissions,
            "metadata": token_data.metadata,
        }
