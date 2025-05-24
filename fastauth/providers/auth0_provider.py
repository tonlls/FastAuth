"""
Auth0 authentication provider.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import httpx
from jose import jwt

from .base import BaseAuthProvider
from ..schemas import TokenData


class Auth0Provider(BaseAuthProvider):
    """Auth0 authentication provider."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.domain = config["auth0_domain"]
        self.client_id = config.get("auth0_client_id")
        self.client_secret = config.get("auth0_client_secret")
        self.algorithms = ["RS256"]
        self._jwks_cache = None
        self._jwks_cache_time = None
        self._cache_duration = timedelta(hours=1)
    
    async def _get_jwks(self) -> Dict[str, Any]:
        """Get JWKS from Auth0."""
        now = datetime.utcnow()
        
        if (self._jwks_cache is None or 
            self._jwks_cache_time is None or 
            now - self._jwks_cache_time > self._cache_duration):
            
            async with httpx.AsyncClient() as client:
                response = await client.get(f"https://{self.domain}/.well-known/jwks.json")
                response.raise_for_status()
                self._jwks_cache = response.json()
                self._jwks_cache_time = now
        
        return self._jwks_cache
    
    async def validate_token(self, token: str) -> Optional[TokenData]:
        """Validate Auth0 JWT token."""
        try:
            # Get the key ID from token header
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            
            if not kid:
                return None
            
            # Get JWKS and find the key
            jwks = await self._get_jwks()
            key = None
            
            for jwk in jwks.get("keys", []):
                if jwk.get("kid") == kid:
                    key = jwk
                    break
            
            if not key:
                return None
            
            # Verify token
            payload = jwt.decode(
                token,
                key,
                algorithms=self.algorithms,
                audience=self.client_id,
                issuer=f"https://{self.domain}/"
            )
            
            # Extract user information
            user_id = payload.get("sub")
            exp = payload.get("exp")
            if exp:
                exp = datetime.fromtimestamp(exp)
            
            iat = payload.get("iat")
            if iat:
                iat = datetime.fromtimestamp(iat)
            
            # Extract Auth0 specific claims
            roles = []
            permissions = []
            
            # Auth0 typically stores roles and permissions in custom claims
            namespace = f"https://{self.domain}/"
            roles = payload.get(f"{namespace}roles", [])
            permissions = payload.get(f"{namespace}permissions", [])
            
            # Also check for standard claims
            if not roles:
                roles = payload.get("roles", [])
            if not permissions:
                permissions = payload.get("permissions", [])
            
            return TokenData(
                user_id=None,  # Auth0 uses external_id
                email=payload.get("email"),
                username=payload.get("nickname") or payload.get("preferred_username"),
                roles=roles if isinstance(roles, list) else [roles] if roles else [],
                permissions=permissions if isinstance(permissions, list) else [permissions] if permissions else [],
                auth_provider="auth0",
                external_id=user_id,
                metadata={
                    "name": payload.get("name"),
                    "picture": payload.get("picture"),
                    "email_verified": payload.get("email_verified"),
                    "locale": payload.get("locale"),
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
        """Get additional user info from Auth0 Management API."""
        if not self.client_secret or not token_data.external_id:
            return None
        
        try:
            # Get management API token
            async with httpx.AsyncClient() as client:
                # Get access token for Management API
                auth_response = await client.post(
                    f"https://{self.domain}/oauth/token",
                    json={
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "audience": f"https://{self.domain}/api/v2/",
                        "grant_type": "client_credentials"
                    }
                )
                auth_response.raise_for_status()
                access_token = auth_response.json()["access_token"]
                
                # Get user info
                user_response = await client.get(
                    f"https://{self.domain}/api/v2/users/{token_data.external_id}",
                    headers={"Authorization": f"Bearer {access_token}"}
                )
                user_response.raise_for_status()
                
                return user_response.json()
                
        except Exception:
            return None
