"""
Custom token provider for other authentication systems.
"""

from typing import Any, Dict, Optional

import httpx

from .base import BaseAuthProvider
from ..schemas import TokenData


class CustomTokenProvider(BaseAuthProvider):
    """Custom token provider for other authentication systems."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.validation_url = config.get("validation_url")
        self.headers = config.get("headers", {})
        self.token_field = config.get("token_field", "token")
        self.user_id_field = config.get("user_id_field", "user_id")
        self.email_field = config.get("email_field", "email")
        self.roles_field = config.get("roles_field", "roles")
        self.permissions_field = config.get("permissions_field", "permissions")
    
    async def validate_token(self, token: str) -> Optional[TokenData]:
        """Validate token using external API."""
        if not self.validation_url:
            return None
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.validation_url,
                    json={self.token_field: token},
                    headers=self.headers
                )
                
                if response.status_code != 200:
                    return None
                
                data = response.json()
                
                roles = data.get(self.roles_field, [])
                permissions = data.get(self.permissions_field, [])
                
                return TokenData(
                    user_id=data.get(self.user_id_field),
                    email=data.get(self.email_field),
                    username=data.get("username"),
                    roles=roles if isinstance(roles, list) else [roles] if roles else [],
                    permissions=permissions if isinstance(permissions, list) else [permissions] if permissions else [],
                    auth_provider="custom",
                    external_id=data.get("external_id"),
                    metadata=data.get("metadata"),
                )
                
        except Exception:
            return None
    
    async def get_user_info(self, token_data: TokenData) -> Optional[Dict[str, Any]]:
        """Get user info (already contained in token validation)."""
        return {
            "user_id": str(token_data.user_id) if token_data.user_id else None,
            "email": token_data.email,
            "username": token_data.username,
            "roles": token_data.roles,
            "permissions": token_data.permissions,
            "metadata": token_data.metadata,
        }
