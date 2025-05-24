"""
Base authentication provider.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ..schemas import TokenData


class BaseAuthProvider(ABC):
    """Base authentication provider."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    @abstractmethod
    async def validate_token(self, token: str) -> Optional[TokenData]:
        """Validate a token and return token data."""
        pass
    
    @abstractmethod
    async def get_user_info(self, token_data: TokenData) -> Optional[Dict[str, Any]]:
        """Get user information from the provider."""
        pass
    
    def extract_roles_and_permissions(self, user_data: Dict[str, Any]) -> tuple[List[str], List[str]]:
        """Extract roles and permissions from user data."""
        roles = user_data.get("roles", [])
        permissions = user_data.get("permissions", [])
        
        # Handle different data structures
        if isinstance(roles, str):
            roles = [roles]
        if isinstance(permissions, str):
            permissions = [permissions]
            
        return roles, permissions
