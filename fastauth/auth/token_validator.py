"""
Token validation utility.
"""

from typing import Any, Dict, List, Optional

from ..providers import BaseAuthProvider
from ..schemas import TokenData


class TokenValidator:
    """Token validation utility."""
    
    def __init__(self, providers: List[BaseAuthProvider]):
        self.providers = providers
    
    async def validate_token(self, token: str) -> Optional[TokenData]:
        """Validate token using available providers."""
        for provider in self.providers:
            token_data = await provider.validate_token(token)
            if token_data:
                return token_data
        return None
    
    async def get_user_info(self, token_data: TokenData) -> Optional[Dict[str, Any]]:
        """Get user info from the appropriate provider."""
        for provider in self.providers:
            if provider.__class__.__name__.lower().replace("provider", "") == token_data.auth_provider:
                return await provider.get_user_info(token_data)
        return None
