"""
Provider factory for creating authentication providers.
"""

from typing import Any, Dict

from .base import BaseAuthProvider
from .jwt_provider import JWTProvider
from .auth0_provider import Auth0Provider
from .firebase_provider import FirebaseProvider
from .custom_provider import CustomTokenProvider


def create_provider(provider_type: str, config: Dict[str, Any]) -> BaseAuthProvider:
    """Create an authentication provider based on type."""
    providers = {
        "jwt": JWTProvider,
        "auth0": Auth0Provider,
        "firebase": FirebaseProvider,
        "custom": CustomTokenProvider,
    }
    
    provider_class = providers.get(provider_type.lower())
    if not provider_class:
        raise ValueError(f"Unknown provider type: {provider_type}")
    
    return provider_class(config)
