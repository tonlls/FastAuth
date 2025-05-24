"""
Authentication providers for FastAPI Roles package.
"""

from .base import BaseAuthProvider
from .jwt_provider import JWTProvider
from .auth0_provider import Auth0Provider
from .firebase_provider import FirebaseProvider
from .custom_provider import CustomTokenProvider
from .factory import create_provider

__all__ = [
    "BaseAuthProvider",
    "JWTProvider",
    "Auth0Provider",
    "FirebaseProvider",
    "CustomTokenProvider",
    "create_provider",
]
