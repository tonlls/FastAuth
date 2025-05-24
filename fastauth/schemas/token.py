"""
Token data schema.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class TokenData(BaseModel):
    """Token data schema."""
    
    user_id: Optional[UUID] = None
    email: Optional[str] = None
    username: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    permissions: List[str] = Field(default_factory=list)
    auth_provider: Optional[str] = None
    external_id: Optional[str] = None
    user_metadata: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None  # Alias for user_metadata
    exp: Optional[datetime] = None
    iat: Optional[datetime] = None
    sub: Optional[str] = None
    aud: Optional[str] = None
    iss: Optional[str] = None
