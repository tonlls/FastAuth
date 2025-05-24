"""
User-Role association with additional metadata.
"""

from datetime import datetime
from typing import Optional, TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base, GUID, JSON

if TYPE_CHECKING:
    from .user import User
    from .role import Role


class UserRole(Base):
    """User-Role association with additional metadata."""
    
    __tablename__ = "user_role_details"
    
    id: Mapped[str] = mapped_column(GUID(), primary_key=True, default=uuid4)
    user_id: Mapped[str] = mapped_column(GUID(), ForeignKey("users.id"))
    role_id: Mapped[str] = mapped_column(GUID(), ForeignKey("roles.id"))
    
    # Additional metadata for the relationship
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    granted_by: Mapped[Optional[str]] = mapped_column(GUID(), ForeignKey("users.id"), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    assignment_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    
    # Relationships
    user: Mapped["User"] = relationship("User", foreign_keys=[user_id])
    role: Mapped["Role"] = relationship("Role", foreign_keys=[role_id])
    granted_by_user: Mapped[Optional["User"]] = relationship("User", foreign_keys=[granted_by])
