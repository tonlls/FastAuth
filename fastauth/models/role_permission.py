"""
Role-Permission association with additional metadata.
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
    from .permission import Permission


class RolePermission(Base):
    """Role-Permission association with additional metadata."""
    
    __tablename__ = "role_permission_details"
    
    id: Mapped[str] = mapped_column(GUID(), primary_key=True, default=uuid4)
    role_id: Mapped[str] = mapped_column(GUID(), ForeignKey("roles.id"))
    permission_id: Mapped[str] = mapped_column(GUID(), ForeignKey("permissions.id"))
    
    # Additional metadata for the relationship
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    granted_by: Mapped[Optional[str]] = mapped_column(GUID(), ForeignKey("users.id"), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    assignment_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    
    # Relationships
    role: Mapped["Role"] = relationship("Role", foreign_keys=[role_id])
    permission: Mapped["Permission"] = relationship("Permission", foreign_keys=[permission_id])
    granted_by_user: Mapped[Optional["User"]] = relationship("User", foreign_keys=[granted_by])
