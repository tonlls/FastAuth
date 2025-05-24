"""
Permission model.
"""

from datetime import datetime
from typing import List, Optional, TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base, GUID, JSON
from .associations import RolePermissionAssociation

if TYPE_CHECKING:
    from .role import Role


class Permission(Base):
    """Permission model."""
    
    __tablename__ = "permissions"
    
    id: Mapped[str] = mapped_column(GUID(), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    resource: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # e.g., 'users', 'posts', 'admin'
    action: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # e.g., 'read', 'write', 'delete'
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    
    # Dynamic permission data
    permission_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), onupdate=func.now(), nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(GUID(), ForeignKey("users.id"), nullable=True)
    
    # Relationships
    roles: Mapped[List["Role"]] = relationship("Role", secondary=RolePermissionAssociation.__table__, back_populates="permissions")
    
    def __repr__(self) -> str:
        return f"<Permission(id={self.id}, name={self.name})>"
