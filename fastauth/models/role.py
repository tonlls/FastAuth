"""
Role model.
"""

from datetime import datetime
from typing import List, Optional, TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base, GUID, JSON
from .associations import UserRoleAssociation, RolePermissionAssociation

if TYPE_CHECKING:
    from .user import User
    from .permission import Permission


class Role(Base):
    """Role model."""
    
    __tablename__ = "roles"
    
    id: Mapped[str] = mapped_column(GUID(), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    
    # Hierarchy support
    parent_id: Mapped[Optional[str]] = mapped_column(GUID(), ForeignKey("roles.id"), nullable=True)
    
    # Dynamic role data
    role_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), onupdate=func.now(), nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(GUID(), ForeignKey("users.id"), nullable=True)
    
    # Relationships
    users: Mapped[List["User"]] = relationship("User", secondary=UserRoleAssociation.__table__, back_populates="roles")
    permissions: Mapped[List["Permission"]] = relationship("Permission", secondary=RolePermissionAssociation.__table__, back_populates="roles")
    parent: Mapped[Optional["Role"]] = relationship("Role", remote_side=[id])
    children: Mapped[List["Role"]] = relationship("Role")
    
    def __repr__(self) -> str:
        return f"<Role(id={self.id}, name={self.name})>"
    
    def has_permission(self, permission_name: str) -> bool:
        """Check if role has a specific permission."""
        return any(perm.name == permission_name for perm in self.permissions)
    
    def get_all_permissions(self) -> List[str]:
        """Get all permissions including inherited from parent roles."""
        permissions = set(perm.name for perm in self.permissions)
        
        # Add parent permissions if hierarchy is used
        if self.parent:
            permissions.update(self.parent.get_all_permissions())
        
        return list(permissions)
