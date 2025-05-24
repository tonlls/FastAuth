"""
User model.
"""

from datetime import datetime
from typing import List, Optional, TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base, GUID, JSON
from .associations import UserRoleAssociation

if TYPE_CHECKING:
    from .role import Role
    from .permission import Permission


class User(Base):
    """User model with dynamic fields support."""
    
    __tablename__ = "users"
    
    id: Mapped[str] = mapped_column(GUID(), primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    username: Mapped[Optional[str]] = mapped_column(String(100), unique=True, index=True, nullable=True)
    hashed_password: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Nullable for external auth
    first_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    last_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # External auth provider info
    auth_provider: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # 'auth0', 'firebase', 'local', etc.
    external_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # ID from external provider
    
    # Dynamic user data
    user_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # Store additional user fields
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), onupdate=func.now(), nullable=True)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    roles: Mapped[List["Role"]] = relationship("Role", secondary=UserRoleAssociation.__table__, back_populates="users")
    created_roles: Mapped[List["Role"]] = relationship("Role", foreign_keys="Role.created_by", overlaps="roles")
    created_permissions: Mapped[List["Permission"]] = relationship("Permission", foreign_keys="Permission.created_by")
    
    def __repr__(self) -> str:
        return f"<User(id={self.id}, email={self.email})>"
    
    @property
    def full_name(self) -> str:
        """Get user's full name."""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.first_name or self.last_name or self.email
    
    def has_role(self, role_name: str) -> bool:
        """Check if user has a specific role."""
        return any(role.name == role_name for role in self.roles)
    
    def has_permission(self, permission_name: str) -> bool:
        """Check if user has a specific permission through any role."""
        for role in self.roles:
            if role.has_permission(permission_name):
                return True
        return False
    
    def get_permissions(self) -> List[str]:
        """Get all permissions for this user."""
        permissions = set()
        for role in self.roles:
            permissions.update(perm.name for perm in role.permissions)
        return list(permissions)
