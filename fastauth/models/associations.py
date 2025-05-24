"""
Association models for many-to-many relationships.
"""

from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base, GUID


class UserRoleAssociation(Base):
    __tablename__ = "user_roles"
    
    user_id: Mapped[str] = mapped_column(GUID(), ForeignKey("users.id"), primary_key=True)
    role_id: Mapped[str] = mapped_column(GUID(), ForeignKey("roles.id"), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RolePermissionAssociation(Base):
    __tablename__ = "role_permissions"
    
    role_id: Mapped[str] = mapped_column(GUID(), ForeignKey("roles.id"), primary_key=True)
    permission_id: Mapped[str] = mapped_column(GUID(), ForeignKey("permissions.id"), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
