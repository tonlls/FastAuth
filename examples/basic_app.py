"""
Basic FastAPI application demonstrating fastapi-roles usage.
"""

from datetime import timedelta
from typing import List

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

# Import fastapi-roles components
from fastauth import (
    AuthConfig,
    AuthManager,
    Base,
    Permission,
    Role,
    RoleRouter,
    User,
    UserCreate,
    UserResponse,
    admin_required,
    require_permission,
    require_role,
    setup_role_middleware,
)
from fastauth.endpoints import create_user_management_router

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create tables
Base.metadata.create_all(bind=engine)


def get_db():
    """Database dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Auth configuration
config = AuthConfig(
    secret_key="your-super-secret-key-change-this-in-production",
    algorithm="HS256",
    access_token_expire_minutes=30,
)

# Initialize auth manager
auth_manager = AuthManager(
    config=config,
    get_db=get_db,
    providers=["jwt"]
)

# Create FastAPI app
app = FastAPI(
    title="FastAPI Roles Example",
    description="Example application demonstrating fastapi-roles",
    version="1.0.0"
)

# Setup middleware for automatic user injection
setup_role_middleware(app, auth_manager)

# Dependencies
get_current_user = auth_manager.create_dependency()
get_current_active_user = auth_manager.create_active_user_dependency()


# Initialize database with sample data
def init_db():
    """Initialize database with sample roles and permissions."""
    db = SessionLocal()
    
    # Check if data already exists
    if db.query(Role).first():
        db.close()
        return
    
    try:
        # Create permissions
        permissions = [
            Permission(name="users:read", description="Read user information"),
            Permission(name="users:write", description="Create and update users"),
            Permission(name="users:delete", description="Delete users"),
            Permission(name="posts:read", description="Read posts"),
            Permission(name="posts:write", description="Create and update posts"),
            Permission(name="posts:delete", description="Delete posts"),
            Permission(name="admin:access", description="Access admin panel"),
        ]
        
        for perm in permissions:
            db.add(perm)
        db.commit()
        
        # Create roles
        admin_role = Role(name="admin", description="Administrator with full access")
        moderator_role = Role(name="moderator", description="Moderator with limited admin access")
        user_role = Role(name="user", description="Regular user")
        
        db.add(admin_role)
        db.add(moderator_role)
        db.add(user_role)
        db.commit()
        
        # Assign permissions to roles
        admin_perms = db.query(Permission).all()
        moderator_perms = db.query(Permission).filter(
            Permission.name.in_(["users:read", "posts:read", "posts:write", "posts:delete"])
        ).all()
        user_perms = db.query(Permission).filter(
            Permission.name.in_(["posts:read"])
        ).all()
        
        admin_role.permissions = admin_perms
        moderator_role.permissions = moderator_perms
        user_role.permissions = user_perms
        
        db.commit()
        
        # Create sample users
        # Get JWT provider for password hashing
        from fastauth.providers import JWTProvider
        jwt_provider = None
        for provider in auth_manager.providers:
            if isinstance(provider, JWTProvider):
                jwt_provider = provider
                break
        
        if not jwt_provider:
            print("JWT provider not found")
            return
        
        admin_user = User(
            email="admin@example.com",
            username="admin",
            hashed_password=jwt_provider.get_password_hash("admin123"),
            is_superuser=True,
            is_verified=True
        )
        admin_user.roles = [admin_role]
        
        mod_user = User(
            email="moderator@example.com",
            username="moderator",
            hashed_password=jwt_provider.get_password_hash("mod123"),
            is_verified=True
        )
        mod_user.roles = [moderator_role]
        
        regular_user = User(
            email="user@example.com",
            username="user",
            hashed_password=jwt_provider.get_password_hash("user123"),
            is_verified=True
        )
        regular_user.roles = [user_role]
        
        db.add(admin_user)
        db.add(mod_user)
        db.add(regular_user)
        db.commit()
        
        print("Database initialized with sample data")
        
    except Exception as e:
        print(f"Error initializing database: {e}")
        db.rollback()
    finally:
        db.close()


# Initialize database on startup
init_db()


auth_router = create_user_management_router(
    auth_manager=auth_manager,
    get_db=get_db,
    prefix="/auth",
    tags=["Authentication"],
    enable_registration=True,
    enable_password_reset=True,
    require_email_verification=False,
    default_user_role="user"
)
app.include_router(auth_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
