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


# Authentication endpoints
@app.post("/auth/login")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """Login endpoint."""
    user = await auth_manager.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=config.access_token_expire_minutes)
    access_token = auth_manager.create_access_token(
        user=user, expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": str(user.id),
            "email": user.email,
            "username": user.username,
            "roles": [role.name for role in user.roles]
        }
    }


@app.get("/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_active_user)):
    """Get current user information."""
    return current_user


# Public endpoints
@app.get("/")
async def root():
    """Public endpoint."""
    return {"message": "Welcome to FastAPI Roles Example!"}


@app.get("/public")
async def public_endpoint():
    """Another public endpoint."""
    return {"message": "This is a public endpoint accessible to everyone"}


# Protected endpoints using decorators
@app.get("/protected")
async def protected_endpoint(current_user: User = Depends(get_current_active_user)):
    """Endpoint that requires authentication."""
    return {
        "message": f"Hello {current_user.email}! This is a protected endpoint.",
        "user_roles": [role.name for role in current_user.roles]
    }


@app.get("/admin-only")
@admin_required()
async def admin_only_endpoint(current_user: User = Depends(get_current_active_user)):
    """Endpoint that requires admin role."""
    return {
        "message": "Welcome to the admin area!",
        "user": current_user.email
    }


@app.get("/moderator-or-admin")
@require_role(["admin", "moderator"])
async def moderator_or_admin_endpoint(current_user: User = Depends(get_current_active_user)):
    """Endpoint that requires admin or moderator role."""
    return {
        "message": "You have moderator or admin access!",
        "user": current_user.email,
        "role": [role.name for role in current_user.roles]
    }


@app.get("/read-users")
@require_permission("users:read")
async def read_users_endpoint(current_user: User = Depends(get_current_active_user)):
    """Endpoint that requires users:read permission."""
    return {
        "message": "You can read user information!",
        "user": current_user.email
    }


@app.post("/create-user")
@require_permission("users:write")
async def create_user_endpoint(
    user_data: UserCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Endpoint that requires users:write permission."""
    # This is a simplified example - in production you'd want proper validation
    
    # Get JWT provider for password hashing
    from fastauth.providers import JWTProvider
    jwt_provider = None
    for provider in auth_manager.providers:
        if isinstance(provider, JWTProvider):
            jwt_provider = provider
            break
    
    hashed_password = None
    if user_data.password and jwt_provider:
        hashed_password = jwt_provider.get_password_hash(user_data.password)
    
    new_user = User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=hashed_password,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        is_active=user_data.is_active,
        is_verified=user_data.is_verified,
        user_metadata=user_data.user_metadata
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {
        "message": "User created successfully!",
        "created_by": current_user.email,
        "new_user": {
            "id": str(new_user.id),
            "email": new_user.email,
            "username": new_user.username
        }
    }


# Role-based routers
admin_router = RoleRouter(
    auth_manager=auth_manager,
    required_roles=["admin"],
    prefix="/admin",
    tags=["admin"]
)

@admin_router.get("/dashboard")
async def admin_dashboard():
    """Admin dashboard."""
    return {"message": "Welcome to the admin dashboard!"}

@admin_router.get("/users")
async def admin_get_users(db: Session = Depends(get_db)):
    """Get all users (admin only)."""
    users = db.query(User).all()
    return {
        "users": [
            {
                "id": str(user.id),
                "email": user.email,
                "username": user.username,
                "is_active": user.is_active,
                "roles": [role.name for role in user.roles]
            }
            for user in users
        ]
    }

@admin_router.get("/roles")
async def admin_get_roles(db: Session = Depends(get_db)):
    """Get all roles (admin only)."""
    roles = db.query(Role).all()
    return {
        "roles": [
            {
                "id": str(role.id),
                "name": role.name,
                "description": role.description,
                "permissions": [perm.name for perm in role.permissions]
            }
            for role in roles
        ]
    }


# Moderator router
moderator_router = RoleRouter(
    auth_manager=auth_manager,
    required_roles=["moderator", "admin"],  # Admin can also access
    prefix="/moderator",
    tags=["moderator"]
)

@moderator_router.get("/posts")
async def moderator_get_posts():
    """Get posts for moderation."""
    return {
        "message": "Here are the posts for moderation",
        "posts": [
            {"id": 1, "title": "Sample Post 1", "status": "pending"},
            {"id": 2, "title": "Sample Post 2", "status": "approved"},
        ]
    }

@moderator_router.post("/posts/{post_id}/approve")
async def moderator_approve_post(post_id: int):
    """Approve a post."""
    return {
        "message": f"Post {post_id} has been approved",
        "post_id": post_id,
        "status": "approved"
    }


# Include routers
app.include_router(admin_router)
app.include_router(moderator_router)


# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom HTTP exception handler."""
    return {
        "error": exc.detail,
        "status_code": exc.status_code
    }


if __name__ == "__main__":
    import uvicorn
    
    print("Starting FastAPI Roles Example Application...")
    print("\nSample users:")
    print("- admin@example.com / admin123 (admin role)")
    print("- moderator@example.com / mod123 (moderator role)")
    print("- user@example.com / user123 (user role)")
    print("\nAPI Documentation: http://localhost:8000/docs")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)
