"""
Comprehensive FastAuth Example

This example demonstrates all the major features of FastAuth:
- Multiple access control methods (decorators, dependencies, routers, middleware)
- User management endpoints
- Role and permission management
- Multiple authentication providers
- Advanced features like WebSocket auth and custom middleware
"""

import os
from datetime import timedelta
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

# Import FastAuth components
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
    create_user_management_router,
)
from fastauth.decorators import (
    require_all_roles,
    require_all_permissions,
    require_superuser,
    verified_required,
)
from fastauth.middleware import setup_authentication_middleware
from fastauth.router import AdminRouter, ModeratorRouter, SuperuserRouter

# Database setup with environment variable support
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./comprehensive_example.db")
engine = create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
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


# Auth configuration with multiple providers
config = AuthConfig(
    secret_key=os.getenv("SECRET_KEY", "comprehensive-example-secret-key"),
    algorithm="HS256",
    access_token_expire_minutes=30,
    refresh_token_expire_days=7,
    password_reset_expire_minutes=15,
    # Auth0 configuration (optional)
    auth0_domain=os.getenv("AUTH0_DOMAIN"),
    auth0_client_id=os.getenv("AUTH0_CLIENT_ID"),
    auth0_client_secret=os.getenv("AUTH0_CLIENT_SECRET"),
    # Firebase configuration (optional)
    firebase_project_id=os.getenv("FIREBASE_PROJECT_ID"),
)

# Initialize auth manager with multiple providers
providers = ["jwt"]
if config.auth0_domain:
    providers.append("auth0")
if config.firebase_project_id:
    providers.append("firebase")

auth_manager = AuthManager(
    config=config,
    get_db=get_db,
    providers=providers
)

# Create FastAPI app
app = FastAPI(
    title="FastAuth Comprehensive Example",
    description="Complete demonstration of FastAuth capabilities",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Setup middleware for automatic user injection
setup_role_middleware(app, auth_manager)

# Optional: Setup authentication middleware for all routes except public ones
# setup_authentication_middleware(
#     app, 
#     auth_manager, 
#     exclude_paths=["/", "/docs", "/redoc", "/openapi.json", "/auth/login", "/auth/register"]
# )

# Dependencies
get_current_user = auth_manager.create_dependency()
get_current_active_user = auth_manager.create_active_user_dependency()
get_current_superuser = auth_manager.create_superuser_dependency()

# Custom dependencies
require_admin = auth_manager.create_role_dependency("admin")
require_manager = auth_manager.create_role_dependency(["admin", "manager"])
require_read = auth_manager.create_permission_dependency("posts:read")
require_write = auth_manager.create_permission_dependency(["posts:read", "posts:write"])


def init_comprehensive_data():
    """Initialize comprehensive demo data with roles, permissions, and users."""
    db = SessionLocal()
    
    try:
        # Check if data already exists
        if db.query(Role).first():
            return
        
        print("🔧 Initializing comprehensive demo data...")
        
        # Create comprehensive permissions
        permissions = [
            # User management
            Permission(name="users:read", description="Read user information"),
            Permission(name="users:write", description="Create and update users"),
            Permission(name="users:delete", description="Delete users"),
            Permission(name="users:promote", description="Promote users to higher roles"),
            
            # Content management
            Permission(name="posts:read", description="Read posts"),
            Permission(name="posts:write", description="Create and update posts"),
            Permission(name="posts:delete", description="Delete posts"),
            Permission(name="posts:moderate", description="Moderate posts"),
            
            # System administration
            Permission(name="admin:access", description="Access admin panel"),
            Permission(name="admin:settings", description="Modify system settings"),
            Permission(name="admin:logs", description="View system logs"),
            
            # Reports and analytics
            Permission(name="reports:view", description="View reports"),
            Permission(name="reports:generate", description="Generate reports"),
            Permission(name="analytics:view", description="View analytics"),
            
            # API access
            Permission(name="api:read", description="Read API access"),
            Permission(name="api:write", description="Write API access"),
        ]
        
        for perm in permissions:
            db.add(perm)
        db.commit()
        
        # Create comprehensive roles
        roles_data = [
            {
                "name": "user",
                "description": "Regular user with basic permissions",
                "permissions": ["posts:read", "api:read"]
            },
            {
                "name": "author",
                "description": "Content author with writing permissions",
                "permissions": ["posts:read", "posts:write", "api:read"]
            },
            {
                "name": "moderator",
                "description": "Content moderator with moderation permissions",
                "permissions": ["posts:read", "posts:write", "posts:moderate", "users:read", "api:read"]
            },
            {
                "name": "manager",
                "description": "Manager with user and content management",
                "permissions": [
                    "posts:read", "posts:write", "posts:moderate", "posts:delete",
                    "users:read", "users:write", "reports:view", "api:read", "api:write"
                ]
            },
            {
                "name": "admin",
                "description": "Administrator with full access",
                "permissions": [p.name for p in permissions]  # All permissions
            }
        ]
        
        for role_data in roles_data:
            role = Role(name=role_data["name"], description=role_data["description"])
            db.add(role)
            db.commit()
            db.refresh(role)
            
            # Assign permissions to role
            role_permissions = db.query(Permission).filter(
                Permission.name.in_(role_data["permissions"])
            ).all()
            role.permissions = role_permissions
            db.commit()
        
        # Create demo users with different roles
        from fastauth.providers import JWTProvider
        jwt_provider = None
        for provider in auth_manager.providers:
            if isinstance(provider, JWTProvider):
                jwt_provider = provider
                break
        
        if not jwt_provider:
            print("❌ JWT provider not found")
            return
        
        users_data = [
            {
                "email": "user@example.com",
                "username": "user",
                "password": "user123",
                "first_name": "Regular",
                "last_name": "User",
                "roles": ["user"],
                "is_superuser": False
            },
            {
                "email": "author@example.com",
                "username": "author",
                "password": "author123",
                "first_name": "Content",
                "last_name": "Author",
                "roles": ["author"],
                "is_superuser": False
            },
            {
                "email": "moderator@example.com",
                "username": "moderator",
                "password": "mod123",
                "first_name": "Content",
                "last_name": "Moderator",
                "roles": ["moderator"],
                "is_superuser": False
            },
            {
                "email": "manager@example.com",
                "username": "manager",
                "password": "manager123",
                "first_name": "Project",
                "last_name": "Manager",
                "roles": ["manager"],
                "is_superuser": False
            },
            {
                "email": "admin@example.com",
                "username": "admin",
                "password": "admin123",
                "first_name": "System",
                "last_name": "Administrator",
                "roles": ["admin"],
                "is_superuser": True
            }
        ]
        
        for user_data in users_data:
            user = User(
                email=user_data["email"],
                username=user_data["username"],
                hashed_password=jwt_provider.get_password_hash(user_data["password"]),
                first_name=user_data["first_name"],
                last_name=user_data["last_name"],
                is_superuser=user_data["is_superuser"],
                is_verified=True,
                auth_provider="local"
            )
            
            # Assign roles
            user_roles = db.query(Role).filter(Role.name.in_(user_data["roles"])).all()
            user.roles = user_roles
            
            db.add(user)
        
        db.commit()
        
        print("✅ Comprehensive demo data initialized!")
        print("👤 Demo users created:")
        for user_data in users_data:
            roles_str = ", ".join(user_data["roles"])
            print(f"   - {user_data['email']} / {user_data['password']} ({roles_str})")
        
    except Exception as e:
        print(f"❌ Error initializing demo data: {e}")
        db.rollback()
    finally:
        db.close()


# Initialize demo data
init_comprehensive_data()

# Include user management router
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


# =============================================================================
# PUBLIC ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    """Welcome endpoint with demo information."""
    return {
        "message": "Welcome to FastAuth Comprehensive Example!",
        "features": [
            "Multiple access control methods",
            "Role-based and permission-based access",
            "User management endpoints",
            "WebSocket authentication",
            "Multiple authentication providers",
            "Advanced middleware"
        ],
        "docs": "/docs",
        "demo_users": {
            "user": "user@example.com / user123 (basic user)",
            "author": "author@example.com / author123 (content author)",
            "moderator": "moderator@example.com / mod123 (content moderator)",
            "manager": "manager@example.com / manager123 (project manager)",
            "admin": "admin@example.com / admin123 (system admin)"
        },
        "endpoints": {
            "authentication": "/auth/*",
            "basic_protection": "/protected",
            "role_based": "/roles/*",
            "permission_based": "/permissions/*",
            "admin_area": "/admin/*",
            "management": "/management/*",
            "websocket": "/ws"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "providers": [p.__class__.__name__ for p in auth_manager.providers]}


# =============================================================================
# BASIC PROTECTED ENDPOINTS
# =============================================================================

@app.get("/protected")
async def protected_endpoint(current_user: User = Depends(get_current_active_user)):
    """Basic protected endpoint requiring authentication."""
    return {
        "message": f"Hello {current_user.email}!",
        "user_info": {
            "email": current_user.email,
            "username": current_user.username,
            "roles": [role.name for role in current_user.roles],
            "permissions": current_user.get_permissions(),
            "is_superuser": current_user.is_superuser,
            "is_verified": current_user.is_verified
        }
    }


# =============================================================================
# DECORATOR-BASED ACCESS CONTROL
# =============================================================================

@app.get("/decorators/admin")
@admin_required()
async def decorator_admin(current_user: User = Depends(get_current_active_user)):
    """Admin-only endpoint using decorator."""
    return {"message": "Admin access via decorator", "user": current_user.email}


@app.get("/decorators/role/{role_name}")
@require_role(["manager", "admin"])
async def decorator_role(role_name: str, current_user: User = Depends(get_current_active_user)):
    """Multi-role endpoint using decorator."""
    return {
        "message": f"Access granted for role check: {role_name}",
        "user": current_user.email,
        "user_roles": [role.name for role in current_user.roles]
    }


@app.get("/decorators/all-roles")
@require_all_roles(["admin"])
async def decorator_all_roles(current_user: User = Depends(get_current_active_user)):
    """Endpoint requiring ALL specified roles."""
    return {
        "message": "Access granted - user has ALL required roles",
        "user": current_user.email,
        "user_roles": [role.name for role in current_user.roles]
    }


@app.get("/decorators/permission")
@require_permission(["posts:read", "api:read"])
async def decorator_permission(current_user: User = Depends(get_current_active_user)):
    """Permission-based endpoint using decorator."""
    return {
        "message": "Permission-based access granted",
        "user": current_user.email,
        "user_permissions": current_user.get_permissions()
    }


@app.get("/decorators/all-permissions")
@require_all_permissions(["posts:read", "posts:write", "api:read"])
async def decorator_all_permissions(current_user: User = Depends(get_current_active_user)):
    """Endpoint requiring ALL specified permissions."""
    return {
        "message": "Access granted - user has ALL required permissions",
        "user": current_user.email,
        "user_permissions": current_user.get_permissions()
    }


@app.get("/decorators/superuser")
@require_superuser()
async def decorator_superuser(current_user: User = Depends(get_current_active_user)):
    """Superuser-only endpoint using decorator."""
    return {"message": "Superuser access granted", "user": current_user.email}


@app.get("/decorators/verified")
@verified_required()
async def decorator_verified(current_user: User = Depends(get_current_active_user)):
    """Verified users only endpoint using decorator."""
    return {
        "message": "Verified user access granted",
        "user": current_user.email,
        "is_verified": current_user.is_verified
    }


# =============================================================================
# DEPENDENCY-BASED ACCESS CONTROL
# =============================================================================

@app.get("/dependencies/admin")
async def dependency_admin(user: User = Depends(require_admin)):
    """Admin endpoint using dependency."""
    return {"message": "Admin access via dependency", "user": user.email}


@app.get("/dependencies/manager")
async def dependency_manager(user: User = Depends(require_manager)):
    """Manager endpoint using dependency."""
    return {"message": "Manager access via dependency", "user": user.email}


@app.get("/dependencies/read")
async def dependency_read(user: User = Depends(require_read)):
    """Read permission endpoint using dependency."""
    return {"message": "Read access via dependency", "user": user.email}


@app.get("/dependencies/write")
async def dependency_write(user: User = Depends(require_write)):
    """Write permission endpoint using dependency."""
    return {"message": "Write access via dependency", "user": user.email}


# =============================================================================
# ROLE-BASED ROUTERS
# =============================================================================

# Admin router - requires admin role for all routes
admin_router = AdminRouter(
    auth_manager=auth_manager,
    prefix="/admin",
    tags=["Admin"]
)

@admin_router.get("/dashboard")
async def admin_dashboard():
    """Admin dashboard."""
    return {
        "message": "Admin Dashboard",
        "features": ["User management", "System settings", "Logs", "Analytics"]
    }

@admin_router.get("/users")
async def admin_list_users(db: Session = Depends(get_db)):
    """List all users (admin only)."""
    users = db.query(User).all()
    return {
        "users": [
            {
                "id": str(user.id),
                "email": user.email,
                "username": user.username,
                "roles": [role.name for role in user.roles],
                "is_active": user.is_active,
                "is_superuser": user.is_superuser
            }
            for user in users
        ]
    }

@admin_router.post("/users/{user_id}/promote")
async def admin_promote_user(
    user_id: str, 
    new_role: str,
    db: Session = Depends(get_db)
):
    """Promote user to a new role."""
    user = db.query(User).filter(User.id == user_id).first()
    role = db.query(Role).filter(Role.name == new_role).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    
    if role not in user.roles:
        user.roles.append(role)
        db.commit()
    
    return {"message": f"User {user.email} promoted to {new_role}"}


# Manager router - requires manager or admin role
manager_router = RoleRouter(
    auth_manager=auth_manager,
    required_roles=["manager", "admin"],
    prefix="/management",
    tags=["Management"]
)

@manager_router.get("/reports")
async def management_reports():
    """Management reports."""
    return {
        "reports": [
            {"name": "User Activity", "type": "analytics"},
            {"name": "Content Statistics", "type": "content"},
            {"name": "System Performance", "type": "system"}
        ]
    }

@manager_router.get("/team")
async def management_team(db: Session = Depends(get_db)):
    """Team management."""
    users = db.query(User).all()
    return {
        "team_members": [
            {
                "email": user.email,
                "roles": [role.name for role in user.roles],
                "permissions": user.get_permissions()
            }
            for user in users
        ]
    }


# Content router - requires specific permissions
content_router = RoleRouter(
    auth_manager=auth_manager,
    required_permissions=["posts:read"],
    prefix="/content",
    tags=["Content"]
)

@content_router.get("/posts")
async def list_posts():
    """List posts (requires read permission)."""
    return {
        "posts": [
            {"id": 1, "title": "Welcome Post", "author": "admin"},
            {"id": 2, "title": "Getting Started", "author": "author"},
            {"id": 3, "title": "Advanced Features", "author": "moderator"}
        ]
    }

# Create separate endpoints with decorators for additional permission requirements
@app.post("/content/posts")
@require_permission("posts:write")
async def create_post(title: str, content: str, current_user: User = Depends(get_current_active_user)):
    """Create post (requires write permission)."""
    return {
        "message": "Post created successfully",
        "post": {"title": title, "content": content},
        "author": current_user.email
    }

@app.delete("/content/posts/{post_id}")
@require_permission("posts:delete")
async def delete_post(post_id: int, current_user: User = Depends(get_current_active_user)):
    """Delete post (requires delete permission)."""
    return {
        "message": f"Post {post_id} deleted successfully",
        "deleted_by": current_user.email
    }


# Include all routers
app.include_router(admin_router)
app.include_router(manager_router)
app.include_router(content_router)


# =============================================================================
# WEBSOCKET WITH AUTHENTICATION
# =============================================================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: Optional[str] = None):
    """WebSocket endpoint with authentication."""
    await websocket.accept()
    
    try:
        # Authenticate WebSocket connection
        if not token:
            await websocket.send_text("❌ Authentication required. Provide token parameter.")
            await websocket.close()
            return
        
        # Validate token
        token_data = await auth_manager.token_validator.validate_token(token)
        if not token_data:
            await websocket.send_text("❌ Invalid token.")
            await websocket.close()
            return
        
        # Get user
        db = next(get_db())
        user = await auth_manager._get_or_create_user(db, token_data)
        if not user or not user.is_active:
            await websocket.send_text("❌ User not found or inactive.")
            await websocket.close()
            return
        
        # Send welcome message
        await websocket.send_text(f"✅ Welcome {user.email}!")
        await websocket.send_text(f"🔑 Your roles: {', '.join([role.name for role in user.roles])}")
        await websocket.send_text(f"🛡️ Your permissions: {', '.join(user.get_permissions())}")
        
        # Keep connection alive and handle messages
        while True:
            data = await websocket.receive_text()
            
            if data == "info":
                await websocket.send_text(f"📊 User info: {user.email} | Roles: {[role.name for role in user.roles]}")
            elif data == "permissions":
                await websocket.send_text(f"🛡️ Permissions: {user.get_permissions()}")
            elif data == "ping":
                await websocket.send_text("🏓 pong")
            else:
                await websocket.send_text(f"📨 Echo: {data}")
                
    except WebSocketDisconnect:
        print("WebSocket disconnected")
    except Exception as e:
        await websocket.send_text(f"❌ Error: {str(e)}")
        await websocket.close()


# =============================================================================
# ADVANCED FEATURES
# =============================================================================

@app.get("/advanced/user-context")
async def user_context_example(request: Request):
    """Example of accessing user from request context (via middleware)."""
    user = getattr(request.state, 'user', None)
    if user:
        return {
            "message": "User found in request context",
            "user": user.email,
            "source": "middleware injection"
        }
    else:
        return {
            "message": "No user in request context",
            "note": "User is injected by RoleMiddleware when authenticated"
        }


@app.post("/advanced/dynamic-permissions")
@require_permission("admin:access")
async def dynamic_permissions(
    user_id: str,
    permission_name: str,
    action: str,  # "grant" or "revoke"
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Dynamically grant or revoke permissions (admin only)."""
    user = db.query(User).filter(User.id == user_id).first()
    permission = db.query(Permission).filter(Permission.name == permission_name).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not permission:
        raise HTTPException(status_code=404, detail="Permission not found")
    
    # Find user's roles that could have this permission
    user_roles = user.roles
    
    if action == "grant":
        # Add permission to user's first role (simplified example)
        if user_roles and permission not in user_roles[0].permissions:
            user_roles[0].permissions.append(permission)
            db.commit()
            return {"message": f"Permission {permission_name} granted to {user.email}"}
    elif action == "revoke":
        # Remove permission from all user's roles
        for role in user_roles:
            if permission in role.permissions:
                role.permissions.remove(permission)
        db.commit()
        return {"message": f"Permission {permission_name} revoked from {user.email}"}
    
    return {"message": "No changes made"}


if __name__ == "__main__":
    import uvicorn
    
    print("\n🚀 Starting FastAuth Comprehensive Example...")
    print("📖 API Documentation: http://localhost:8000/docs")
    print("🔗 Main endpoint: http://localhost:8000/")
    print("🔌 WebSocket test: ws://localhost:8000/ws?token=YOUR_TOKEN")
    print("\n🎯 Available endpoint categories:")
    print("   📁 /auth/*           - User management (login, register, etc.)")
    print("   🔒 /protected        - Basic authentication required")
    print("   🎭 /decorators/*     - Decorator-based access control")
    print("   🔗 /dependencies/*   - Dependency-based access control")
    print("   👑 /admin/*          - Admin router (admin role required)")
    print("   📊 /management/*     - Manager router (manager/admin roles)")
    print("   📝 /content/*        - Content router (permission-based)")
    print("   🚀 /advanced/*       - Advanced features")
    print("   🔌 /ws               - WebSocket with authentication")
    print("\n👤 Demo users:")
    print("   - user@example.com / user123 (basic user)")
    print("   - author@example.com / author123 (content author)")
    print("   - moderator@example.com / mod123 (content moderator)")
    print("   - manager@example.com / manager123 (project manager)")
    print("   - admin@example.com / admin123 (system admin)")
    print("\n💡 Try logging in and testing different endpoints!")
    print("   1. POST /auth/login with demo credentials")
    print("   2. Use the returned token in Authorization header")
    print("   3. Test different endpoints based on your role")
    print("\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)
