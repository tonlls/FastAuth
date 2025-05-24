"""
Example demonstrating how to use the FastAPI Roles user management endpoints.

This example shows how to:
1. Set up a FastAPI app with user management endpoints
2. Create users, roles, and permissions
3. Use the authentication endpoints
4. Protect routes with role-based access control
"""

from fastapi import FastAPI, Depends
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from fastauth import (
    AuthManager,
    AuthConfig,
    DatabaseConfig,
    create_database_manager,
    User,
    Role,
    Permission,
    UserManagementRouter,
    Base,
    create_user_management_router,
    UserResponse,
)

# Database setup
DATABASE_URL = "sqlite:///./user_management_example.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create tables
Base.metadata.create_all(bind=engine)

# Database dependency
def get_db():
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
    refresh_token_expire_days=7,
)

# Create auth manager
auth_manager = AuthManager(config, get_db)

# Create FastAPI app
app = FastAPI(
    title="User Management Example",
    description="Example showing FastAPI Roles user management endpoints",
    version="1.0.0"
)

# Include user management router
user_router = create_user_management_router(
    auth_manager=auth_manager,
    get_db=get_db,
    prefix="/auth",
    tags=["Authentication"],
    enable_registration=True,
    enable_password_reset=True,
    require_email_verification=False,
    default_user_role="user"
)
app.include_router(user_router)

# Example protected routes
@app.get("/protected", dependencies=[Depends(auth_manager.create_active_user_dependency())])
async def protected_route():
    """A route that requires authentication."""
    return {"message": "This is a protected route"}

@app.get("/admin-only", dependencies=[Depends(auth_manager.create_superuser_dependency())])
async def admin_only_route():
    """A route that requires admin privileges."""
    return {"message": "This is an admin-only route"}

@app.get("/moderator-only", dependencies=[Depends(auth_manager.create_role_dependency("moderator"))])
async def moderator_only_route():
    """A route that requires moderator role."""
    return {"message": "This is a moderator-only route"}

@app.get("/users/me/profile")
async def get_my_profile(
    current_user: User = Depends(auth_manager.create_active_user_dependency())
) -> UserResponse:
    """Get current user's profile with dependency injection."""
    return UserResponse.model_validate(current_user)

# Startup event to create initial data
@app.on_event("startup")
async def create_initial_data():
    """Create initial roles and admin user."""
    db = next(get_db())
    
    # Create roles if they don't exist
    roles_to_create = [
        {"name": "admin", "description": "Administrator role"},
        {"name": "moderator", "description": "Moderator role"},
        {"name": "user", "description": "Regular user role"},
    ]
    
    for role_data in roles_to_create:
        existing_role = db.query(Role).filter(Role.name == role_data["name"]).first()
        if not existing_role:
            role = Role(**role_data)
            db.add(role)
    
    # Create permissions if they don't exist
    permissions_to_create = [
        {"name": "read_users", "description": "Read user information"},
        {"name": "write_users", "description": "Create and update users"},
        {"name": "delete_users", "description": "Delete users"},
        {"name": "manage_roles", "description": "Manage roles and permissions"},
    ]
    
    for perm_data in permissions_to_create:
        existing_perm = db.query(Permission).filter(Permission.name == perm_data["name"]).first()
        if not existing_perm:
            permission = Permission(**perm_data)
            db.add(permission)
    
    db.commit()
    
    # Assign permissions to roles
    admin_role = db.query(Role).filter(Role.name == "admin").first()
    moderator_role = db.query(Role).filter(Role.name == "moderator").first()
    
    if admin_role:
        # Admin gets all permissions
        all_permissions = db.query(Permission).all()
        for permission in all_permissions:
            if permission not in admin_role.permissions:
                admin_role.permissions.append(permission)
    
    if moderator_role:
        # Moderator gets read and write permissions
        read_perm = db.query(Permission).filter(Permission.name == "read_users").first()
        write_perm = db.query(Permission).filter(Permission.name == "write_users").first()
        
        if read_perm and read_perm not in moderator_role.permissions:
            moderator_role.permissions.append(read_perm)
        if write_perm and write_perm not in moderator_role.permissions:
            moderator_role.permissions.append(write_perm)
    
    db.commit()
    
    # Create admin user if it doesn't exist
    admin_email = "admin@example.com"
    existing_admin = db.query(User).filter(User.email == admin_email).first()
    
    if not existing_admin:
        from fastauth.providers import JWTProvider
        
        # Get JWT provider for password hashing
        jwt_provider = None
        for provider in auth_manager.providers:
            if isinstance(provider, JWTProvider):
                jwt_provider = provider
                break
        
        if jwt_provider:
            admin_user = User(
                email=admin_email,
                username="admin",
                hashed_password=jwt_provider.get_password_hash("admin123"),
                first_name="Admin",
                last_name="User",
                is_active=True,
                is_verified=True,
                is_superuser=True,
                auth_provider="local"
            )
            
            db.add(admin_user)
            db.commit()
            db.refresh(admin_user)
            
            # Assign admin role
            if admin_role:
                admin_user.roles.append(admin_role)
                db.commit()
            
            print(f"Created admin user: {admin_email} / admin123")
    
    db.close()

if __name__ == "__main__":
    import uvicorn
    
    print("Starting User Management Example Server...")
    print("Available endpoints:")
    print("- POST /auth/register - Register a new user")
    print("- POST /auth/login - Login with email/username and password")
    print("- POST /auth/refresh - Refresh access token")
    print("- GET /auth/me - Get current user profile")
    print("- PUT /auth/me - Update current user profile")
    print("- POST /auth/change-password - Change password")
    print("- POST /auth/reset-password - Request password reset")
    print("- POST /auth/reset-password/confirm - Confirm password reset")
    print("- GET /auth/users - List all users (admin only)")
    print("- GET /auth/users/{user_id} - Get user by ID (admin only)")
    print("- PUT /auth/users/{user_id} - Update user by ID (admin only)")
    print("- DELETE /auth/users/{user_id} - Delete user by ID (admin only)")
    print("- GET /protected - Protected route (requires authentication)")
    print("- GET /admin-only - Admin only route")
    print("- GET /moderator-only - Moderator only route")
    print("- GET /users/me/profile - Get profile with dependency injection")
    print("\nAdmin credentials: admin@example.com / admin123")
    print("API docs available at: http://localhost:8000/docs")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)
