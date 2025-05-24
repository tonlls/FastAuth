"""
FastAPI Roles - Demo Application

This is a simple demo showing how to use the fastapi-roles package.
Run this file to see the package in action.
"""

from datetime import timedelta

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

# Import our package components
from fastauth import (
    AuthConfig,
    AuthManager,
    Permission,
    Role,
    RoleRouter,
    User,
    admin_required,
    create_database_manager,
    require_permission,
    require_role,
)

# Create database manager with multi-database support
# You can change this to use different databases:
# - SQLite: create_database_manager("sqlite:///./demo.db")
# - PostgreSQL: create_database_manager("postgresql://user:pass@localhost/fastapi_roles")
# - MySQL: create_database_manager("mysql+pymysql://user:pass@localhost/fastapi_roles")
# - Oracle: create_database_manager("oracle+cx_oracle://user:pass@localhost:1521/?service_name=XE")
# Or use environment variables (see database.py for details)

db_manager = create_database_manager("sqlite:///./demo.db")

# Create all tables
db_manager.create_tables()


def get_db():
    """Database dependency."""
    db = next(db_manager.get_session())
    try:
        yield db
    finally:
        db.close()


# Configure authentication
config = AuthConfig(
    secret_key="demo-secret-key-change-in-production",
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
    title="FastAPI Roles Demo",
    description="Demonstration of the fastapi-roles package",
    version="0.1.0"
)

# Dependencies
get_current_active_user = auth_manager.create_active_user_dependency()


def init_demo_data():
    """Initialize demo data."""
    db_gen = get_db()
    db = next(db_gen)
    
    try:
        # Check if data already exists
        if db.query(User).first():
            return
        
        # Create permissions
        read_perm = Permission(name="read", description="Read access")
        write_perm = Permission(name="write", description="Write access")
        admin_perm = Permission(name="admin", description="Admin access")
        
        db.add(read_perm)
        db.add(write_perm)
        db.add(admin_perm)
        db.commit()
        
        # Create roles
        user_role = Role(name="user", description="Regular user")
        admin_role = Role(name="admin", description="Administrator")
        
        db.add(user_role)
        db.add(admin_role)
        db.commit()
        
        # Assign permissions to roles
        user_role.permissions = [read_perm]
        admin_role.permissions = [read_perm, write_perm, admin_perm]
        db.commit()
        
        # Create demo users
        # Get JWT provider for password hashing
        from fastauth.providers import JWTProvider
        jwt_provider = None
        for provider in auth_manager.providers:
            if isinstance(provider, JWTProvider):
                jwt_provider = provider
                break
        
        if not jwt_provider:
            print("❌ JWT provider not found")
            return
        
        demo_user = User(
            email="user@demo.com",
            username="user",
            hashed_password=jwt_provider.get_password_hash("password"),
            is_verified=True
        )
        demo_user.roles = [user_role]
        
        demo_admin = User(
            email="admin@demo.com",
            username="admin",
            hashed_password=jwt_provider.get_password_hash("admin"),
            is_superuser=True,
            is_verified=True
        )
        demo_admin.roles = [admin_role]
        
        db.add(demo_user)
        db.add(demo_admin)
        db.commit()
        
        print("✅ Demo data initialized!")
        print("👤 Users created:")
        print("   - user@demo.com / password (user role)")
        print("   - admin@demo.com / admin (admin role)")
        
    except Exception as e:
        print(f"❌ Error initializing demo data: {e}")
        db.rollback()
    finally:
        db.close()


# Initialize demo data
init_demo_data()


# Routes
@app.get("/")
async def root():
    """Welcome endpoint."""
    return {
        "message": "Welcome to FastAPI Roles Demo!",
        "docs": "/docs",
        "demo_users": {
            "user": "user@demo.com / password",
            "admin": "admin@demo.com / admin"
        }
    }


@app.post("/login")
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
    
    access_token = auth_manager.create_access_token(
        user=user,
        expires_delta=timedelta(minutes=config.access_token_expire_minutes)
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "email": user.email,
            "roles": [role.name for role in user.roles]
        }
    }


@app.get("/protected")
async def protected_endpoint(current_user: User = Depends(get_current_active_user)):
    """Protected endpoint requiring authentication."""
    return {
        "message": f"Hello {current_user.email}!",
        "roles": [role.name for role in current_user.roles],
        "permissions": current_user.get_permissions()
    }


@app.get("/admin-only")
@admin_required()
async def admin_only(current_user: User = Depends(get_current_active_user)):
    """Admin-only endpoint using decorator."""
    return {
        "message": "Welcome to the admin area!",
        "user": current_user.email
    }


@app.get("/read-data")
@require_permission("read")
async def read_data(current_user: User = Depends(get_current_active_user)):
    """Endpoint requiring read permission."""
    return {
        "message": "Here's some data you can read",
        "data": ["item1", "item2", "item3"],
        "user": current_user.email
    }


@app.post("/write-data")
@require_permission("write")
async def write_data(current_user: User = Depends(get_current_active_user)):
    """Endpoint requiring write permission."""
    return {
        "message": "Data written successfully!",
        "user": current_user.email
    }


# Admin router example
admin_router = RoleRouter(
    auth_manager=auth_manager,
    required_roles=["admin"],
    prefix="/admin",
    tags=["admin"]
)


@admin_router.get("/dashboard")
async def admin_dashboard():
    """Admin dashboard."""
    return {"message": "Admin Dashboard - You have admin access!"}


@admin_router.get("/users")
async def list_users(db: Session = Depends(get_db)):
    """List all users (admin only)."""
    users = db.query(User).all()
    return {
        "users": [
            {
                "email": user.email,
                "username": user.username,
                "roles": [role.name for role in user.roles],
                "is_active": user.is_active
            }
            for user in users
        ]
    }


app.include_router(admin_router)


if __name__ == "__main__":
    import uvicorn
    
    print("\n🚀 Starting FastAPI Roles Demo...")
    print("📖 API Documentation: http://localhost:8000/docs")
    print("🔗 Demo endpoint: http://localhost:8000/")
    print("\n💡 Try these endpoints:")
    print("   GET  /              - Public welcome")
    print("   POST /login         - Login with demo users")
    print("   GET  /protected     - Requires authentication")
    print("   GET  /admin-only    - Requires admin role")
    print("   GET  /read-data     - Requires read permission")
    print("   POST /write-data    - Requires write permission")
    print("   GET  /admin/users   - Admin router example")
    print("\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
