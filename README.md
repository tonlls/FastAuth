# FastAuth 🔐

A comprehensive FastAPI package for role-based access control (RBAC) with support for multiple authentication providers and databases.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.68+-green.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ✨ Features

- **🔐 Complete RBAC System**: Users, roles, and permissions with fine-grained access control
- **🗄️ Multi-Database Support**: SQLite, PostgreSQL, MySQL, Oracle with SQLAlchemy 2.0
- **🔑 Multiple Auth Providers**: JWT, Auth0, Firebase, and custom token providers
- **⚡ Modern FastAPI**: Built for async FastAPI applications with full type safety
- **🎯 Flexible Access Control**: Decorators, dependencies, middleware, and protected routers
- **🛡️ Secure by Default**: Built-in password hashing, token validation, and security best practices
- **📝 Type Safety**: Full type hints and Pydantic models throughout
- **🔧 Easy Integration**: Simple setup with minimal configuration required
- **🚀 Production Ready**: Comprehensive user management endpoints and middleware

## 📦 Installation

### Basic Installation
```bash
pip install fastauth
```

### Database-Specific Installation
```bash
# PostgreSQL
pip install fastauth[postgres]

# MySQL
pip install fastauth[mysql]

# Oracle
pip install fastauth[oracle]

# All databases
pip install fastauth[all-databases]

# Development
pip install fastauth[dev]
```

## 🚀 Quick Start

### 1. Basic Setup

```python
from fastapi import FastAPI, Depends
from fastauth import (
    AuthConfig, AuthManager, User, create_database_manager,
    require_role, require_permission, admin_required
)

# Database setup
db_manager = create_database_manager("sqlite:///./app.db")
db_manager.create_tables()

def get_db():
    return next(db_manager.get_session())

# Auth configuration
config = AuthConfig(
    secret_key="your-secret-key-change-in-production",
    algorithm="HS256",
    access_token_expire_minutes=30,
)

auth_manager = AuthManager(config=config, get_db=get_db, providers=["jwt"])
app = FastAPI()

# Create dependencies
get_current_user = auth_manager.create_active_user_dependency()
```

### 2. Protected Routes

```python
@app.get("/protected")
async def protected_route(current_user: User = Depends(get_current_user)):
    return {"message": f"Hello {current_user.email}!"}

@app.get("/admin-only")
@admin_required()
async def admin_route(current_user: User = Depends(get_current_user)):
    return {"message": "Admin access granted"}

@app.get("/read-data")
@require_permission("read")
async def read_route(current_user: User = Depends(get_current_user)):
    return {"data": "sensitive information"}

@app.get("/manager-or-admin")
@require_role(["manager", "admin"])
async def multi_role_route(current_user: User = Depends(get_current_user)):
    return {"message": "Manager or admin access"}
```

### 3. Complete Authentication System

```python
from fastauth import create_user_management_router

# Add complete user management endpoints
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
```

## 🎯 Access Control Methods

FastAuth provides multiple ways to control access to your endpoints:

### 1. Decorators (Simple & Clean)

```python
from fastauth import (
    admin_required, require_role, require_permission, 
    require_user, require_superuser, require_all_roles,
    require_all_permissions, verified_required
)

@app.get("/admin")
@admin_required()
async def admin_endpoint():
    return {"message": "Admin only"}

@app.get("/manager")
@require_role("manager")
async def manager_endpoint():
    return {"message": "Manager access"}

@app.get("/multi-role")
@require_role(["admin", "manager"])  # Any of these roles
async def multi_role_endpoint():
    return {"message": "Admin or manager access"}

@app.get("/all-roles")
@require_all_roles(["admin", "security"])  # Must have ALL roles
async def all_roles_endpoint():
    return {"message": "Admin AND security roles required"}

@app.get("/read")
@require_permission("read")
async def read_endpoint():
    return {"message": "Read permission required"}

@app.get("/multi-permission")
@require_permission(["read", "write"])  # Any of these permissions
async def multi_permission_endpoint():
    return {"message": "Read or write permission"}

@app.get("/all-permissions")
@require_all_permissions(["read", "write", "admin"])  # Must have ALL permissions
async def all_permissions_endpoint():
    return {"message": "All permissions required"}

@app.get("/verified")
@verified_required()
async def verified_endpoint():
    return {"message": "Verified users only"}

@app.get("/superuser")
@require_superuser()
async def superuser_endpoint():
    return {"message": "Superuser only"}
```

### 2. Dependencies (Flexible & Reusable)

```python
# Create reusable dependencies
require_admin = auth_manager.create_role_dependency("admin")
require_manager = auth_manager.create_role_dependency(["admin", "manager"])
require_read = auth_manager.create_permission_dependency("read")
require_write = auth_manager.create_permission_dependency(["read", "write"])

@app.get("/admin")
async def admin_endpoint(user: User = Depends(require_admin)):
    return {"message": f"Hello admin {user.email}"}

@app.get("/read-data")
async def read_endpoint(user: User = Depends(require_read)):
    return {"data": "sensitive information"}
```

### 3. Protected Routers (Group Protection)

```python
from fastauth import RoleRouter, AdminRouter, ModeratorRouter

# Create a router that requires admin role for ALL routes
admin_router = AdminRouter(
    auth_manager=auth_manager,
    prefix="/admin",
    tags=["admin"]
)

@admin_router.get("/dashboard")
async def admin_dashboard():
    return {"message": "Admin dashboard"}

@admin_router.get("/users")
async def list_users():
    return {"users": []}

# Custom role router
manager_router = RoleRouter(
    auth_manager=auth_manager,
    required_roles=["manager", "admin"],
    prefix="/management",
    tags=["management"]
)

@manager_router.get("/reports")
async def reports():
    return {"reports": []}

# Permission-based router
read_router = RoleRouter(
    auth_manager=auth_manager,
    required_permissions=["read"],
    prefix="/data",
    tags=["data"]
)

@read_router.get("/sensitive")
async def sensitive_data():
    return {"data": "classified"}

app.include_router(admin_router)
app.include_router(manager_router)
app.include_router(read_router)
```

### 4. Middleware (Application-Wide Protection)

```python
from fastauth import (
    setup_role_middleware, setup_authentication_middleware,
    setup_role_requirement_middleware, setup_permission_requirement_middleware
)

# Auto-inject user information into all requests
setup_role_middleware(app, auth_manager)

# Require authentication for all routes (except excluded paths)
setup_authentication_middleware(
    app, 
    auth_manager, 
    exclude_paths=["/", "/login", "/register", "/docs", "/openapi.json"]
)

# Require specific roles for all routes
setup_role_requirement_middleware(
    app,
    auth_manager,
    required_roles=["user"],
    exclude_paths=["/", "/login", "/register"]
)

# Require specific permissions for all routes
setup_permission_requirement_middleware(
    app,
    auth_manager,
    required_permissions=["read"],
    exclude_paths=["/", "/login", "/register"]
)
```

## 🗄️ Database Configuration

### Environment Variables

```bash
# Option 1: Full database URL
export DATABASE_URL="postgresql://user:password@localhost/fastauth"

# Option 2: Individual components
export DB_TYPE="postgresql"
export DB_HOST="localhost"
export DB_PORT="5432"
export DB_NAME="fastauth"
export DB_USER="user"
export DB_PASSWORD="password"
```

### Supported Databases

```python
# SQLite (Default)
db_manager = create_database_manager("sqlite:///./app.db")

# PostgreSQL
db_manager = create_database_manager(
    "postgresql://user:password@localhost/fastauth"
)

# MySQL
db_manager = create_database_manager(
    "mysql+pymysql://user:password@localhost/fastauth"
)

# Oracle
db_manager = create_database_manager(
    "oracle+cx_oracle://user:password@localhost:1521/?service_name=XE"
)

# Advanced configuration
from fastauth import DatabaseConfig, DatabaseManager

config = DatabaseConfig(
    database_url="postgresql://user:pass@localhost/db",
    pool_size=10,
    max_overflow=20,
    pool_timeout=30,
    pool_recycle=3600,
    echo=True  # Enable SQL logging
)

db_manager = DatabaseManager(config)
db_manager.initialize()
```

## 🔑 Authentication Providers

### JWT Provider (Default)

```python
config = AuthConfig(
    secret_key="your-secret-key",
    algorithm="HS256",
    access_token_expire_minutes=30,
    refresh_token_expire_days=7,
    password_reset_expire_minutes=15,
)

auth_manager = AuthManager(
    config=config,
    get_db=get_db,
    providers=["jwt"]
)
```

### Auth0 Provider

```python
config = AuthConfig(
    auth0_domain="your-domain.auth0.com",
    auth0_client_id="your-client-id",
    auth0_client_secret="your-client-secret",
    auth0_audience="your-api-identifier",
)

auth_manager = AuthManager(
    config=config,
    get_db=get_db,
    providers=["auth0"]
)
```

### Firebase Provider

```python
config = AuthConfig(
    firebase_project_id="your-project-id",
    firebase_credentials_path="path/to/service-account.json",
)

auth_manager = AuthManager(
    config=config,
    get_db=get_db,
    providers=["firebase"]
)
```

### Custom Provider

```python
from fastauth.providers import BaseAuthProvider

class MyCustomProvider(BaseAuthProvider):
    async def validate_token(self, token: str) -> Optional[TokenData]:
        # Your custom token validation logic
        pass
    
    async def get_user_info(self, token_data: TokenData) -> Optional[Dict[str, Any]]:
        # Your custom user info retrieval logic
        pass

# Register custom provider
auth_manager = AuthManager(
    config=config,
    get_db=get_db,
    providers=["jwt", "custom"]
)
```

### Multiple Providers

```python
# Support multiple authentication methods
auth_manager = AuthManager(
    config=config,
    get_db=get_db,
    providers=["jwt", "auth0", "firebase"]
)
```

## 👥 User Management

### Complete User Management Endpoints

The `create_user_management_router` provides a full set of endpoints:

```python
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
```

**Available Endpoints:**
- `POST /auth/register` - Register a new user
- `POST /auth/login` - Login with email/username and password
- `POST /auth/refresh` - Refresh access token
- `GET /auth/me` - Get current user profile
- `PUT /auth/me` - Update current user profile
- `POST /auth/change-password` - Change password
- `POST /auth/reset-password` - Request password reset
- `POST /auth/reset-password/confirm` - Confirm password reset
- `GET /auth/users` - List all users (admin only)
- `GET /auth/users/{user_id}` - Get user by ID (admin only)
- `PUT /auth/users/{user_id}` - Update user by ID (admin only)
- `DELETE /auth/users/{user_id}` - Delete user by ID (admin only)

### Manual User Management

```python
from fastauth import UserCreate, User, Role, Permission

@app.post("/register")
async def create_user(user_data: UserCreate, db = Depends(get_db)):
    # Get JWT provider for password hashing
    jwt_provider = auth_manager.get_provider("jwt")
    
    new_user = User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=jwt_provider.get_password_hash(user_data.password),
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        is_active=True,
        is_verified=False
    )
    
    db.add(new_user)
    db.commit()
    
    return {"message": "User created successfully"}

@app.post("/admin/roles")
@admin_required()
async def create_role(role_data: dict, db = Depends(get_db)):
    role = Role(
        name=role_data["name"],
        description=role_data["description"]
    )
    db.add(role)
    db.commit()
    return {"message": "Role created"}

@app.post("/admin/permissions")
@admin_required()
async def create_permission(perm_data: dict, db = Depends(get_db)):
    permission = Permission(
        name=perm_data["name"],
        description=perm_data["description"]
    )
    db.add(permission)
    db.commit()
    return {"message": "Permission created"}

@app.post("/admin/users/{user_id}/roles/{role_id}")
@admin_required()
async def assign_role(user_id: str, role_id: str, db = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    role = db.query(Role).filter(Role.id == role_id).first()
    
    if user and role:
        user.roles.append(role)
        db.commit()
        return {"message": "Role assigned"}
    
    raise HTTPException(status_code=404, detail="User or role not found")
```

## 🔧 Advanced Features

### Custom Token Validation

```python
from fastauth import TokenValidator

# Create custom token validator
token_validator = TokenValidator(auth_manager.providers)

@app.middleware("http")
async def custom_auth_middleware(request, call_next):
    token = request.headers.get("Authorization")
    if token:
        user = await token_validator.validate_token(token.replace("Bearer ", ""))
        request.state.user = user
    
    response = await call_next(request)
    return response
```

### Role-Based CORS

```python
from fastauth.middleware import CORSRoleMiddleware

app.add_middleware(
    CORSRoleMiddleware,
    auth_manager=auth_manager,
    allowed_origins=["http://localhost:3000"],
    role_based_origins={
        "admin": ["http://admin.example.com"],
        "manager": ["http://manager.example.com"]
    },
    allow_credentials=True
)
```

### Dynamic Role Assignment

```python
@app.post("/promote-user/{user_id}")
@require_permission("users:promote")
async def promote_user(
    user_id: str, 
    new_role: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    role = db.query(Role).filter(Role.name == new_role).first()
    
    if user and role:
        user.roles.append(role)
        db.commit()
        return {"message": f"User promoted to {new_role}"}
    
    raise HTTPException(status_code=404, detail="User or role not found")
```

### WebSocket Authentication

```python
from fastapi import WebSocket, WebSocketDisconnect

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = None):
    await websocket.accept()
    
    # Authenticate WebSocket connection
    if token:
        token_data = await auth_manager.token_validator.validate_token(token)
        if token_data:
            user = await auth_manager._get_or_create_user(next(get_db()), token_data)
            if user and user.is_active:
                await websocket.send_text(f"Welcome {user.email}!")
                # Continue with authenticated WebSocket logic
                return
    
    await websocket.send_text("Authentication required")
    await websocket.close()
```

## 📚 Complete Examples

### 1. Basic Application

```python
from fastapi import FastAPI, Depends
from fastauth import *

# Setup
db_manager = create_database_manager("sqlite:///./app.db")
db_manager.create_tables()

config = AuthConfig(secret_key="your-secret-key")
auth_manager = AuthManager(config, lambda: next(db_manager.get_session()))
app = FastAPI()

# Add user management
auth_router = create_user_management_router(auth_manager, lambda: next(db_manager.get_session()))
app.include_router(auth_router)

# Protected routes
@app.get("/protected")
async def protected(user: User = Depends(auth_manager.create_active_user_dependency())):
    return {"user": user.email}

@app.get("/admin")
@admin_required()
async def admin_only(user: User = Depends(auth_manager.create_active_user_dependency())):
    return {"message": "Admin access"}
```

### 2. Multi-Database Enterprise App

```python
import os
from fastapi import FastAPI
from fastauth import *

# Environment-based database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:pass@localhost/app")
db_manager = create_database_manager(DATABASE_URL)

# Production configuration
config = AuthConfig(
    secret_key=os.getenv("SECRET_KEY"),
    algorithm="HS256",
    access_token_expire_minutes=30,
    refresh_token_expire_days=7,
    auth0_domain=os.getenv("AUTH0_DOMAIN"),
    auth0_client_id=os.getenv("AUTH0_CLIENT_ID"),
    firebase_project_id=os.getenv("FIREBASE_PROJECT_ID"),
)

# Multi-provider authentication
auth_manager = AuthManager(
    config=config,
    get_db=lambda: next(db_manager.get_session()),
    providers=["jwt", "auth0", "firebase"]
)

app = FastAPI(title="Enterprise App")

# Global authentication middleware
setup_authentication_middleware(
    app, 
    auth_manager, 
    exclude_paths=["/", "/health", "/docs", "/openapi.json"]
)

# Role-based routers
admin_router = AdminRouter(auth_manager, prefix="/admin")
manager_router = RoleRouter(auth_manager, required_roles=["manager"], prefix="/management")

app.include_router(admin_router)
app.include_router(manager_router)
```

### 3. Microservice with Custom Permissions

```python
from fastapi import FastAPI
from fastauth import *

# Custom permissions for microservice
PERMISSIONS = [
    "orders:read", "orders:write", "orders:delete",
    "inventory:read", "inventory:write",
    "reports:generate", "reports:view"
]

app = FastAPI(title="Order Management Service")
auth_manager = AuthManager(config, get_db, providers=["jwt"])

# Permission-specific endpoints
@app.get("/orders")
@require_permission("orders:read")
async def list_orders(user: User = Depends(auth_manager.create_active_user_dependency())):
    return {"orders": []}

@app.post("/orders")
@require_permission("orders:write")
async def create_order(user: User = Depends(auth_manager.create_active_user_dependency())):
    return {"message": "Order created"}

@app.delete("/orders/{order_id}")
@require_permission("orders:delete")
async def delete_order(order_id: str, user: User = Depends(auth_manager.create_active_user_dependency())):
    return {"message": "Order deleted"}

# Reports require multiple permissions
@app.get("/reports/sales")
@require_all_permissions(["reports:generate", "reports:view", "orders:read"])
async def sales_report(user: User = Depends(auth_manager.create_active_user_dependency())):
    return {"report": "sales data"}
```

## 🧪 Testing

```python
import pytest
from fastapi.testclient import TestClient
from fastauth import AuthManager, AuthConfig

@pytest.fixture
def auth_manager():
    config = AuthConfig(secret_key="test-secret")
    return AuthManager(config, get_test_db)

@pytest.fixture
def client(auth_manager):
    app = create_test_app(auth_manager)
    return TestClient(app)

def test_protected_endpoint_requires_auth(client):
    response = client.get("/protected")
    assert response.status_code == 401

def test_admin_endpoint_requires_admin_role(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.get("/admin", headers=headers)
    assert response.status_code == 200

def test_permission_based_access(client, user_with_read_permission):
    token = create_token_for_user(user_with_read_permission)
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/read-data", headers=headers)
    assert response.status_code == 200
```

## 🚀 Running the Demo

```bash
# Clone and install
git clone https://github.com/your-repo/fastauth.git
cd fastauth
pip install -e .[dev]

# Run the demo
python main.py
```

**Demo Features:**
- 🗄️ SQLite database (easily configurable for other databases)
- 👤 Demo users: `user@demo.com/password` and `admin@demo.com/admin`
- 🔒 Protected endpoints demonstrating all access control methods
- 📖 Interactive API documentation at `http://localhost:8000/docs`
- 🎯 Examples of decorators, dependencies, routers, and middleware

## 📖 API Reference

### Core Classes

| Class | Description |
|-------|-------------|
| `AuthManager` | Main authentication and authorization manager |
| `AuthConfig` | Configuration for authentication settings |
| `User` | User model with roles and permissions |
| `Role` | Role model with associated permissions |
| `Permission` | Permission model for fine-grained access control |
| `RoleRouter` | FastAPI router with built-in role protection |

### Decorators

| Decorator | Description |
|-----------|-------------|
| `@admin_required()` | Requires admin role |
| `@require_role(roles)` | Requires specific role(s) |
| `@require_permission(permissions)` | Requires specific permission(s) |
| `@require_user()` | Requires authenticated user |
| `@require_superuser()` | Requires superuser |
| `@require_all_roles(roles)` | Requires ALL specified roles |
| `@require_all_permissions(permissions)` | Requires ALL specified permissions |
| `@verified_required()` | Requires verified user |

### Routers

| Router | Description |
|--------|-------------|
| `RoleRouter` | Base router with role/permission protection |
| `AdminRouter` | Router requiring admin role |
| `ModeratorRouter` | Router requiring moderator role |
| `SuperuserRouter` | Router requiring superuser |
| `VerifiedRouter` | Router requiring verified users |

### Middleware

| Middleware | Description |
|------------|-------------|
| `RoleMiddleware` | Auto-inject user information |
| `AuthenticationMiddleware` | Require authentication |
| `RequireRoleMiddleware` | Require specific roles |
| `RequirePermissionMiddleware` | Require specific permissions |
| `CORSRoleMiddleware` | Role-based CORS handling |

### Providers

| Provider | Description |
|----------|-------------|
| `JWTProvider` | Local JWT token authentication |
| `Auth0Provider` | Auth0 integration |
| `FirebaseProvider` | Firebase authentication |
| `CustomTokenProvider` | Custom token validation |

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for your changes
5. Ensure all tests pass (`pytest`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- 📖 **Documentation**: Check out our [examples](examples/) and [API documentation](http://localhost:8000/docs) when running the demo
- 🐛 **Bug Reports**: [Open an issue](https://github.com/your-repo/fastauth/issues) on GitHub
- 💬 **Discussions**: [GitHub Discussions](https://github.com/your-repo/fastauth/discussions) for questions and ideas
- 📧 **Email**: Contact us at support@fastauth.dev

## 🗺️ Roadmap

- [ ] **OAuth2 Providers**: Google, GitHub, Microsoft authentication
- [ ] **Session Management**: Redis-based session storage
- [ ] **Rate Limiting**: Built-in rate limiting for authentication endpoints
- [ ] **Audit Logging**: Comprehensive audit trail for security events
- [ ] **Multi-tenancy**: Support for multi-tenant applications
- [ ] **GraphQL Support**: GraphQL integration for role-based queries
- [ ] **CLI Tools**: Command-line tools for user and role management
- [ ] **Admin Dashboard**: Web-based admin interface

---

**Made with ❤️ for the FastAPI community**

*FastAuth - Secure, Flexible, Production-Ready Authentication for FastAPI*
