# FastAuth

A comprehensive FastAPI package for role-based access control (RBAC) with support for multiple authentication providers and databases.

## 🚀 Features

- **🔐 Role-Based Access Control**: Complete RBAC system with users, roles, and permissions
- **🗄️ Multi-Database Support**: SQLite, PostgreSQL, MySQL, Oracle with SQLAlchemy 2.0
- **🔑 Multiple Auth Providers**: JWT, Auth0, Firebase, and custom token providers
- **⚡ Modern FastAPI**: Built for async FastAPI applications with full type safety
- **🎯 Flexible Decorators**: Easy-to-use decorators for route protection
- **🛡️ Secure by Default**: Built-in password hashing, token validation, and security best practices
- **📝 Type Safety**: Full type hints and Pydantic models throughout
- **🔧 Easy Integration**: Simple setup with minimal configuration required

## 📦 Installation

### Basic Installation

```bash
pip install FastAuth
```

### Database-Specific Installation

Choose the database driver you need:

```bash
# PostgreSQL
pip install FastAuth[postgres]

# MySQL
pip install FastAuth[mysql]

# Oracle
pip install FastAuth[oracle]

# MongoDB
pip install FastAuth[mongodb]

# All databases
pip install FastAuth[all-databases]
```

### Development Installation

```bash
pip install FastAuth[dev]
```

## 🚀 Quick Start

### 1. Basic Setup

```python
from fastapi import FastAPI, Depends
from fastauth import (
    AuthConfig,
    AuthManager,
    User,
    create_database_manager,
    require_role,
    require_permission,
    admin_required,
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

auth_manager = AuthManager(
    config=config,
    get_db=get_db,
    providers=["jwt"]
)

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

### 3. Authentication Endpoint

```python
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta

@app.post("/login")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db = Depends(get_db)
):
    user = await auth_manager.authenticate_user(
        db, form_data.username, form_data.password
    )
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
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
```

## 🗄️ Database Configuration

### Environment Variables

Configure your database using environment variables:

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

#### SQLite (Default)
```python
db_manager = create_database_manager("sqlite:///./app.db")
```

#### PostgreSQL
```python
db_manager = create_database_manager(
    "postgresql://user:password@localhost/fastauth"
)
```

#### MySQL
```python
db_manager = create_database_manager(
    "mysql+pymysql://user:password@localhost/fastauth"
)
```

#### Oracle
```python
db_manager = create_database_manager(
    "oracle+cx_oracle://user:password@localhost:1521/?service_name=XE"
)
```

## 🔑 Authentication Providers

### JWT Provider (Default)

```python
config = AuthConfig(
    secret_key="your-secret-key",
    algorithm="HS256",
    access_token_expire_minutes=30,
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
)

auth_manager = AuthManager(
    config=config,
    get_db=get_db,
    providers=["firebase"]
)
```

### Multiple Providers

```python
auth_manager = AuthManager(
    config=config,
    get_db=get_db,
    providers=["jwt", "auth0", "firebase"]
)
```

## 🛡️ Role-Based Access Control

### Using Decorators

```python
from fastauth import require_role, require_permission, admin_required

@app.get("/admin")
@admin_required()
async def admin_endpoint():
    return {"message": "Admin only"}

@app.get("/manager")
@require_role("manager")
async def manager_endpoint():
    return {"message": "Manager access"}

@app.get("/read")
@require_permission("read")
async def read_endpoint():
    return {"message": "Read permission required"}

@app.get("/multi-role")
@require_role(["admin", "manager"])
async def multi_role_endpoint():
    return {"message": "Admin or manager access"}
```

### Using Dependencies

```python
# Create role-specific dependencies
require_admin = auth_manager.create_role_dependency("admin")
require_manager = auth_manager.create_role_dependency(["admin", "manager"])

# Create permission-specific dependencies
require_read = auth_manager.create_permission_dependency("read")
require_write = auth_manager.create_permission_dependency(["read", "write"])

@app.get("/admin")
async def admin_endpoint(user: User = Depends(require_admin)):
    return {"message": f"Hello admin {user.email}"}

@app.get("/read-data")
async def read_endpoint(user: User = Depends(require_read)):
    return {"data": "sensitive information"}
```

### Role-Protected Routers

```python
from fastauth import RoleRouter

# Create a router that requires admin role for all routes
admin_router = RoleRouter(
    auth_manager=auth_manager,
    required_roles=["admin"],
    prefix="/admin",
    tags=["admin"]
)

@admin_router.get("/dashboard")
async def admin_dashboard():
    return {"message": "Admin dashboard"}

@admin_router.get("/users")
async def list_users():
    return {"users": []}

app.include_router(admin_router)
```

## 👥 User Management

### Creating Users

```python
from fastauth import UserCreate

@app.post("/register")
@require_permission("users:write")
async def create_user(
    user_data: UserCreate,
    db = Depends(get_db)
):
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
```

### Managing Roles and Permissions

```python
from fastauth import Role, Permission

# Create roles and permissions
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

# Assign roles to users
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

## 🔧 Advanced Configuration

### Custom Database Configuration

```python
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

### Middleware Setup

```python
from fastauth import setup_role_middleware

# Automatically inject user information into requests
setup_role_middleware(app, auth_manager)
```

### Custom Token Validation

```python
from fastauth import TokenValidator

# Create custom token validator
token_validator = TokenValidator(auth_manager)

@app.middleware("http")
async def custom_auth_middleware(request, call_next):
    # Custom authentication logic
    token = request.headers.get("Authorization")
    if token:
        user = await token_validator.validate_token(token)
        request.state.user = user
    
    response = await call_next(request)
    return response
```

## 📚 Examples

### Complete Working Example

Check out our example applications:

- **[Basic App](examples/basic_app.py)**: Complete FastAPI application with authentication and RBAC
- **[User Management](examples/user_management_example.py)**: Advanced user management features
- **[Demo App](main.py)**: Simple demo showing core functionality

### Running the Demo

```bash
# Clone the repository
git clone https://github.com/your-repo/fastauth.git
cd fastauth

# Install dependencies
pip install -e .[dev]

# Run the demo
python main.py
```

The demo includes:
- 🗄️ SQLite database (easily configurable for other databases)
- 👤 Demo users: `user@demo.com/password` and `admin@demo.com/admin`
- 🔒 Protected endpoints demonstrating role and permission-based access
- 📖 Interactive API documentation at `http://localhost:8000/docs`

## 🔍 API Reference

### Core Classes

- **`AuthManager`**: Main authentication and authorization manager
- **`AuthConfig`**: Configuration for authentication settings
- **`User`**: User model with roles and permissions
- **`Role`**: Role model with associated permissions
- **`Permission`**: Permission model for fine-grained access control
- **`RoleRouter`**: FastAPI router with built-in role protection

### Decorators

- **`@admin_required()`**: Requires admin role
- **`@require_role(roles)`**: Requires specific role(s)
- **`@require_permission(permissions)`**: Requires specific permission(s)
- **`@require_user()`**: Requires authenticated user

### Database Utilities

- **`create_database_manager(url)`**: Create database manager with URL
- **`DatabaseManager`**: Advanced database configuration and management
- **`Base`**: SQLAlchemy declarative base for models

## 🧪 Testing

```bash
# Run tests
pytest

# Run tests with coverage
pytest --cov=fastauth --cov-report=html

# Run specific test file
pytest tests/test_auth.py
```

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

## 📈 Changelog

### Version 0.1.0 (Current)

**🎉 Initial Release**

- ✅ Complete RBAC system with users, roles, and permissions
- ✅ Multi-database support (SQLite, PostgreSQL, MySQL, Oracle)
- ✅ JWT, Auth0, and Firebase authentication providers
- ✅ FastAPI decorators and dependencies for route protection
- ✅ Role-protected routers
- ✅ SQLAlchemy 2.0 support with modern async patterns
- ✅ Comprehensive type safety with Pydantic models
- ✅ Example applications and documentation

---

**Made with ❤️ for the FastAPI community**
