# FastAPI Roles

A comprehensive FastAPI package for role-based access control with support for multiple authentication providers and databases.

## Features

- **SQLAlchemy 2.0 Support**: Fully migrated to SQLAlchemy 2.0 with modern syntax
- **Multi-Database Support**: SQLite, PostgreSQL, MySQL, Oracle, and MongoDB support
- **Role-Based Access Control**: Comprehensive RBAC with users, roles, and permissions
- **Multiple Auth Providers**: JWT, Auth0, Firebase, and custom token providers
- **Flexible Architecture**: Easy to integrate and customize
- **Type Safety**: Full type hints and Pydantic models
- **Async Support**: Built for modern async FastAPI applications

## Installation

### Basic Installation

```bash
pip install fastapi-roles
```

### Database-Specific Installation

Choose the database driver you need:

```bash
# SQLite (included with Python)
pip install fastapi-roles[sqlite]

# PostgreSQL
pip install fastapi-roles[postgres]

# MySQL
pip install fastapi-roles[mysql]

# Oracle
pip install fastapi-roles[oracle]

# MongoDB
pip install fastapi-roles[mongodb]

# All databases
pip install fastapi-roles[all-databases]
```

### Development Installation

```bash
pip install fastapi-roles[dev]
```

## Quick Start

### 1. Database Setup

FastAPI Roles now supports multiple databases with automatic configuration:

```python
from fastauth import create_database_manager

# SQLite (default)
db_manager = create_database_manager("sqlite:///./app.db")

# PostgreSQL
db_manager = create_database_manager(
    "postgresql://user:password@localhost/fastapi_roles"
)

# MySQL
db_manager = create_database_manager(
    "mysql+pymysql://user:password@localhost/fastapi_roles"
)

# Oracle
db_manager = create_database_manager(
    "oracle+cx_oracle://user:password@localhost:1521/?service_name=XE"
)

# Or use environment variables
db_manager = create_database_manager()  # Uses DATABASE_URL or DB_* env vars
```

### 2. Environment Configuration

You can configure the database using environment variables:

```bash
# Option 1: Full database URL
export DATABASE_URL="postgresql://user:password@localhost/fastapi_roles"

# Option 2: Individual components
export DB_TYPE="postgresql"
export DB_HOST="localhost"
export DB_PORT="5432"
export DB_NAME="fastapi_roles"
export DB_USER="user"
export DB_PASSWORD="password"
```

### 3. Basic Application Setup

```python
from fastapi import FastAPI, Depends
from fastauth import (
    AuthConfig,
    AuthManager,
    User,
    create_database_manager,
    require_role,
    require_permission,
)

# Database setup
db_manager = create_database_manager("sqlite:///./app.db")
db_manager.create_tables()

def get_db():
    return next(db_manager.get_session())

# Auth configuration
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

app = FastAPI()

# Dependencies
get_current_user = auth_manager.create_active_user_dependency()

@app.get("/protected")
async def protected_route(current_user: User = Depends(get_current_user)):
    return {"message": f"Hello {current_user.email}!"}

@app.get("/admin-only")
@require_role("admin")
async def admin_route(current_user: User = Depends(get_current_user)):
    return {"message": "Admin access granted"}

@app.get("/read-data")
@require_permission("read")
async def read_route(current_user: User = Depends(get_current_user)):
    return {"data": "sensitive information"}
```

## Database Migration from SQLAlchemy 1.x

If you're upgrading from a previous version, here are the key changes:

### 1. Import Changes

```python
# Old (SQLAlchemy 1.x)
from fastauth import Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# New (SQLAlchemy 2.0)
from fastauth import create_database_manager, Base
```

### 2. Database Setup Changes

```python
# Old
engine = create_engine("sqlite:///./app.db")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# New
db_manager = create_database_manager("sqlite:///./app.db")
db_manager.create_tables()

def get_db():
    return next(db_manager.get_session())
```

### 3. Model Changes

The models now use SQLAlchemy 2.0 syntax with proper type annotations:

```python
# Old
class User(Base):
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    email = Column(String(255), unique=True, index=True, nullable=False)

# New
class User(Base):
    __tablename__ = "users"
    
    id: Mapped[str] = mapped_column(GUID(), primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
```

## Database Support

### SQLite

SQLite is the default database and requires no additional dependencies:

```python
from fastauth import sqlite_url, create_database_manager

db_manager = create_database_manager(sqlite_url("./app.db"))
```

### PostgreSQL

```python
from fastauth import postgresql_url, create_database_manager

db_manager = create_database_manager(
    postgresql_url(
        host="localhost",
        port=5432,
        database="fastapi_roles",
        username="postgres",
        password="password"
    )
)
```

### MySQL

```python
from fastauth import mysql_url, create_database_manager

db_manager = create_database_manager(
    mysql_url(
        host="localhost",
        port=3306,
        database="fastapi_roles",
        username="root",
        password="password"
    )
)
```

### Oracle

```python
from fastauth import oracle_url, create_database_manager

db_manager = create_database_manager(
    oracle_url(
        host="localhost",
        port=1521,
        service_name="XE",
        username="fastapi_roles",
        password="password"
    )
)
```

## Authentication Providers

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

## Role-Based Access Control

### Decorators

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

### Dependencies

```python
# Role-based dependency
require_admin = auth_manager.create_role_dependency("admin")
require_manager = auth_manager.create_role_dependency(["admin", "manager"])

# Permission-based dependency
require_read = auth_manager.create_permission_dependency("read")
require_write = auth_manager.create_permission_dependency(["read", "write"])

@app.get("/admin")
async def admin_endpoint(user: User = Depends(require_admin)):
    return {"message": f"Hello admin {user.email}"}
```

### Router-Level Protection

```python
from fastauth import RoleRouter

# Create a router that requires admin role
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

## Database Information

You can get information about your database configuration:

```python
db_info = db_manager.get_database_info()
print(f"Database type: {db_info['database_type']}")
print(f"Dialect: {db_info['dialect']}")
print(f"Driver: {db_info['driver']}")
```

## Advanced Configuration

### Custom Database Types

The package uses custom database types that work across all supported databases:

- `GUID()`: UUID type that works on all databases
- `JSON()`: JSON type with fallback to TEXT for unsupported databases

### Connection Pooling

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

## Examples

Check out the `examples/` directory for complete working examples:

- `basic_app.py`: Basic FastAPI application with role-based access control
- `main.py`: Demo application with multiple database support

## Running the Demo

```bash
# Clone the repository
git clone https://github.com/your-repo/fastapi-roles.git
cd fastapi-roles

# Install dependencies
pip install -e .[dev]

# Run the demo
python main.py
```

The demo will start a FastAPI server with:
- SQLite database (easily changeable to other databases)
- Demo users: `user@demo.com/password` and `admin@demo.com/admin`
- Protected endpoints demonstrating role and permission-based access

## API Documentation

When you run the demo, visit `http://localhost:8000/docs` to see the interactive API documentation.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Changelog

### Version 0.1.0

- **Breaking Changes:**
  - Migrated to SQLAlchemy 2.0
  - Updated model syntax with proper type annotations
  - Changed database setup API

- **New Features:**
  - Multi-database support (SQLite, PostgreSQL, MySQL, Oracle)
  - Database abstraction layer
  - Environment-based configuration
  - Improved type safety
  - Better error handling

- **Improvements:**
  - Modern SQLAlchemy 2.0 syntax
  - Better performance with connection pooling
  - Cross-database compatibility
  - Enhanced documentation

## Support

For questions and support, please open an issue on GitHub.
