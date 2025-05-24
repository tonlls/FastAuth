# User Management System

FastAPI Roles Auth now includes a comprehensive user management system with ready-to-use authentication endpoints. This eliminates the need for developers to implement their own login, registration, and user management endpoints.

## Features

The user management system provides:

- **User Registration** - Allow users to create accounts
- **User Authentication** - Login with email/username and password
- **Token Management** - JWT access and refresh tokens
- **Password Management** - Change password and password reset functionality
- **User Profile Management** - Get and update user profiles
- **Admin User Management** - Admin endpoints for managing all users
- **Role-based Access Control** - Protect endpoints with roles and permissions

## Quick Start

### 1. Basic Setup

```python
from fastapi import FastAPI
from fastauth import (
    AuthManager,
    AuthConfig,
    create_user_management_router,
    Base,
)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Database setup
engine = create_engine("sqlite:///./app.db")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Auth configuration
config = AuthConfig(
    secret_key="your-secret-key",
    access_token_expire_minutes=30,
    refresh_token_expire_days=7,
)

# Create auth manager
auth_manager = AuthManager(config, get_db)

# Create FastAPI app
app = FastAPI()

# Include user management router
user_router = create_user_management_router(
    auth_manager=auth_manager,
    get_db=get_db,
)
app.include_router(user_router)
```

### 2. Available Endpoints

Once you include the user management router, you get these endpoints automatically:

#### Authentication Endpoints
- `POST /auth/register` - Register a new user
- `POST /auth/login` - Login with email/username and password
- `POST /auth/refresh` - Refresh access token

#### User Profile Endpoints
- `GET /auth/me` - Get current user profile
- `PUT /auth/me` - Update current user profile

#### Password Management
- `POST /auth/change-password` - Change current user's password
- `POST /auth/reset-password` - Request password reset email
- `POST /auth/reset-password/confirm` - Confirm password reset with token

#### Admin Endpoints (Superuser only)
- `GET /auth/users` - List all users
- `GET /auth/users/{user_id}` - Get user by ID
- `PUT /auth/users/{user_id}` - Update user by ID
- `DELETE /auth/users/{user_id}` - Delete user by ID

## Configuration Options

The `create_user_management_router` function accepts several configuration options:

```python
user_router = create_user_management_router(
    auth_manager=auth_manager,
    get_db=get_db,
    prefix="/auth",                    # URL prefix (default: "/auth")
    tags=["Authentication"],           # OpenAPI tags
    enable_registration=True,          # Enable user registration (default: True)
    enable_password_reset=True,        # Enable password reset (default: True)
    require_email_verification=False,  # Require email verification (default: False)
    default_user_role="user",         # Default role for new users (default: "user")
)
```

## Usage Examples

### User Registration

```bash
curl -X POST "http://localhost:8000/auth/register" \
     -H "Content-Type: application/json" \
     -d '{
       "email": "user@example.com",
       "username": "johndoe",
       "password": "securepassword",
       "first_name": "John",
       "last_name": "Doe"
     }'
```

### User Login

```bash
curl -X POST "http://localhost:8000/auth/login" \
     -H "Content-Type: application/json" \
     -d '{
       "email": "user@example.com",
       "password": "securepassword"
     }'
```

Response:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": 1800,
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "email": "user@example.com",
    "username": "johndoe",
    "first_name": "John",
    "last_name": "Doe",
    "is_active": true,
    "is_verified": false,
    "is_superuser": false,
    "roles": []
  }
}
```

### Get Current User Profile

```bash
curl -X GET "http://localhost:8000/auth/me" \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Change Password

```bash
curl -X POST "http://localhost:8000/auth/change-password" \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "current_password": "oldpassword",
       "new_password": "newpassword"
     }'
```

## Protecting Your Routes

Use the auth manager to protect your custom routes:

```python
from fastapi import Depends
from fastauth import User

@app.get("/protected")
async def protected_route(
    current_user: User = Depends(auth_manager.create_active_user_dependency())
):
    return {"message": f"Hello {current_user.email}!"}

@app.get("/admin-only")
async def admin_route(
    current_user: User = Depends(auth_manager.create_superuser_dependency())
):
    return {"message": "Admin access granted"}

@app.get("/moderator-only")
async def moderator_route(
    current_user: User = Depends(auth_manager.create_role_dependency("moderator"))
):
    return {"message": "Moderator access granted"}
```

## Customization

### Custom User Management Router

For advanced customization, you can create your own router class:

```python
from fastauth.endpoints import UserManagementRouter

class CustomUserManagementRouter(UserManagementRouter):
    async def register(self, user_data, db):
        # Custom registration logic
        # Send welcome email, etc.
        user = await super().register(user_data, db)
        # Additional custom logic
        return user
    
    async def login(self, login_data, db):
        # Custom login logic
        # Log login attempts, etc.
        response = await super().login(login_data, db)
        # Additional custom logic
        return response

# Use your custom router
custom_router = CustomUserManagementRouter(
    auth_manager=auth_manager,
    get_db=get_db,
)
app.include_router(custom_router.router)
```

### Email Integration

To enable password reset emails, implement the email sending logic:

```python
# In your custom router or by monkey-patching
async def send_password_reset_email(user_email: str, reset_token: str):
    # Implement your email sending logic here
    # Use services like SendGrid, AWS SES, etc.
    reset_link = f"https://yourapp.com/reset-password?token={reset_token}"
    # Send email with reset_link
    pass
```

## Security Considerations

1. **Secret Key**: Use a strong, random secret key in production
2. **HTTPS**: Always use HTTPS in production
3. **Token Expiration**: Set appropriate token expiration times
4. **Rate Limiting**: Implement rate limiting for authentication endpoints
5. **Password Policy**: Enforce strong password requirements
6. **Email Verification**: Enable email verification for production use

## Integration with Frontend

The user management system works seamlessly with any frontend framework. Here's an example with JavaScript:

```javascript
// Login
const loginResponse = await fetch('/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'password'
  })
});

const { access_token, user } = await loginResponse.json();

// Store token
localStorage.setItem('access_token', access_token);

// Make authenticated requests
const profileResponse = await fetch('/auth/me', {
  headers: { 'Authorization': `Bearer ${access_token}` }
});

const profile = await profileResponse.json();
```

## Complete Example

See `examples/user_management_example.py` for a complete working example that demonstrates:

- Setting up the user management system
- Creating initial roles and permissions
- Protecting routes with different access levels
- Admin user creation
- Integration with the FastAPI docs

Run the example:

```bash
cd examples
python user_management_example.py
```

Then visit `http://localhost:8000/docs` to explore the API interactively.

## Migration from Custom Auth

If you have existing custom authentication endpoints, you can gradually migrate to the user management system:

1. **Keep existing endpoints** while adding the new ones with a different prefix
2. **Migrate users gradually** by updating their auth_provider field
3. **Update frontend** to use new endpoints
4. **Remove old endpoints** once migration is complete

The user management system is designed to be flexible and work alongside existing authentication systems during migration.
