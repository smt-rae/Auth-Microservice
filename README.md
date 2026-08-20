# Auth Microservice

A standalone authentication and authorization microservice built with FastAPI. Handles registration, login, JWT token management, refresh tokens, role-based access control, and token introspection for other services.

---

## Tech Stack

- FastAPI
- SQLAlchemy + SQLite / PostgreSQL
- python-jose for JWT
- passlib + bcrypt for password hashing
- Deployed on Railway

---

## Security Design

**Access tokens** expire in 15 minutes. Short lived by design limits the damage window if intercepted.

**Refresh tokens** are stored as SHA-256 hashes in the database. The raw token is returned to the client once and never stored server side. A database breach exposes useless hashes.

**Token blacklisting** lets users invalidate access tokens on logout before they expire naturally.

**Password validation** requires minimum 8 characters, one uppercase letter, and one number.

**Force logout** revokes all refresh tokens for a user, used on password change or admin action.

---

## Setup

```bash
git clone https://github.com/yourusername/auth-service.git
cd auth-service
pip install -r requirements.txt

export SECRET_KEY=your-super-secret-key-here

uvicorn main:app --reload
```

Docs at `http://localhost:8000/docs`

---

## API Reference

### Auth
| Method | Route | Description |
|---|---|---|
| POST | `/auth/register` | Create a new account |
| POST | `/auth/login` | Login, receive access + refresh tokens |
| POST | `/auth/refresh` | Get new access token from refresh token |
| POST | `/auth/logout` | Revoke refresh token + blacklist access token |
| POST | `/auth/logout-all` | Log out all devices |
| POST | `/auth/verify-token` | Token introspection for other services |

### Users
| Method | Route | Description |
|---|---|---|
| GET | `/users/me` | Get current user profile |
| POST | `/users/me/change-password` | Change password (revokes all sessions) |
| GET | `/users/me/sessions` | List active sessions by device |

### Admin
| Method | Route | Description |
|---|---|---|
| GET | `/admin/users` | List all users |
| GET | `/admin/users/{id}` | Get single user |
| PATCH | `/admin/users/{id}` | Update role / active / verified status |
| POST | `/admin/users/{id}/force-logout` | Revoke all user sessions |
| DELETE | `/admin/users/{id}` | Permanently delete user |
| GET | `/admin/stats` | System-wide auth stats |

---

## Example Walkthrough

### Register
```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "rae@example.com", "username": "rae", "password": "Secure123"}'
```

### Login
```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "rae@example.com", "password": "Secure123"}'
```
Returns:
```json
{
  "access_token": "eyJ...",
  "refresh_token": "abc123...",
  "token_type": "bearer",
  "expires_in": 900
}
```

### Access a protected route
```bash
curl http://localhost:8000/users/me \
  -H "Authorization: Bearer eyJ..."
```

### Refresh
```bash
curl -X POST http://localhost:8000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "abc123..."}'
```

### Token verification (for other microservices)
```bash
curl -X POST http://localhost:8000/auth/verify-token \
  -H "Content-Type: application/json" \
  -d '{"token": "eyJ..."}'
```
Returns:
```json
{ "valid": true, "user_id": 1, "username": "rae", "role": "user", "message": "Token is valid" }
```

---

## Using RBAC in Other Services

Import the dependency pattern into any FastAPI app:

```python
# In another service that trusts this auth service
from fastapi import Depends

def require_role(*roles):
    def checker(token: str):
        # Call auth service /verify-token
        # Check role in response
        pass
    return checker

@app.get("/admin-only", dependencies=[Depends(require_role("admin"))])
def admin_route():
    pass
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | Random (generated at startup) | JWT signing key — set explicitly in production |
| `DATABASE_URL` | `sqlite:///./auth.db` | Database connection string |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | Access token lifetime |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifetime |

---

## What I Learned

- JWT access and refresh token architecture from scratch
- Refresh token storage security hashing instead of plain text
- Token blacklisting for pre expiry invalidation
- Role-based access control with reusable FastAPI dependencies
- The `require_role()` factory pattern for flexible route protection
- Why short-lived access tokens + long-lived refresh tokens is the right design