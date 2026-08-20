from fastapi import FastAPI
from app.database import Base, engine
from app.routers import auth, users, admin

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Auth Microservice",
    description="""
Standalone authentication and authorization microservice.

**Features:**
- JWT access tokens (15 min) + refresh tokens (7 days)
- Refresh tokens stored as hashes — never plain text server-side
- Token blacklisting on logout
- Role-based access control (user / moderator / admin)
- Force logout from all devices
- Token introspection endpoint for other microservices
- Admin dashboard with system stats

**How other services verify tokens:**
```
POST /auth/verify-token
{ "token": "eyJ..." }
→ { "valid": true, "user_id": 1, "role": "user" }
```

**Environment variables:**
- `SECRET_KEY` — JWT signing key (auto-generated if not set)
- `DATABASE_URL` — defaults to SQLite
- `ACCESS_TOKEN_EXPIRE_MINUTES` — defaults to 15
- `REFRESH_TOKEN_EXPIRE_DAYS` — defaults to 7
    """,
    version="1.0.0"
)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(admin.router)


@app.get("/", tags=["Health"])
def root():
    return {
        "service": "Auth Microservice",
        "version": "1.0.0",
        "status":  "running",
        "docs":    "/docs"
    }


@app.get("/health", tags=["Health"])
def health():
    return {"status": "ok"}