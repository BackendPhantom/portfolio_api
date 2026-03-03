# Developer Portfolio API

A production-grade Django REST Framework backend for a developer portfolio application. Handles user authentication (email/password + social OAuth), project showcases, and technical skill tracking — with a focus on security, performance, and clean API design.

---

## Table of Contents

- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Architecture](#-architecture)
- [Getting Started](#-getting-started)
- [API Endpoints](#-api-endpoints)
- [Authentication Deep Dive](#-authentication-deep-dive)
- [Environment Variables](#-environment-variables)
- [Performance Optimizations](#-performance-optimizations)
- [Project Structure](#-project-structure)
- [API Documentation](#-api-documentation)
- [Testing](#-testing)
- [Deployment](#-deployment)
- [License](#-license)

---

## ✨ Features

### Authentication & Security

- **Custom User Model** — UUID primary keys, email as unique identifier
- **JWT Authentication** — Short-lived access tokens (5 min) with versioned, single-use refresh tokens (1 day)
- **Token Versioning** — Incrementing `token_version` instantly revokes all outstanding JWTs on logout or password change
- **JTI Rotation** — Each refresh token's JTI hash is stored on the user; replay attempts auto-revoke the entire token family
- **API Key Authentication** — Long-lived HMAC-SHA256 hashed keys (max 10 per user, max 180-day expiry)
- **Social OAuth** — Google and GitHub login via `django-allauth` with cryptographic `state` parameter for CSRF protection
- **Time-Based Signed Tokens** — Email verification and password reset use `django.core.signing` with configurable `max_age` (default 24 h)
- **Glassmorphism HTML Emails** — Styled verification, password reset, and welcome emails with plain-text fallback
- **Password Policy** — Enforced uppercase, lowercase, digit, and special character requirements
- **Rate Limiting** — Per-endpoint throttles (signup 3/min, login 5/min, password reset 3/min, social exchange 5/min)

### Portfolio Management

- **Projects** — Full CRUD with M2M tech-stack linking to skills, atomic transactions, and ownership enforcement
- **Skills & Categories** — Categorized skill tracking with protected deletion (skills linked to projects cannot be removed)
- **Data Export** — Single-endpoint JSON export of all user data (profile, projects, skills)
- **Activity Log** — Recent activity feed for the authenticated user
- **Public Stats** — Unauthenticated aggregate counts endpoint
- **Public Profiles** — Optional public visibility toggle per user

### Infrastructure

- **Celery + Redis** — Async email delivery with automatic retry (3 attempts, 60 s delay)
- **Redis Caching** — `django-redis` with Zlib compression and 50-connection pool
- **GZip + Brotli** — Compressed HTTP responses via middleware
- **Request Logging** — Custom middleware logs method, path, status, and duration (slow-request warnings >1 s)
- **CSRF-Safe API** — CSRF checks skipped for `/api/` routes (header-based auth), enforced elsewhere
- **API Versioning** — `/api/v1/` prefix with unsupported-version catch-all returning `400`
- **OpenAPI 3.0 Docs** — Auto-generated via `drf-spectacular` with Swagger UI + ReDoc

---

## 🛠 Tech Stack

| Layer            | Technologies                                                      |
| ---------------- | ----------------------------------------------------------------- |
| **Framework**    | Django 5.2, Django REST Framework 3.16                            |
| **Auth**         | `djangorestframework-simplejwt`, `dj-rest-auth`, `django-allauth` |
| **Database**     | SQLite (dev), PostgreSQL via `psycopg2-binary` (prod)             |
| **Task Queue**   | Celery 5.6 with Redis broker                                      |
| **Caching**      | Redis via `django-redis` (Zlib compression, connection pooling)   |
| **API Docs**     | `drf-spectacular` + sidecar (Swagger UI, ReDoc)                   |
| **Filtering**    | `django-filter`, `SearchFilter`, `OrderingFilter`                 |
| **Static Files** | WhiteNoise with `CompressedManifestStaticFilesStorage`            |
| **Deployment**   | Gunicorn, Heroku-ready (`Procfile`, Redis TLS)                    |

---

## 🏗 Architecture

```
Client (Frontend / Mobile / cURL)
  │
  ▼
┌──────────────────────────────────────────┐
│  Django + DRF                            │
│  ├── JWT Auth (simplejwt + versioning)   │
│  ├── API Key Auth (HMAC-SHA256)          │
│  ├── OAuth (Google, GitHub via allauth)  │
│  ├── Rate Limiting (per-endpoint)        │
│  └── GZip / Brotli Compression          │
├──────────────────────────────────────────┤
│  Celery Worker  ◄──── Redis (Broker)     │
│  └── Async Emails (verification, reset)  │
├──────────────────────────────────────────┤
│  Redis Cache (django-redis + Zlib)       │
├──────────────────────────────────────────┤
│  SQLite (dev) / PostgreSQL (prod)        │
└──────────────────────────────────────────┘
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- Redis (for Celery + caching)

### Installation

```bash
# Clone
git clone https://github.com/BackendPhantom/portfolio_api.git
cd portfolio_api/src

# Virtual environment
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# Dependencies
pip install -r requirements.txt

# Create a .env file (see Environment Variables section below)

# Database
python manage.py migrate

# (Optional) Create an admin user
python manage.py createsuperuser
```

### Running Locally

```bash
# Terminal 1 — Redis
redis-server

# Terminal 2 — Celery worker
celery -A core worker -l info

# Terminal 3 — Development server
python manage.py runserver
```

The API will be available at **http://127.0.0.1:8000/**

---

## 🔗 API Endpoints

All endpoints are prefixed with `/api/v1/`.

### Authentication — `/api/v1/auth/`

| Method | Endpoint               | Description                                                    | Auth   | Throttle | View                        |
| :----- | :--------------------- | :------------------------------------------------------------- | :----- | :------- | :-------------------------- |
| POST   | `/auth/signup/`        | Register a new user; sends a verification email                | Public | 3/min    | `SignupViewset`             |
| POST   | `/auth/login/`         | Login with email & password → JWT access + refresh + user data | Public | 5/min    | `LoginView`                 |
| POST   | `/auth/logout/`        | Logout; bumps `token_version`, invalidates all JWTs            | Bearer | —        | `LogoutView`                |
| POST   | `/auth/token/refresh/` | Rotate refresh token (validates `token_version` + JTI)         | Public | —        | `VersionedTokenRefreshView` |

### Email Verification & Password Reset — `/api/v1/users/`

| Method | Endpoint                         | Description                                                   | Auth   | Throttle | View                                        |
| :----- | :------------------------------- | :------------------------------------------------------------ | :----- | :------- | :------------------------------------------ |
| POST   | `/users/verify-email/`           | Verify email with signed token → auto-login (returns JWTs)    | Public | —        | `UserProfileViewset.verify_email`           |
| POST   | `/users/verify-email/request/`   | Request a new verification email for an inactive account      | Public | —        | `UserProfileViewset.verify_email_request`   |
| POST   | `/users/password-reset/`         | Request password reset email (always returns success)         | Public | 3/min    | `UserProfileViewset.request_password_reset` |
| POST   | `/users/password-reset/confirm/` | Reset password with signed token; revokes all existing tokens | Public | —        | `UserProfileViewset.confirm_password_reset` |

### User Profile — `/api/v1/users/`

| Method    | Endpoint                       | Description                                                     | Auth   | View                                 |
| :-------- | :----------------------------- | :-------------------------------------------------------------- | :----- | :----------------------------------- |
| GET       | `/users/me/`                   | Get the authenticated user's own profile                        | Bearer | `UserProfileViewset.me`              |
| PATCH/PUT | `/users/update-profile/`       | Update the authenticated user's profile                         | Bearer | `UserProfileViewset.update_profile`  |
| GET       | `/users/{id}/`                 | Retrieve a user profile (owner only)                            | Bearer | `UserProfileViewset.retrieve`        |
| PUT/PATCH | `/users/{id}/`                 | Update a user profile (owner only)                              | Bearer | `UserProfileViewset.update`          |
| DELETE    | `/users/{id}/`                 | Deactivate account (requires password confirmation)             | Bearer | `UserProfileViewset.destroy`         |
| PUT/PATCH | `/users/{id}/change-password/` | Change password (requires current password; revokes all tokens) | Bearer | `UserProfileViewset.change_password` |
| GET       | `/users/{id}/public/`          | Get public profile (only if user enabled visibility)            | Public | `UserProfileViewset.public_profile`  |

### API Keys — `/api/v1/auth/`

| Method | Endpoint                 | Description                                               | Auth   | View             |
| :----- | :----------------------- | :-------------------------------------------------------- | :----- | :--------------- |
| GET    | `/auth/api-keys/`        | List all API keys (metadata only, raw key never returned) | Bearer | `list_api_keys`  |
| POST   | `/auth/api-keys/create/` | Create a new API key (raw key returned **once**)          | Bearer | `create_api_key` |
| DELETE | `/auth/api-keys/{id}/`   | Permanently delete an API key                             | Bearer | `delete_api_key` |

### Social OAuth — `/api/v1/auth/social/`

| Method | Endpoint                   | Description                                                    | Auth   | Throttle | View                |
| :----- | :------------------------- | :------------------------------------------------------------- | :----- | :------- | :------------------ |
| GET    | `/social/urls/`            | Get Google & GitHub OAuth authorization URLs (with CSRF state) | Public | —        | `get_oauth_urls`    |
| POST   | `/social/google/`          | Google login (accepts `id_token` or `code`)                    | Public | —        | `GoogleLogin`       |
| POST   | `/social/github/`          | GitHub login (accepts `code`)                                  | Public | —        | `GitHubLogin`       |
| GET    | `/social/google/callback/` | Google OAuth callback (validates `state`, exchanges code)      | Public | —        | `google_callback`   |
| GET    | `/social/github/callback/` | GitHub OAuth callback (validates `state`, exchanges code)      | Public | —        | `github_callback`   |
| POST   | `/social/exchange/`        | Exchange short-lived authorization code for JWT tokens         | Public | 5/min    | `ExchangeTokenView` |

### Projects — `/api/v1/projects/`

| Method    | Endpoint                         | Description                                         | Auth   | View                             |
| :-------- | :------------------------------- | :-------------------------------------------------- | :----- | :------------------------------- |
| GET       | `/projects/my-projects/`         | Paginated list of the authenticated user's projects | Bearer | `ProjectViewSet.my_projects`     |
| POST      | `/projects/create-new/`          | Create a new project (with tech stack skill names)  | Bearer | `ProjectViewSet.create_project`  |
| GET       | `/projects/{id}/details/`        | Get detailed info about a specific project          | Bearer | `ProjectViewSet.project_details` |
| PUT/PATCH | `/projects/{id}/update-project/` | Update a project (full or partial)                  | Bearer | `ProjectViewSet.update_project`  |
| DELETE    | `/projects/{id}/delete-project/` | Permanently delete a project                        | Bearer | `ProjectViewSet.delete_project`  |

### Skills — `/api/v1/skills/`

| Method | Endpoint              | Description                                                     | Auth   | View                        |
| :----- | :-------------------- | :-------------------------------------------------------------- | :----- | :-------------------------- |
| GET    | `/skills/`            | List all skills for the authenticated user (with category info) | Bearer | `SkillViewSet.list`         |
| GET    | `/skills/categories/` | List all skill categories with nested skills                    | Bearer | `SkillCategoryViewSet.list` |

### Core / Utility

| Method | Endpoint               | Description                                                    | Auth   | View                     |
| :----- | :--------------------- | :------------------------------------------------------------- | :----- | :----------------------- |
| GET    | `/health/`             | Health check — DB connectivity status                          | Public | `health_check`           |
| GET    | `/api/v1/stats/`       | Aggregate skill & project counts                               | Public | `StatsView`              |
| GET    | `/api/v1/activity/`    | 20 most recent activity log entries for the authenticated user | Bearer | `RecentActivityView`     |
| GET    | `/api/v1/export/`      | Full JSON data export (profile, projects, skills)              | Bearer | `DataExportView`         |
| GET    | `/api/schema/`         | OpenAPI 3.0 JSON schema                                        | Public | `SpectacularAPIView`     |
| GET    | `/api/schema/swagger/` | Swagger UI                                                     | Public | `SpectacularSwaggerView` |
| GET    | `/api/schema/redoc/`   | ReDoc                                                          | Public | `SpectacularRedocView`   |
| ANY    | `/api/{version}/`      | Catch-all for unsupported API versions → `400`                 | Public | `unsupported_version`    |

---

## 🔐 Authentication Deep Dive

### 1. JWT (Bearer Token)

```
Authorization: Bearer <access_token>
```

| Token   | Lifetime | Notes                                                                |
| ------- | -------- | -------------------------------------------------------------------- |
| Access  | 5 min    | Carries `token_version`; verified on every authenticated request     |
| Refresh | 1 day    | Single-use via JTI rotation; replay auto-revokes entire token family |

**Revocation:** Bumping `token_version` (on logout, password change, or detected replay) instantly invalidates every outstanding access and refresh token — no blacklist table needed.

### 2. API Key

```
X-API-Key: dvf_<random>
```

- HMAC-SHA256 hashed with Django `SECRET_KEY` (raw key never stored)
- Max 10 active keys per user, max 180-day expiry
- Not revoked on logout — managed separately via `/api/v1/auth/api-keys/`
- Usage tracked with 5-min stamp debounce

### 3. Social OAuth (Google / GitHub)

1. `GET /api/v1/auth/social/urls/` → returns OAuth authorization URLs + CSRF `state` (also set as HTTP-only cookie)
2. User authorizes with provider → redirected to callback with `code` + `state`
3. Callback validates `state` against cookie, exchanges `code` internally
4. Tokens cached in Redis (60 s TTL) under a UUID code
5. `POST /api/v1/auth/social/exchange/` → exchanges the UUID code for JWT pair (single-use)

### 4. Signed Tokens (Email Verification & Password Reset)

Both flows use `django.core.signing.dumps` / `loads` with a configurable `max_age`:

| Token Type         | Salt             | Default Expiry | Setting                            |
| ------------------ | ---------------- | -------------- | ---------------------------------- |
| Email verification | `email-verify`   | 24 hours       | `EMAIL_VERIFICATION_TOKEN_MAX_AGE` |
| Password reset     | `password-reset` | 24 hours       | `PASSWORD_RESET_TOKEN_MAX_AGE`     |

- Expired tokens → `"link has expired"` (400)
- Tampered tokens → `"invalid link"` (400)
- Password reset also bumps `token_version` + clears `refresh_jti`

---

## 🔑 Environment Variables

Create a `.env` file in the `src/` directory:

```bash
# Django
SECRET_KEY=your-secret-key
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
DJANGO_SETTINGS_MODULE=core.settings.development

# JWT
JWT_SIGNING_KEY=your-jwt-key   # defaults to SECRET_KEY

# Database (production — dev uses SQLite by default)
DATABASE_URL=postgres://user:pass@host:5432/portfolio_db

# Redis (required for Celery + caching)
REDIS_URL=redis://localhost:6379/0

# OAuth Credentials
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...

# URLs
FRONTEND_URL=http://localhost:5173
GOOGLE_CALLBACK_URL=http://localhost:8000/api/v1/auth/social/google/callback/
GITHUB_CALLBACK_URL=http://localhost:8000/api/v1/auth/social/github/callback/

# CORS
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173

# Email (dev uses console backend by default)
EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
# Production SMTP example:
# EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
# EMAIL_HOST=smtp.gmail.com
# EMAIL_PORT=587
# EMAIL_USE_TLS=True
# EMAIL_HOST_USER=your-email@gmail.com
# EMAIL_HOST_PASSWORD=your-app-password
```

---

## ⚡ Performance Optimizations

| Optimization         | Implementation                                                          |
| -------------------- | ----------------------------------------------------------------------- |
| Query optimization   | `select_related` / `prefetch_related` on all querysets                  |
| Database indexes     | Composite indexes on frequently filtered fields (email, title, status)  |
| Pagination           | `PageNumberPagination` (5 items/page default)                           |
| Response compression | GZip middleware + Brotli via `django-brotli`                            |
| Async emails         | Celery tasks with retry (3×, 60 s backoff)                              |
| Redis caching        | `django-redis` with Zlib compression and 50-connection pool             |
| Rate limiting        | Per-endpoint DRF throttles (signup, login, password reset, social)      |
| Filtering & search   | `django-filter` + DRF `SearchFilter` + `OrderingFilter`                 |
| Static files         | WhiteNoise with `CompressedManifestStaticFilesStorage`                  |
| Request logging      | Middleware logs method, path, status, and duration (slow warnings >1 s) |
| Single-use tokens    | JTI hash rotation without a blacklist table                             |

---

## 📂 Project Structure

```
src/
├── accounts/                  # Authentication, profiles, email tasks
│   ├── models.py              # User (UUID PK, token versioning), APIKey (HMAC-SHA256)
│   ├── views.py               # SignupViewset, LoginView, LogoutView,
│   │                          #   VersionedTokenRefreshView, UserProfileViewset,
│   │                          #   GoogleLogin, GitHubLogin, get_oauth_urls,
│   │                          #   google_callback, github_callback, ExchangeTokenView,
│   │                          #   list_api_keys, create_api_key, delete_api_key
│   ├── serializers.py         # Registration, profile, password change/reset
│   ├── tokens.py              # VersionedRefreshToken, VersionedAccessToken, JTI rotation
│   ├── authentication.py      # VersionedJWTAuthentication, APIKeyAuthentication
│   ├── tasks.py               # Celery: send_verification_email, send_password_reset_email,
│   │                          #   send_welcome_email (glassmorphism HTML)
│   ├── throttles.py           # Signup, Login, PasswordReset, SocialExchange throttles
│   ├── adapters.py            # Custom allauth account + social adapters
│   └── urls.py                # auth/ and users/ URL patterns
├── projects/                  # Portfolio project management
│   ├── models.py              # Project with M2M tech_stack → Skill
│   ├── views.py               # ProjectViewSet (my_projects, create_project,
│   │                          #   project_details, update_project, delete_project)
│   ├── serializers.py         # ProjectSerializer
│   └── urls.py                # projects/ URL patterns
├── skills/                    # Skill & category management
│   ├── models.py              # SkillCategory, Skill (protected deletion via signal)
│   ├── views.py               # SkillViewSet (list), SkillCategoryViewSet (list)
│   ├── serializers.py         # SkillSerializer, SkillCategorySerializer
│   └── urls.py                # skills/ and skills/categories/ URL patterns
├── core/                      # Project-wide configuration
│   ├── settings/              # Split settings: base, development, production, testing
│   ├── urls.py                # API v1 routing, schema, health check, version catch-all
│   ├── views.py               # health_check, DataExportView, RecentActivityView, StatsView
│   ├── models.py              # TimestampedModel, ActivityLog
│   ├── middleware.py           # CSRFExemptAPIMiddleware, RequestLoggingMiddleware
│   ├── celery.py              # Celery app configuration
│   ├── exception_handler.py   # Custom DRF exception handler
│   ├── validators.py          # Shared validators
│   └── utils.py               # Shared utilities (e.g. generate_unique_slug)
├── commons/                   # Shared cross-app utilities
│   ├── pagination.py          # PortfolioPagination
│   └── permissions.py         # IsSelf, IsAuthenticatedAndOwner, ProjectPermission
├── improvements/              # Documentation for each implemented optimization
├── requirements.txt           # Pinned Python dependencies
├── Procfile                   # Heroku: web (gunicorn) + worker (celery)
└── manage.py
```

---

## 📖 API Documentation

Once the server is running:

| Format           | URL                                       |
| ---------------- | ----------------------------------------- |
| **Swagger UI**   | http://localhost:8000/api/schema/swagger/ |
| **ReDoc**        | http://localhost:8000/api/schema/redoc/   |
| **OpenAPI JSON** | http://localhost:8000/api/schema/         |

---

## 🧪 Testing

```bash
# Run all tests
python manage.py test

# Run a specific app's tests
python manage.py test accounts
python manage.py test projects
python manage.py test skills
```

### Quick cURL Examples

```bash
# Register
curl -X POST http://localhost:8000/api/v1/auth/signup/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!",
    "password_confirm": "SecurePass123!"
  }'

# Login
curl -X POST http://localhost:8000/api/v1/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!"
  }'

# Access protected endpoint
curl http://localhost:8000/api/v1/users/me/ \
  -H "Authorization: Bearer <access_token>"

# Refresh token
curl -X POST http://localhost:8000/api/v1/auth/token/refresh/ \
  -H "Content-Type: application/json" \
  -d '{"refresh": "<refresh_token>"}'

# Verify email
curl -X POST http://localhost:8000/api/v1/users/verify-email/ \
  -H "Content-Type: application/json" \
  -d '{"token": "<signed_token>"}'

# Request password reset
curl -X POST http://localhost:8000/api/v1/users/password-reset/ \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com"}'

# Confirm password reset
curl -X POST http://localhost:8000/api/v1/users/password-reset/confirm/ \
  -H "Content-Type: application/json" \
  -d '{
    "token": "<signed_token>",
    "new_password": "NewSecure456!",
    "new_password_confirm": "NewSecure456!"
  }'

# Create API key
curl -X POST http://localhost:8000/api/v1/auth/api-keys/create/ \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "My Frontend", "expires_in_days": 90}'

# Use API key
curl http://localhost:8000/api/v1/users/me/ \
  -H "X-API-Key: dvf_<your_raw_key>"
```

---

## 🚢 Deployment

The project is Heroku-ready:

```
web: gunicorn core.wsgi
worker: celery -A core worker --loglevel=info
```

**Required add-ons:** Heroku Postgres, Heroku Redis (TLS configured via `ssl_cert_reqs`).

Ensure all [environment variables](#-environment-variables) are set and `DJANGO_SETTINGS_MODULE=core.settings.production`.

---

## 📄 License

[MIT](LICENSE)
