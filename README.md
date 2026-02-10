# Developer Portfolio API

A robust Django REST Framework backend designed to power a Developer Portfolio application. This system manages user authentication, project showcases, and technical skill tracking with a focus on security and data integrity.

## 🚀 Features

### Authentication & Authorization

- **Custom User Model**: UUID-based primary keys with email as the unique identifier
- **JWT Authentication**: Secure token-based auth via `simplejwt` with HTTP-only cookie support
- **Token Versioning**: Invalidate all user tokens on logout or password change
- **Social OAuth**: Google and GitHub login via `django-allauth`
- **Email Verification**: Mandatory verification before account activation
- **Password Security**: Enforced policies (uppercase, lowercase, digits, symbols)

### Project Management (`projects` app)

- **Full CRUD**: Create, read, update, and delete portfolio projects
- **Tech Stack Tracking**: Link projects to skills with automatic category creation
- **Atomic Transactions**: Ensures data integrity when creating projects with skills
- **Ownership Permissions**: Users can only manage their own projects

### Skill Tracking (`skills` app)

- **Categorization**: Organize skills into categories (Frontend, Backend, DevOps, etc.)
- **Optimized Queries**: Prefetch and select_related for efficient data retrieval
- **Read-Optimized**: Designed for easy fetching of user skills for display

### Performance & Infrastructure

- **Celery Integration**: Async email sending for verification and password reset
- **Redis Caching**: Response caching with compression
- **GZip Compression**: Reduced response sizes
- **Pagination**: Efficient handling of large datasets

## 🛠 Tech Stack

| Category           | Technologies                                                      |
| ------------------ | ----------------------------------------------------------------- |
| **Framework**      | Django 6.0+, Django REST Framework                                |
| **Database**       | SQLite (dev), PostgreSQL (prod-ready)                             |
| **Authentication** | `dj-rest-auth`, `django-allauth`, `djangorestframework-simplejwt` |
| **Task Queue**     | Celery with Redis broker                                          |
| **Caching**        | Redis with `django-redis`                                         |
| **API Docs**       | `drf-spectacular` (OpenAPI 3.0)                                   |
| **Filtering**      | `django-filter`                                                   |

## 📖 API Documentation

Once the server is running, access the interactive API docs:

| Format             | URL                                          |
| ------------------ | -------------------------------------------- |
| **Swagger UI**     | http://localhost:8000/api/schema/swagger-ui/ |
| **ReDoc**          | http://localhost:8000/api/schema/redoc/      |
| **OpenAPI Schema** | http://localhost:8000/api/schema/            |

## 📂 Project Structure

```text
src/
├── accounts/       # User models, auth views, JWT authentication, social OAuth
├── commons/        # Shared utilities (pagination, permissions)
├── core/           # Project settings, URL routing, Celery config
├── projects/       # Project CRUD operations and serializers
├── skills/         # Skill and category management
├── templates/      # HTML templates for testing auth flows
├── improvements/   # Documentation for implemented optimizations
├── manage.py       # Django CLI entry point
└── db.sqlite3      # Development database
```

## ⚡ Getting Started

### Prerequisites

- Python 3.10+
- Redis (for Celery and caching)
- pip (Python Package Manager)

### Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/BackendPhantom/portfolio_api.git
   cd portfolio_api/src
   ```

2. **Create and activate a virtual environment**

   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # or: venv\Scripts\activate  # Windows
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Run migrations**

   ```bash
   python manage.py migrate
   ```

5. **Create a superuser** (optional, for admin panel)

   ```bash
   python manage.py createsuperuser
   ```

6. **Start Redis** (required for Celery and caching)

   ```bash
   redis-server
   ```

7. **Start Celery worker** (in a separate terminal)

   ```bash
   celery -A core worker -l info
   ```

8. **Run the development server**

   ```bash
   python manage.py runserver
   ```

   The API will be available at `http://127.0.0.1:8000/`

## 🔗 API Endpoints

### Authentication

| Method | Endpoint                      | Description                                  |
| :----- | :---------------------------- | :------------------------------------------- |
| POST   | `/api/v1/auth/signup/`        | Register new user (sends verification email) |
| POST   | `/api/v1/auth/login/`         | Email/password login (returns JWT tokens)    |
| POST   | `/api/v1/auth/logout/`        | Logout and invalidate all tokens             |
| POST   | `/api/v1/users/verify-email/` | Verify email with token                      |

### Password Management

| Method    | Endpoint                                | Description                                 |
| :-------- | :-------------------------------------- | :------------------------------------------ |
| PUT/PATCH | `/api/v1/users/{id}/change-password/`   | Change password (requires current password) |
| POST      | `/api/v1/users/password-reset/`         | Request password reset email                |
| POST      | `/api/v1/users/password-reset/confirm/` | Confirm password reset with token           |

### Social Authentication

| Method | Endpoint                               | Description                                |
| :----- | :------------------------------------- | :----------------------------------------- |
| GET    | `/api/v1/auth/social/urls/`            | Get OAuth authorization URLs               |
| POST   | `/api/v1/auth/social/google/`          | Google OAuth login (with code or id_token) |
| POST   | `/api/v1/auth/social/github/`          | GitHub OAuth login (with code)             |
| GET    | `/api/v1/auth/social/google/callback/` | Google OAuth callback handler              |
| GET    | `/api/v1/auth/social/github/callback/` | GitHub OAuth callback handler              |

### User Profile

| Method    | Endpoint                     | Description                            |
| :-------- | :--------------------------- | :------------------------------------- |
| GET       | `/api/v1/users/{id}/`        | Get user profile                       |
| PUT/PATCH | `/api/v1/users/{id}/`        | Update user profile                    |
| DELETE    | `/api/v1/users/{id}/`        | Deactivate account (requires password) |
| GET       | `/api/v1/users/{id}/public/` | Get public user profile                |

### Projects

| Method    | Endpoint                                | Description                        |
| :-------- | :-------------------------------------- | :--------------------------------- |
| GET       | `/api/v1/projects/my-projects/`         | List authenticated user's projects |
| POST      | `/api/v1/projects/create-new/`          | Create a new project               |
| GET       | `/api/v1/projects/{id}/details/`        | Get project details                |
| PUT/PATCH | `/api/v1/projects/{id}/update-project/` | Update project                     |
| DELETE    | `/api/v1/projects/{id}/delete-project/` | Delete project                     |

### Skills

| Method | Endpoint                     | Description                              |
| :----- | :--------------------------- | :--------------------------------------- |
| GET    | `/api/v1/skills/`            | List all user's skills                   |
| GET    | `/api/v1/skills/categories/` | List skill categories with nested skills |

## 🔐 Environment Variables

For production deployment, configure these environment variables:

```bash
# Django
SECRET_KEY=your-production-secret-key
DEBUG=False
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com

# Database (PostgreSQL)
DATABASE_URL=postgres://user:password@host:5432/portfolio_db

# Redis
REDIS_URL=redis://localhost:6379/0

# OAuth Credentials
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# URLs
FRONTEND_URL=https://yourfrontend.com
GOOGLE_CALLBACK_URL=https://yourapi.com/api/v1/auth/social/google/callback/
GITHUB_CALLBACK_URL=https://yourapi.com/api/v1/auth/social/github/callback/

# Email (Production)
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
```

## 🧪 Testing

### Test Authentication Flows

The repository includes HTML templates for testing auth flows:

- **Signup**: `http://127.0.0.1:8000/auth/signup/`
- **Login**: `http://127.0.0.1:8000/auth/login/`

### Run Tests

```bash
python manage.py test
```

### Test with cURL

```bash
# Register a new user
curl -X POST http://localhost:8000/api/v1/auth/signup/ \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "SecurePass123!", "password_confirm": "SecurePass123!"}'

# Login
curl -X POST http://localhost:8000/api/v1/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "SecurePass123!"}'

# Access protected endpoint
curl http://localhost:8000/api/v1/projects/my-projects/ \
  -H "Authorization: Bearer <access_token>"
```

## 📈 Performance Optimizations

This API includes several performance optimizations documented in the `improvements/` directory:

| Optimization       | Description                                                   |
| ------------------ | ------------------------------------------------------------- |
| Query Optimization | `select_related` and `prefetch_related` for efficient queries |
| Database Indexes   | Indexed frequently queried fields                             |
| Pagination         | Cursor-based pagination for large datasets                    |
| Compression        | GZip middleware for response compression                      |
| Async Email        | Celery tasks for background email sending                     |
| Caching            | Redis caching with key prefixing                              |
| Throttling         | Rate limiting to prevent abuse                                |
| Filtering          | `django-filter` for efficient data filtering                  |

## 📄 License

[MIT](LICENSE)
