# Developer Portfolio API

A robust Django REST Framework backend designed to power a Developer Portfolio application. This system manages user authentication, project showcases, and technical skill tracking with a focus on security and data integrity.

## 🚀 Features

### Authentication & Authorization

- **Custom User Model**: UUID-based primary keys with Email as the unique identifier.
- **Secure Authentication**: Implements `dj_rest_auth` and `simplejwt` with `JWT_AUTH_COOKIE` for secure, HTTP-only cookie-based authentication.
- **Social Login**: Integrated Google and GitHub OAuth support via `django-allauth`.
- **Strict Security**: Enforced password policies (uppercase, lowercase, digits, symbols).

### Project Management (`projects` app)

- **Detailed Records**: Track project names, descriptions, URLs, and images.
- **Automated Relations**: Atomic transactions ensure `Skills` and `SkillCategories` are automatically created or linked when adding a project's tech stack.
- **Permissions**: Users can only manage their own projects (`IsAuthenticatedAndOwner`).

### Skill Tracking (`skills` app)

- **Categorization**: Organize skills into categories (e.g., Frontend, Backend, DevOps).
- **Read-Optimized**: Designed to allow easy fetching of user skills for display.

## 🛠 Tech Stack

- **Backend Framework**: Django 6.0+, Django REST Framework (DRF)
- **Database**: SQLite (Development), PostgreSQL-ready.
- **Authentication**: `dj_rest_auth`, `django-allauth`, `djangorestframework-simplejwt`.
- **Frontend (Templates)**: Simple HTML/Tailwind CSS templates included for testing auth flows.

## 📂 Project Structure

```text
src/
├── accounts/       # User models, Social Auth views, Custom Permissions
├── commons/        # Shared utilities (Pagination, Permissions)
├── core/           # Project settings, URL routing, WSGI/ASGI
├── projects/       # Project creation & management logic
├── skills/         # Skill definitions & classifications
├── templates/      # HTML templates for testing (Login, Signup, Dashboard)
├── manage.py       # Django CLI entry point
└── db.sqlite3      # Development database
```

## ⚡ Getting Started

### Prerequisites

- Python 3.10+
- Pip (Python Package Manager)

### Installation

1.  **Clone the repository**

    ```bash
    git clone <repository-url>
    cd portfolio_api/src
    ```

2.  **Create and activate a virtual environment**

    ```bash
    python -m venv venv
    # Linux/Mac
    source venv/bin/activate
    # Windows
    venv\Scripts\activate
    ```

3.  **Install Dependencies**
    _(Ensure you have a requirements.txt, otherwise install key packages manually)_

    ```bash
    pip install django djangorestframework django-allauth dj-rest_auth djangorestframework-simplejwt django-cors-headers
    ```

4.  **Run Migrations**
    Initialize the database setup.

    ```bash
    python manage.py makemigrations
    python manage.py migrate
    ```

5.  **Create a Superuser** (Optional, for Admin Panel)

    ```bash
    python manage.py createsuperuser
    ```

6.  **Run the Server**

    ```bash
    python manage.py runserver
    ```

    The API will be available at `http://127.0.0.1:8000/`.

## 🔗 API Endpoints

### Authentication

| Method | Endpoint                      | Description                      |
| :----- | :---------------------------- | :------------------------------- |
| POST   | `/api/v1/auth/login/`         | Email/password login             |
| POST   | `/api/v1/auth/signup/`        | Register new user                |
| POST   | `/api/v1/auth/logout/`        | Logout (blacklist refresh token) |
| POST   | `/api/v1/auth/social/google/` | Google OAuth Login               |
| POST   | `/api/v1/auth/social/github/` | GitHub OAuth Login               |
| GET    | `/api/v1/auth/social/urls/`   | Get OAuth authorization URLs     |

### User Profile

| Method    | Endpoint                            | Description                   |
| :-------- | :---------------------------------- | :---------------------------- |
| GET       | `/api/v1/users/me/`                 | Get current user's profile    |
| PATCH/PUT | `/api/v1/users/me/`                 | Update current user's profile |
| POST      | `/api/v1/users/me/change-password/` | Change password               |
| DELETE    | `/api/v1/users/me/delete/`          | Deactivate account            |
| GET       | `/api/v1/users/{uuid}/`             | Get public user profile       |

### Projects

| Method    | Endpoint                           | Description                             |
| :-------- | :--------------------------------- | :-------------------------------------- |
| GET       | `/api/v1/projects/my_projects/`    | List logged-in user's projects          |
| POST      | `/api/v1/projects/create_project/` | Create a new project (atomic w/ skills) |
| GET       | `/api/v1/projects/{id}/`           | Retrieve specific project details       |
| PUT/PATCH | `/api/v1/projects/{id}/`           | Update project                          |

### Skills

| Method | Endpoint                     | Description           |
| :----- | :--------------------------- | :-------------------- |
| GET    | `/api/v1/skills/`            | List all skills       |
| GET    | `/api/v1/skills/categories/` | List skill categories |

## 🧪 Testing

The repository allows for quick testing of authentication flows via provided templates:

- Visit `http://127.0.0.1:8000/auth/signup/` to test Social Auth integration UI.

## 📄 License

[MIT](LICENSE)
