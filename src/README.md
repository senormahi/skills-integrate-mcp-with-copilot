# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- Teachers can register and unregister students after signing in
- Students can view activities and participant rosters without signing in

## Getting Started

Run these commands from the repository root.

1. Install the dependencies:

   ```
   pip install -r requirements.txt
   ```

2. Run the application:

   ```
   python -m uvicorn src.app:app --reload
   ```

3. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities with their details and current participant count |
| POST   | `/auth/login`                                                      | Sign in as a teacher and set a signed session cookie                 |
| GET    | `/auth/status`                                                     | Check whether the current browser has a teacher session               |
| POST   | `/auth/logout`                                                     | Clear the teacher session                                             |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | Teacher-only student registration                                    |
| DELETE | `/activities/{activity_name}/unregister?email=student@mergington.edu` | Teacher-only student removal                                      |

## Teacher Accounts

Create or replace a teacher account from the repository root. The password is entered without echo and stored as a salted PBKDF2 hash in `src/teachers.json`; that local file is git-ignored.

```bash
python -m src.manage_teachers set-password teacher1
```

Set a stable secret for signed login cookies before deploying. Development uses an ephemeral secret if none is configured, which invalidates sessions when the server restarts.

```bash
export SESSION_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

For an HTTPS deployment, also set `ENVIRONMENT=production` and `COOKIE_SECURE=true`. Production startup fails if `SESSION_SECRET` is missing.

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

All data is stored in memory, which means data will be reset when the server restarts.
