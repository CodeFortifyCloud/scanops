# ScanOps

ScanOps is an internal authorized-use network/security operations platform built with Django MVT, HTML templates, and HTMX.

## Stack

- Django 4.2 (MVT)
- HTMX + server-rendered templates
- Gunicorn in Docker
- PostgreSQL in Docker (default runtime database)

## Quick Docker Deploy (Local or VPS)

1. Ensure Docker Engine + Docker Compose plugin are installed.
2. Create runtime env file once:

```bash
cp .env.example .env
```

3. Update at least:
   - `JTRO_SECRET_KEY`
   - `SCANOPS_DB_PASSWORD`
   - `JTRO_ALLOWED_HOSTS` (for VPS/public hostnames)

4. Deploy:

```bash
./scripts/deploy_and_run.sh up
```

Access:

- `http://127.0.0.1:8008/login/`
- `http://0.0.0.0:8008/login/`

## Docker Operations

```bash
./scripts/deploy_and_run.sh ps
./scripts/deploy_and_run.sh logs
./scripts/deploy_and_run.sh restart
./scripts/deploy_and_run.sh down
```

## Database Migration Helpers

Create a backup from your currently configured local DB (`.env`):

```bash
./scripts/deploy_and_run.sh backup-local-db
```

Restore a SQL backup into Docker PostgreSQL:

```bash
./scripts/deploy_and_run.sh restore-db --backup-file dbbackup/migration/<your-backup>.sql
```

You can also restore automatically during startup:

```bash
./scripts/deploy_and_run.sh up --restore-db --backup-file dbbackup/migration/<your-backup>.sql
```

## Local Non-Docker Development (Optional)

You can still run Django directly:

```bash
python manage.py migrate
python manage.py runserver 0.0.0.0:8008
```

## Docs

- Docker workflow: `DOCKER_README.md`
- Backup scheduler and restore notes: `BACKUP_README.md`

## Account Management

ScanOps includes full account self-service authentication flows:

- Register: `/register/`
- Register success: `/register/success/`
- Forgot password: `/password-reset/`
- Password reset email sent: `/password-reset/done/`
- Password reset confirm: `/reset/<uidb64>/<token>/`
- Password reset complete: `/reset/done/`
- Change password (logged-in): `/password-change/`
- Password change done: `/password-change/done/`

### Registration Policy

Registration behavior is environment-driven:

- `SCANOPS_SELF_REGISTRATION_ENABLED` (default: `True`)
- `SCANOPS_SELF_REGISTRATION_REQUIRES_APPROVAL` (default: `False`)
- `SCANOPS_SELF_REGISTRATION_DEFAULT_ROLE` (default: `viewer`)

By default, new users are created with least-privilege role `viewer`.

### Email Backend Configuration

Password reset uses Django's secure token flow and sends emails using environment variables:

- `EMAIL_BACKEND`
- `EMAIL_HOST`
- `EMAIL_PORT`
- `EMAIL_USE_TLS`
- `EMAIL_USE_SSL`
- `EMAIL_HOST_USER`
- `EMAIL_HOST_PASSWORD`
- `DEFAULT_FROM_EMAIL`

For local development, use:

- `EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend`

With console backend, reset links are printed in app logs/terminal output.

## Read Documentation Page

ScanOps includes a public product documentation page:

- URL: `/documentation/`
- Public access: available without login from the login page via **Read Documentation**
- In-app access: available from the sidebar for authenticated users via **Read Documentation**

The page documents core modules and safe operational workflow without exposing sensitive runtime data.

## Feedback Channels

ScanOps includes two feedback intake routes for users and visitors:

- Suggestions: `/feedback/suggestions/`
- Issues: `/feedback/issues/`

Suggestions capture improvement ideas. Issues capture operational defects and can include optional evidence attachments (`jpg`, `jpeg`, `png`, `webp`, `mp4`, `webm`, `mov`, max `25MB`).

## Public New Scan Access

The `New Scan` page (`/scans/new/`) is accessible in two modes:

- Visitors (not logged in): can open the page in public-safe preview mode only. Submission is blocked and they are prompted to sign in/register.
- Authenticated users (all roles): can create scan requests using user-scoped targets and profiles.

The backend enforces ownership filtering on target/profile selection and blocks anonymous POST submission.

## User-Owned Data Isolation

ScanOps enforces backend ownership filtering for operational data.

- Scoped roles (`analyst`, `operator`, `viewer`) can only access their own records.
- Global roles (`super_admin`, `security_admin`) can access all operational records.
- Isolation is applied across list views, detail views, POST actions, HTMX partial endpoints, and form dropdown querysets.

Ownership is evaluated through centralized visibility helpers in:

- `apps/ops/services/data_visibility_service.py`

### Public Schedule Access

The schedule module supports public-safe access:

- Visitors (not logged in): can browse public schedules only (`is_public=True`) in read-only mode.
- Authenticated users: can create/manage only their own schedules, and can view public schedules.
- Super Admin / Security Admin: can view and manage all schedules.

Sensitive schedule details are restricted in public mode (target/profile details are hidden).

### Ownership Backfill

If legacy rows are missing ownership references, run:

```bash
./.venv/bin/python manage.py backfill_user_ownership
```

Optional dry run:

```bash
./.venv/bin/python manage.py backfill_user_ownership --dry-run
```

## Security Note

ScanOps is intended for internal authorized-use operations only. Do not use this project to scan unauthorized systems or networks.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
