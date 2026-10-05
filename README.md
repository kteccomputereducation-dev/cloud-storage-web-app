# Cloud File Storage System

A Flask-based web application that simulates a personal cloud storage service
(similar in spirit to Google Drive / Dropbox), built as an academic mini-project.

## Features

- User registration & login (passwords hashed with Werkzeug's PBKDF2)
- Per-user storage quota (default 500 MB) with a live usage meter
- File upload (multi-file), download, rename, delete
- Folder creation and nested folder navigation with breadcrumbs
- File search by name
- Shareable, expiring download links (valid 7 days)
- SHA-256 checksum stored for every uploaded file (integrity verification)
- Admin panel: view all users, their storage usage, and recent activity log
- JSON API endpoints (`/api/files`, `/api/usage`) for programmatic access

## Architecture

- **Backend:** Python 3 + Flask
- **Database:** SQLite (metadata: users, folders, files, share links, activity log)
- **File storage:** Local filesystem, one directory per user
  (`uploads/<user_id>/<uuid>_<original_filename>`) — mirrors how real cloud
  storage systems separate metadata (DB) from blob storage (object store)
- **Frontend:** Server-rendered Jinja2 templates + vanilla CSS (no JS framework)
- **Auth:** Flask sessions, `werkzeug.security` password hashing

## Setup

```bash
cd app
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Visit **http://127.0.0.1:5000**. The database and default admin account
(`admin` / `admin123`) are created automatically on first run.

## Project Structure

```
app/
├── app.py                 # Flask application (routes, models, logic)
├── requirements.txt
├── instance/
│   └── cloud_storage.db    # SQLite database (auto-created)
├── uploads/                 # Per-user file storage (auto-created)
├── static/
│   └── css/style.css
└── templates/
    ├── base.html
    ├── login.html
    ├── register.html
    ├── dashboard.html
    ├── search.html
    ├── admin.html
    └── error.html
```

## Database Schema

| Table | Purpose |
|---|---|
| `users` | Account credentials, quota, admin flag |
| `folders` | Nested folder hierarchy per user |
| `files` | File metadata (name, size, checksum, owning folder) |
| `share_links` | Expiring public download tokens |
| `activity_log` | Audit trail of logins, uploads, deletes, shares |

## Possible Extensions

- Replace local filesystem with S3 / MinIO for real object storage
- Add file versioning and a recycle bin (soft delete)
- Server-side file preview (images, PDFs) instead of forced download
- Two-factor authentication
- Chunked/resumable uploads for very large files
