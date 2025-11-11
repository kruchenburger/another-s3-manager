# Another S3 Manager

Lightweight web-based file manager for Amazon S3 buckets built with FastAPI and Python.

## 🚀 Try it out

A live demo is available at https://s3-manager-demo.kruchenburger.com

**Demo credentials:** `admin` / `admin`

## Features

- 👥 User management (admin only)
- 🔄 Multi-account support via role assumption or direct credentials
- 🔐 User authentication with login/password
- 🔒 Granular bucket access control - grant access to specific buckets without requiring `s3:ListAllMyBuckets` permission
- 📁 Browse files and directories in S3 buckets
- 📤 Upload single files or entire folders (multiple files supported)
- 🗑️ Delete files and directories (recursively, with optional disable via config)
- ⬇️ Download files from S3 buckets
- 🔍 Search and filter files
- 🛡️ Account lockout after 3 failed login attempts (1 hour ban)
- ⚙️ Web-based configuration for managing multiple AWS accounts/roles
- 🎨 Modern, user-friendly web interface with dark/light theme support
- 📄 Virtual scrolling for large file lists (handles millions of files)
- 🍞 Breadcrumb navigation
- ⚡ Fast and lightweight

## Prerequisites

- Python 3.13
- AWS credentials configured (via AWS CLI, environment variables, or IAM role)

## Installation

### Docker (Recommended)

The easiest way to run Another S3 Manager is using Docker:

```bash
docker run -d \
  --name s3-manager \
  -p 8080:8080 \
  -e JWT_SECRET_KEY="your-secret-key-here" \
  -e ADMIN_PASSWORD="your-admin-password" \
  -v $(pwd)/config.json:/app/config.json \
  -v $(pwd)/data:/app/data \
  ghcr.io/kruchenburger/another-s3-manager:latest
```

Or using Docker Compose:

```yaml
version: '3.8'

services:
  s3-manager:
    image: ghcr.io/kruchenburger/another-s3-manager:latest
    container_name: s3-manager
    ports:
      - "8080:8080"
    environment:
      - JWT_SECRET_KEY=your-secret-key-here
      - ADMIN_PASSWORD=your-admin-password
      - AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
      - AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
      - AWS_REGION=${AWS_REGION}
    volumes:
      - ./config.json:/app/config.json
      - ./data:/app/data
    restart: unless-stopped
```

**Available image tags:**
- `latest` - Latest stable release
- `v0.1.0` - Specific version
- `main` - Latest commit from main branch
- `main-<sha>` - Specific commit from main branch

### Python Installation

**Important:** Always use a virtual environment to isolate project dependencies.

#### Using uv (Recommended)

1. Install [uv](https://github.com/astral-sh/uv) (if not already installed):
```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

2. Create and activate a virtual environment:
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

3. Install dependencies:
```bash
uv pip install .
```
4. (Optional) Install development/test dependencies:
```bash
uv pip install ".[dev]"
```

#### Using pip

1. Create and activate a virtual environment:
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install .
```
3. (Optional) Install development/test dependencies:
```bash
pip install ".[dev]"
```
4. Set up environment variables (create `.env` file):
```bash
JWT_SECRET_KEY=your-secret-key-here
ADMIN_PASSWORD=change_me_pls
```

5. Run the application:
```bash
python main.py
```

## Configuration

### Default Credentials

The application uses AWS credentials from your environment. Make sure you have one of the following configured:

- AWS CLI profile: `aws configure`
- Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`
- IAM role (if running on EC2/ECS)

### Multi-Account Configuration

You can configure multiple AWS accounts/roles through the web interface:

1. Click the "⚙️ Configure" button in the interface
2. Edit the JSON configuration to add roles

Supported role types:

- **default**: Use default AWS credentials from environment
- **profile**: Use AWS profile from `~/.aws/credentials` (requires `profile_name`)
- **assume_role**: Assume an IAM role (requires `role_arn`)
- **credentials**: Use direct credentials (requires `access_key_id`, `secret_access_key`, optional `region`)
- **S3-compatible endpoints**: Any role type can optionally specify `endpoint_url`, `use_ssl`, `verify_ssl`, and `path_style`/`addressing_style` for services like MinIO, Wasabi, or Cloudflare R2

Example configuration:

```json
{
  "items_per_page": 200,
  "disable_deletion": false,
  "enable_lazy_loading": false,
  "max_file_size": 104857600, // 100MB
  "roles": [
    {
      "name": "Default",
      "type": "default",
      "description": "Use default AWS credentials"
    },
    {
      "name": "Production Profile",
      "type": "profile",
      "profile_name": "prod-profile",
      "description": "Production account using AWS profile"
    },
    {
      "name": "Production Account",
      "type": "assume_role",
      "role_arn": "arn:aws:iam::123456789012:role/S3AccessRole",
      "description": "Production account via role assumption"
    },
    {
      "name": "Dev Account",
      "type": "credentials",
      "access_key_id": "AKIA...",
      "secret_access_key": "...",
      "region": "eu-central-1",
      "description": "Development account with direct credentials"
    },
    {
      "name": "Local MinIO",
      "type": "credentials",
      "access_key_id": "minioadmin",
      "secret_access_key": "minioadmin",
      "endpoint_url": "http://localhost:9000",
      "use_ssl": false,
      "verify_ssl": false,
      "path_style": true,
      "description": "Example of connecting to a S3-compatible MinIO server"
    }
  ]
}
```

The configuration is saved in `config.json` in the application directory. You can copy `config.json.example` to `config.json` as a starting point.

### Configuration Options

- `roles` - Array of AWS role configurations
- `items_per_page` - Number of files to display per page (default: 200, can be overridden by `ITEMS_PER_PAGE` env var)
- `disable_deletion` - Set to `true` to disable file deletion (default: `false`, can be overridden by `DISABLE_DELETION=true` env var)
- `enable_lazy_loading` - Enable automatic lazy loading on scroll (default: `true`, can be overridden by `ENABLE_LAZY_LOADING` env var). If set to `false`, users must click "Click to load more..." to load additional files
- `max_file_size` - Maximum file size for uploads in bytes (default: 104857600 = 100MB, can be overridden by `MAX_FILE_SIZE` env var)
- `data_dir` - Directory path for storing `users.json` and `bans.json` files (useful for Kubernetes volumes). Can also be set via `DATA_DIR` environment variable (default: application directory)
- `endpoint_url` (per role) - Custom S3-compatible endpoint (e.g., `http://minio:9000`)
- `use_ssl` / `verify_ssl` (per role) - Override SSL usage and certificate verification flags
- `path_style` / `addressing_style` (per role) - Force path-style addressing (required for MinIO running behind an IP/localhost)

**Note**: Changes to `config.json` are automatically reloaded by the application.

## Running the Application

### Docker

If you're using Docker, the container will start automatically. Make sure to:
1. Set the `JWT_SECRET_KEY` environment variable (required)
2. Mount volumes for `config.json` and data directory (optional but recommended)
3. Configure AWS credentials via environment variables or mounted AWS config files

### Development Mode

Start the server:
```bash
python main.py
```

Or using uvicorn directly:
```bash
uvicorn main:app --host 0.0.0.0 --port 8080 --reload
```

### Production Mode

For production, it's **strongly recommended** to run uvicorn behind a reverse proxy (nginx, Traefik, etc.) for:
- SSL/TLS termination
- Security headers
- Rate limiting
- Compression
- Better performance

**Docker users:** You can run the container behind a reverse proxy by exposing the container port and configuring your reverse proxy to forward requests to it.

## Usage

1. Open your browser and navigate to `http://localhost:8080` (or the port specified by `PORT` env var)
2. Login with your credentials (default: `admin` / password from `ADMIN_PASSWORD` env var or `change_me_pls`)
3. (Optional) Select an role from the "Role" dropdown, or configure new roles using the "⚙️ Configure" button
4. Select a bucket from the dropdown (if only one bucket is available, it will be selected automatically)
5. Navigate through folders by clicking on directory names or using breadcrumbs
6. Upload files using the "Upload Files" button (supports multiple files) or drag-and-drop
7. Upload folders using the "Upload Folder" button or drag-and-drop
8. Download files using the "⬇️ Download" button next to each file
9. Delete files or folders using the delete button (if deletion is enabled)
10. Use the search box to filter files by name
11. Select multiple files using checkboxes and delete them all at once

### Admin Panel

Admins can access the admin panel at `/admin` to:
- Create and delete users
- View and unban banned users
- Manage user privileges

### Security Features

- **Login Protection**: After 3 failed login attempts, account is banned for 1 hour
- **JWT Tokens**: Authentication uses JWT tokens with configurable expiration (default: 3 hours)
- **Password Hashing**: Passwords are hashed using bcrypt
- **Admin Privileges**: Only admins can access admin panel and manage users

## Environment Variables

Environment variables can be set in three ways (in order of priority):
1. **System environment variables** (highest priority)
2. **`.env` file** in the application directory (recommended for local development)
3. **Default values** (lowest priority)

The application automatically loads variables from a `.env` file if it exists. Create a `.env` file in the application directory (you can copy `.env.example` as a template).

| Variable                          | Description                                                                                                                                                               | Default Value                          |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| `PORT`                            | Server port                                                                                                                                                               | `8080`                                 |
| `AWS_REGION`                      | AWS region                                                                                                                                                                | Uses default region if not set         |
| `S3_FILE_MANAGER_CONFIG`          | Path to configuration file                                                                                                                                                | `config.json` in application directory |
| `DATA_DIR`                        | Directory path for storing `users.json` and `bans.json` files (useful for Kubernetes volumes). Can also be set in `config.json` as `"data_dir"`                           | Application directory                  |
| `ADMIN_PASSWORD`                  | Password for default admin user                                                                                                                                           | `change_me_pls`                        |
| `JWT_SECRET_KEY`                  | **REQUIRED** - Secret key for JWT tokens. Application will not start without this variable. Generate with: `python -c 'import secrets; print(secrets.token_urlsafe(32))'` | **Required** (no default)              |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | JWT token expiration time in minutes                                                                                                                                      | `180` (3 hours)                        |
| `ITEMS_PER_PAGE`                  | Number of items to display per page in file list (can also be set in `config.json`)                                                                                       | `200`                                  |
| `DISABLE_DELETION`                | Set to `true` to disable file deletion functionality (can also be set in `config.json` as `"disable_deletion": true`)                                                     | `false`                                |
| `MAX_FILE_SIZE`                   | Maximum file size for uploads in bytes                                                                                                                                    | `104857600` (100MB)                    |
| `ENABLE_LAZY_LOADING`             | Enable automatic lazy loading on scroll. If set to `false`, users must click "Click to load more..." to load additional files                                             | `true`                                 |
| `LOG_LEVEL`                       | Logging level for uvicorn (debug, info, warning, error, critical)                                                                                                         | `info`                                 |
| `UVICORN_HOST`                    | Host address to bind uvicorn server to                                                                                                                                    | `0.0.0.0`                              |

## Docker Volumes

When running with Docker, you can mount volumes for persistent storage:

- `/app/config.json` - Configuration file (optional, can be created via web UI)
- `/app/data` - Directory for `users.json` and `bans.json` (optional, defaults to `/app`)

Example with volumes:
```bash
docker run -d \
  -p 8080:8080 \
  -e JWT_SECRET_KEY="your-secret-key" \
  -v $(pwd)/config.json:/app/config.json \
  -v $(pwd)/data:/app/data \
  ghcr.io/kruchenburger/another-s3-manager:latest
```

## Notes

- **`.env` file**: Create a `.env` file in the application directory to set environment variables locally. The `.env` file is automatically ignored by git for security. See `.env.example` for a template.
- **Change default password**: Set `ADMIN_PASSWORD` environment variable
- **JWT_SECRET_KEY**: **REQUIRED** - Application will not start without this variable. Generate one with: `python -c 'import secrets; print(secrets.token_urlsafe(32))'`
- **JWT Token Expiration**: Default is 3 hours (180 minutes). Can be changed via `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` environment variable
- **Use HTTPS**: Always use HTTPS in production environments
- **S3 Access**: This application provides full access to your S3 buckets - ensure proper IAM policies are in place
- **File Storage**: User data and bans are stored in `users.json` and `bans.json` files - secure these files appropriately
- **Docker Image**: Official Docker images are available on [GitHub Container Registry](https://github.com/kruchenburger/another-s3-manager/pkgs/container/another-s3-manager)

### Required S3 IAM Policy

The application requires the following S3 permissions to function properly. Here's an example IAM policy:

**Option 1: With bucket listing (requires `s3:ListAllMyBuckets` permission):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::YOUR-BUCKET-NAME/*"
    }
  ]
}
```

**Option 2: Without bucket listing (more secure, recommended):**

If you want to avoid giving `s3:ListAllMyBuckets` permission, you can specify allowed buckets in the role configuration:

1. Go to Admin Console → Configuration
2. Edit the role
3. In the "Allowed Buckets" field, enter a comma-separated list of bucket names (e.g., `bucket1,bucket2,bucket3`)
4. Save the configuration

With this approach, you only need permissions for specific buckets:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::YOUR-BUCKET-NAME/*"
    }
  ]
}
```

**Required S3 Actions:**
- `s3:ListAllMyBuckets` - List all buckets in account (only needed if `allowed_buckets` is not configured)
- `s3:GetObject` - Download files from S3
- `s3:PutObject` - Upload files to S3
- `s3:DeleteObject` - Delete files from S3

**For cross-account access** (when using `assume_role`), the role being assumed must also have these permissions, and the source account must have permission to assume the role.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines and development setup instructions.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes and version history.

## MinIO Demo Environment

Want to try the UI without touching your AWS account? A ready-to-run MinIO demo is available via Docker Compose:

```bash
docker compose -f docker-compose-demo.yml up
```

This spin ups three services:

- `minio` – local S3-compatible storage with a 1&nbsp;GiB quota applied to the demo bucket
- `minio-init` – one-shot helper that creates the `s3-demo` bucket and enforces the quota
- `s3-manager-demo` – the application container, preconfigured to talk to MinIO using the config in `demo/config.minio.json`

Once running, open `http://localhost:8080` (app) and `http://localhost:9001` (MinIO console). Default credentials defined in the Compose file are suitable for local testing only—change them before deploying anywhere else.
