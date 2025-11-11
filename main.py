"""
Another S3 Manager - Lightweight S3 file management interface
Provides file browsing, upload, and deletion capabilities for S3 buckets
"""
import os
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import timedelta

# Load environment variables from .env file (if it exists)
# This must be done before importing modules that use environment variables
try:
    from dotenv import load_dotenv
    # Load .env file from the same directory as this file
    env_path = Path(__file__).parent / '.env'
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
    else:
        # Also try to load from current working directory
        load_dotenv()
except ImportError:
    # python-dotenv is optional, continue without it
    pass

from fastapi import FastAPI, UploadFile, File, HTTPException, Query, Form, Body, Depends, status, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from botocore.exceptions import ClientError, BotoCoreError
from io import BytesIO

from constants import APP_NAME, APP_DESCRIPTION, APP_VERSION, STATIC_DIR
from config import load_config, save_config, get_config_value
from auth import (
    verify_password, create_access_token, get_current_user, verify_csrf_token,
    get_current_admin_user, check_ban, record_login_attempt, hash_password,
    generate_csrf_token, get_jwt_secret_key
)
from users import (
    load_users, save_users, load_bans, save_bans, get_user_by_username,
    get_all_users, create_user, update_user, delete_user, get_available_roles
)
from s3_client import get_s3_client, clear_s3_clients_cache
from utils import sanitize_path, sanitize_bucket_name, format_boto_error

# Validate required environment variables at startup
try:
    get_jwt_secret_key()
except ValueError as e:
    print(f"ERROR: {e}")
    print("Please set the JWT_SECRET_KEY environment variable.")
    print("Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(32))'")
    import sys
    sys.exit(1)

app = FastAPI(title=APP_NAME, description=APP_DESCRIPTION)

# Exception handler to ensure all errors return JSON
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )

# Mount static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Clear S3 clients cache when config changes (hook into config module)
def _on_config_change():
    """Callback when config changes to clear S3 clients cache."""
    clear_s3_clients_cache()

# Hook config save to clear cache
_original_save_config = save_config
def save_config_with_cache_clear(config: Dict[str, Any]) -> None:
    """Wrapper for save_config that clears S3 cache."""
    _original_save_config(config)
    _on_config_change()

# Update config module's save_config to use our wrapper
import config as config_module
config_module.save_config = save_config_with_cache_clear


# ============================================================================
# Routes
# ============================================================================


@app.get("/", response_class=HTMLResponse)
async def root():
    """Main page with file manager interface (auth handled by frontend)"""
    html_file = STATIC_DIR / "index.html"
    with open(html_file, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    """Login page"""
    html_file = STATIC_DIR / "login.html"
    with open(html_file, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.post("/api/login")
async def login(username: str = Form(...), password: str = Form(...)):
    """Login endpoint"""
    try:
        # Check if user is banned
        if check_ban(username):
            bans = load_bans()
            ban_data = bans.get(username, {})
            banned_until = ban_data.get("banned_until", 0)
            import time
            remaining = int((banned_until - time.time()) / 60)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account is banned. Try again in {remaining} minutes."
            )

        users = load_users()
        user = next((u for u in users.get("users", []) if u.get("username") == username), None)

        if user is None:
            record_login_attempt(username, False)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password"
            )

        # Verify password
        if not verify_password(password, user.get("password_hash", "")):
            record_login_attempt(username, False)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password"
            )

        # Successful login
        record_login_attempt(username, True)

        # Generate CSRF token and include in JWT
        csrf_token = generate_csrf_token()
        access_token = create_access_token(data={"sub": username, "csrf_token": csrf_token})
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "csrf_token": csrf_token,  # Also return CSRF token separately for convenience
            "user": {"username": username, "is_admin": user.get("is_admin", False)}
        }
    except HTTPException:
        raise
    except Exception as e:
        # Log the error for debugging
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login failed: {str(e)}"
        )


@app.get("/api/me")
async def get_current_user_info(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get current user information"""
    return {
        "username": current_user.get("username"),
        "is_admin": current_user.get("is_admin", False),
        "csrf_token": current_user.get("csrf_token"),  # Return CSRF token for client
        "theme": current_user.get("theme", "auto"),  # Return user's theme preference
        "app_name": APP_NAME,  # Return app name for client
        "app_version": APP_VERSION,
    }


@app.get("/api/app-info")
async def get_app_info():
    """Get application information (public endpoint)"""
    # Check if demo mode is enabled via environment variable
    is_demo = os.getenv("DEMO_MODE", "").lower() == "true"
    demo_bucket_limit = os.getenv("DEMO_BUCKET_LIMIT", "")

    return {
        "app_name": APP_NAME,
        "app_description": APP_DESCRIPTION,
        "app_version": APP_VERSION,
        "is_demo": is_demo,
        "demo_bucket_limit": demo_bucket_limit if is_demo else None,
    }


@app.get("/admin", response_class=HTMLResponse)
async def admin_page():
    """Admin page (authentication checked on client side)"""
    html_file = STATIC_DIR / "admin.html"
    with open(html_file, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/api/admin/users")
async def list_users(current_user: Dict[str, Any] = Depends(get_current_admin_user)):
    """List all users (admin only)"""
    users = load_users()
    # Always reload config to get latest roles
    config = load_config(force_reload=True)
    available_roles = [role.get("name") for role in config.get("roles", [])]

    # Don't return password hashes
    user_list = []
    for user in users.get("users", []):
        user_list.append({
            "username": user.get("username"),
            "is_admin": user.get("is_admin", False),
            "created_at": user.get("created_at"),
            "allowed_roles": user.get("allowed_roles", [])
        })
    return {
        "users": user_list,
        "available_roles": available_roles
    }


@app.post("/api/admin/users")
async def create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    is_admin: bool = Form(False),
    allowed_roles: str = Form("", description="Comma-separated list of allowed role names"),
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    csrf_verified: bool = Depends(verify_csrf_token)
):
    """Create a new user (admin only)"""
    users = load_users()

    # Check if user already exists
    if any(u.get("username") == username for u in users.get("users", [])):
        raise HTTPException(status_code=400, detail="User already exists")

    # Hash password
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        password = password_bytes[:72].decode('utf-8', errors='ignore')

    # Hash password using auth module
    hashed_password = hash_password(password)

    # Parse allowed roles
    roles_list = [r.strip() for r in allowed_roles.split(",") if r.strip()] if allowed_roles else []

    # Import datetime for timestamp
    from datetime import datetime
    new_user = {
        "username": username,
        "password_hash": hashed_password,
        "is_admin": is_admin,
        "allowed_roles": roles_list,
        "theme": "auto",  # Default to auto (system preference)
        "created_at": datetime.now().isoformat()
    }

    users.setdefault("users", []).append(new_user)
    save_users(users)

    return {"message": "User created successfully", "username": username}


@app.put("/api/admin/users/{username}/password")
async def update_user_password(
    request: Request,
    username: str,
    password: str = Body(..., embed=True, description="New password"),
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    csrf_verified: bool = Depends(verify_csrf_token)
):
    """Update user password (admin only)"""
    if not password or len(password.strip()) == 0:
        raise HTTPException(status_code=400, detail="Password cannot be empty")

    users = load_users()
    user = next((u for u in users.get("users", []) if u.get("username") == username), None)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Hash password using auth module
    hashed_password = hash_password(password)

    user["password_hash"] = hashed_password
    save_users(users)

    return {"message": f"Password updated successfully for user {username}"}


@app.put("/api/admin/users/{username}")
async def update_user(
    request: Request,
    username: str,
    is_admin: Optional[bool] = Form(None),
    allowed_roles: Optional[str] = Form(None, description="Comma-separated list of allowed role names"),
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    csrf_verified: bool = Depends(verify_csrf_token)
):
    """Update user permissions (admin only)"""
    users = load_users()
    user = next((u for u in users.get("users", []) if u.get("username") == username), None)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Update fields if provided
    if is_admin is not None:
        user["is_admin"] = is_admin

    if allowed_roles is not None:
        roles_list = [r.strip() for r in allowed_roles.split(",") if r.strip()] if allowed_roles else []
        user["allowed_roles"] = roles_list

    save_users(users)
    return {"message": f"User {username} updated successfully"}


@app.put("/api/user/theme")
async def update_user_theme(
    request: Request,
    theme: str = Body(..., embed=True, description="Theme preference: 'light' or 'dark' (auto only for initial state)"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    csrf_verified: bool = Depends(verify_csrf_token)
):
    """Update user's theme preference"""
    # Allow only 'light' or 'dark' for manual changes (auto is only for initial state)
    if theme not in ["light", "dark"]:
        raise HTTPException(status_code=400, detail="Theme must be 'light' or 'dark'")

    users = load_users()
    user = next((u for u in users.get("users", []) if u.get("username") == current_user.get("username")), None)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user["theme"] = theme
    save_users(users)

    return {"message": f"Theme updated to {theme}", "theme": theme}


@app.delete("/api/admin/users/{username}")
async def delete_user(
    request: Request,
    username: str,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    csrf_verified: bool = Depends(verify_csrf_token)
):
    """Delete a user (admin only)"""
    if username == current_user.get("username"):
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    users = load_users()
    users["users"] = [u for u in users.get("users", []) if u.get("username") != username]
    save_users(users)

    return {"message": f"User {username} deleted successfully"}


@app.get("/api/admin/bans")
async def list_bans(current_user: Dict[str, Any] = Depends(get_current_admin_user)):
    """List all banned users (admin only)"""
    bans = load_bans()
    ban_list = []
    import time
    current_time = time.time()
    for username, ban_data in bans.items():
        banned_until = ban_data.get("banned_until", 0)
        remaining = int((banned_until - current_time) / 60)
        ban_list.append({
            "username": username,
            "banned_until": banned_until,
            "banned_at": ban_data.get("banned_at"),
            "reason": ban_data.get("reason"),
            "remaining_minutes": remaining if remaining > 0 else 0
        })
    return {"bans": ban_list}


@app.delete("/api/admin/bans/{username}")
async def unban_user(
    request: Request,
    username: str,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    csrf_verified: bool = Depends(verify_csrf_token)
):
    """Unban a user (admin only)"""
    bans = load_bans()
    if username in bans:
        del bans[username]
        save_bans(bans)
        # Login attempts are managed in auth module, no need to reset here
        return {"message": f"User {username} unbanned successfully"}
    else:
        raise HTTPException(status_code=404, detail="User is not banned")


@app.get("/api/config")
async def get_config(
    force_reload: bool = Query(False, description="Force reload from file"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get current configuration (filtered by user permissions)."""
    config = load_config(force_reload=force_reload)

    # Get items_per_page from config file, fallback to environment variable, then default
    items_per_page = config.get("items_per_page")
    if items_per_page is None:
        items_per_page = int(os.getenv("ITEMS_PER_PAGE", "200"))
    else:
        items_per_page = int(items_per_page)

    # Check if deletion is disabled (from environment variable or config)
    disable_deletion_env = os.getenv("DISABLE_DELETION", "").lower() == "true"
    disable_deletion_config = config.get("disable_deletion", False)
    disable_deletion = disable_deletion_env or disable_deletion_config

    # Get enable_lazy_loading from config file, fallback to environment variable, then default
    enable_lazy_loading = config.get("enable_lazy_loading")
    if enable_lazy_loading is None:
        enable_lazy_loading = os.getenv("ENABLE_LAZY_LOADING", "true").lower() == "true"
    else:
        enable_lazy_loading = bool(enable_lazy_loading)

    # Get max_file_size from config file, fallback to environment variable, then default
    max_file_size = config.get("max_file_size")
    if max_file_size is None:
        max_file_size = int(os.getenv("MAX_FILE_SIZE", str(100 * 1024 * 1024)))
    else:
        max_file_size = int(max_file_size)

    # Create a safe copy without secret credentials
    def sanitize_role(role: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive secret credentials from role (keep access_key_id as it's not secret)"""
        sanitized = role.copy()
        # Remove secret_access_key completely from API response (don't show it at all)
        if "secret_access_key" in sanitized:
            del sanitized["secret_access_key"]
        # Keep access_key_id, role_arn and profile_name as they're not sensitive
        return sanitized

    # If user is admin, return config but without credentials
    if current_user.get("is_admin", False):
        from config import is_config_writable
        # Apply default_role if specified
        default_role = config.get("default_role", "")
        if default_role and any(r.get("name") == default_role for r in config.get("roles", [])):
            effective_role = default_role
        else:
            # Use first role if default_role is not set or invalid
            effective_role = config.get("roles", [{}])[0].get("name", "") if config.get("roles") else ""

        safe_config = {
            "roles": [sanitize_role(role) for role in config.get("roles", [])],
            "default_role": default_role,  # Return default_role so admin can see/edit it
            "current_role": effective_role,  # Computed value for frontend (not stored in config)
            "items_per_page": items_per_page,
            "disable_deletion": disable_deletion,
            "enable_lazy_loading": enable_lazy_loading,
            "max_file_size": max_file_size,
            "is_read_only": not is_config_writable()
        }
        return safe_config

    # For regular users, filter roles by permissions
    users = load_users()
    user = next((u for u in users.get("users", []) if u.get("username") == current_user.get("username")), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Get allowed roles for this user
    allowed_roles = user.get("allowed_roles", [])
    if not allowed_roles:
        # No roles allowed, return empty config with all required fields
        return {
            "roles": [],
            "current_role": "",
            "items_per_page": items_per_page,
            "disable_deletion": disable_deletion,
            "enable_lazy_loading": enable_lazy_loading,
            "max_file_size": max_file_size
        }

    # Filter roles and sanitize
    filtered_roles = [
        sanitize_role(role) for role in config.get("roles", [])
        if role.get("name") in allowed_roles
    ]

    # Apply default_role if specified and available
    default_role = config.get("default_role", "")

    # If default_role is set and is in allowed_roles, use it
    if default_role and default_role in allowed_roles:
        effective_role = default_role
    # Otherwise, use first allowed role or empty
    else:
        effective_role = allowed_roles[0] if allowed_roles else ""

    return {
        "roles": filtered_roles,
        "current_role": effective_role,
        "items_per_page": items_per_page,
        "disable_deletion": disable_deletion,
        "enable_lazy_loading": enable_lazy_loading,
        "max_file_size": max_file_size
    }


@app.get("/api/config/export")
async def export_config(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Export full configuration as JSON (admin only)"""
    if not current_user.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required to export configuration"
        )

    config = load_config(force_reload=True)

    # Return as JSON response with download headers
    from fastapi.responses import Response
    import json
    json_str = json.dumps(config, indent=2, ensure_ascii=False)
    return Response(
        content=json_str,
        media_type="application/json",
        headers={
            "Content-Disposition": "attachment; filename=config.json"
        }
    )


@app.post("/api/config")
async def update_config(
    request: Request,
    config: Dict[str, Any] = Body(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
    csrf_verified: bool = Depends(verify_csrf_token)
):
    """Update configuration (admin only)"""
    # Only admins can update config
    if not current_user.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required to update configuration"
        )

    # Check if config is read-only
    from config import is_config_writable
    if not is_config_writable():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The application does not have write access to the configuration file (e.g., mounted as read-only from Kubernetes ConfigMap). Configuration management must be handled externally."
        )

    try:
        # Validate config structure
        if "roles" not in config:
            raise HTTPException(status_code=400, detail="Invalid config structure: 'roles' is required")

        # Handle items_per_page - if provided, validate and use it; otherwise preserve existing
        if "items_per_page" in config:
            # Validate items_per_page
            try:
                items_per_page_val = int(config["items_per_page"])
                if items_per_page_val < 10 or items_per_page_val > 1000:
                    raise HTTPException(status_code=400, detail="items_per_page must be between 10 and 1000")
            except (ValueError, TypeError):
                raise HTTPException(status_code=400, detail="items_per_page must be a valid integer")
        else:
            # Preserve items_per_page from current config if not provided
            current_config = load_config(force_reload=False)
            if "items_per_page" in current_config:
                config["items_per_page"] = current_config["items_per_page"]

        # Handle enable_lazy_loading - if provided, validate and use it; otherwise preserve existing or use env var/default
        if "enable_lazy_loading" in config:
            # Validate enable_lazy_loading (must be boolean)
            if not isinstance(config["enable_lazy_loading"], bool):
                raise HTTPException(status_code=400, detail="enable_lazy_loading must be a boolean")
        else:
            # Preserve enable_lazy_loading from current config if exists, otherwise use env var or default
            current_config = load_config(force_reload=False)
            if "enable_lazy_loading" in current_config:
                config["enable_lazy_loading"] = current_config["enable_lazy_loading"]
            else:
                # Use env var or default if not in config
                config["enable_lazy_loading"] = os.getenv("ENABLE_LAZY_LOADING", "true").lower() == "true"

        # Handle max_file_size - if provided, validate and use it; otherwise preserve existing or use env var/default
        if "max_file_size" in config:
            # Validate max_file_size
            try:
                max_file_size_val = int(config["max_file_size"])
                if max_file_size_val < 1024:  # At least 1KB
                    raise HTTPException(status_code=400, detail="max_file_size must be at least 1024 bytes (1KB)")
            except (ValueError, TypeError):
                raise HTTPException(status_code=400, detail="max_file_size must be a valid integer")
        else:
            # Preserve max_file_size from current config if exists, otherwise use env var or default
            current_config = load_config(force_reload=False)
            if "max_file_size" in current_config:
                config["max_file_size"] = current_config["max_file_size"]
            else:
                # Use env var or default if not in config
                config["max_file_size"] = int(os.getenv("MAX_FILE_SIZE", str(100 * 1024 * 1024)))

        # Validate roles and preserve existing secret_access_key if not provided
        current_config = load_config(force_reload=False)
        current_roles = {r.get("name"): r for r in current_config.get("roles", [])}

        for role in config.get("roles", []):
            if "name" not in role or "type" not in role:
                raise HTTPException(status_code=400, detail="Role must have 'name' and 'type'")

            role_type = role.get("type")
            if role_type == "assume_role" and "role_arn" not in role:
                raise HTTPException(status_code=400, detail="assume_role type requires 'role_arn'")
            elif role_type == "credentials":
                if "access_key_id" not in role:
                    raise HTTPException(status_code=400, detail="credentials type requires 'access_key_id'")

                # Validate and clean access_key_id
                access_key_id = role.get("access_key_id", "").strip()
                if not access_key_id:
                    raise HTTPException(status_code=400, detail="access_key_id cannot be empty")

                # Validate AWS format (should start with AKIA and be 20 characters)
                import re
                if not re.match(r'^AKIA[0-9A-Z]{16}$', access_key_id):
                    raise HTTPException(status_code=400, detail="Invalid access_key_id format. AWS access keys should start with AKIA and be 20 characters long")

                role["access_key_id"] = access_key_id  # Save trimmed value

                # Handle secret_access_key: if not provided or is REDACTED, preserve existing from config
                secret_access_key = role.get("secret_access_key", "").strip() if role.get("secret_access_key") else ""
                role_name = role.get("name")

                if not secret_access_key or secret_access_key == "***REDACTED***":
                    # Preserve existing secret_access_key from current config (for editing existing role)
                    if role_name in current_roles:
                        existing_secret = current_roles[role_name].get("secret_access_key", "")
                        if existing_secret and existing_secret != "***REDACTED***":
                            role["secret_access_key"] = existing_secret
                        else:
                            raise HTTPException(status_code=400, detail=f"secret_access_key is required for role '{role_name}'. Please provide it.")
                    else:
                        # New role - secret_access_key is required
                        raise HTTPException(status_code=400, detail="secret_access_key is required for new credentials role")
                else:
                    # New secret_access_key provided, use it
                    role["secret_access_key"] = secret_access_key

            elif role_type == "s3_compatible":
                if "access_key_id" not in role:
                    raise HTTPException(status_code=400, detail="s3_compatible type requires 'access_key_id'")
                if "endpoint_url" not in role:
                    raise HTTPException(status_code=400, detail="s3_compatible type requires 'endpoint_url'")

                # Validate and clean access_key_id (no format validation for S3-compatible services)
                access_key_id = role.get("access_key_id", "").strip()
                if not access_key_id:
                    raise HTTPException(status_code=400, detail="access_key_id cannot be empty")

                endpoint_url = role.get("endpoint_url", "").strip()
                if not endpoint_url:
                    raise HTTPException(status_code=400, detail="endpoint_url cannot be empty")

                role["access_key_id"] = access_key_id  # Save trimmed value
                role["endpoint_url"] = endpoint_url  # Save trimmed value

                # Handle secret_access_key: if not provided or is REDACTED, preserve existing from config
                secret_access_key = role.get("secret_access_key", "").strip() if role.get("secret_access_key") else ""
                role_name = role.get("name")

                if not secret_access_key or secret_access_key == "***REDACTED***":
                    # Preserve existing secret_access_key from current config (for editing existing role)
                    if role_name in current_roles:
                        existing_secret = current_roles[role_name].get("secret_access_key", "")
                        if existing_secret and existing_secret != "***REDACTED***":
                            role["secret_access_key"] = existing_secret
                        else:
                            raise HTTPException(status_code=400, detail=f"secret_access_key is required for role '{role_name}'. Please provide it.")
                    else:
                        # New role - secret_access_key is required
                        raise HTTPException(status_code=400, detail="secret_access_key is required for new s3_compatible role")
                else:
                    # New secret_access_key provided, use it
                    role["secret_access_key"] = secret_access_key

            elif role_type == "profile":
                if "profile_name" not in role:
                    raise HTTPException(status_code=400, detail="profile type requires 'profile_name'")

        save_config(config)
        return {"message": "Configuration updated successfully"}
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update config: {str(e)}")


def validate_role_access(role_name: Optional[str], current_user: Dict[str, Any]) -> Optional[str]:
    """Validate that user has access to the specified role"""
    if role_name is None:
        return None

    # Admins have access to all roles
    if current_user.get("is_admin", False):
        return role_name

    # Check if user has access to this role
    users = load_users()
    user = next((u for u in users.get("users", []) if u.get("username") == current_user.get("username")), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    allowed_roles = user.get("allowed_roles", [])
    if role_name not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail=f"Access denied: You don't have permission to use role '{role_name}'"
        )

    return role_name


@app.get("/api/buckets")
async def list_buckets(
    role: Optional[str] = Query(None, description="Role name to use"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """List available S3 buckets - either from allowed_buckets config or by listing all buckets"""
    try:
        # Validate role access
        validated_role = validate_role_access(role, current_user)

        # Load config to check for allowed_buckets
        from config import load_config
        config = load_config(force_reload=False)
        roles = config.get("roles", [])

        # Find the role configuration
        role_config = None
        if validated_role:
            role_config = next((r for r in roles if r.get("name") == validated_role), None)
        else:
            # Use first role
            role_config = roles[0] if roles else None

        # Check if role has allowed_buckets configured
        if role_config and "allowed_buckets" in role_config and role_config["allowed_buckets"]:
            # Return configured buckets without requiring list_buckets permission
            allowed_buckets = role_config["allowed_buckets"]
            if isinstance(allowed_buckets, list):
                # Verify buckets exist and user has access (optional - can be disabled for performance)
                # For now, just return the list as-is
                return allowed_buckets
            else:
                raise HTTPException(status_code=400, detail="allowed_buckets must be a list")

        # Fallback to listing all buckets (requires s3:ListAllMyBuckets permission)
        s3_client = get_s3_client(validated_role)
        response = s3_client.list_buckets()
        buckets = [bucket['Name'] for bucket in response['Buckets']]
        return buckets
    except HTTPException:
        raise
    except (ClientError, BotoCoreError) as e:
        error_message = format_boto_error(e)
        raise HTTPException(status_code=500, detail=f"Failed to list buckets: {error_message}")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # Catch other AWS-related exceptions (like UnauthorizedSSOTokenError)
        error_message = format_boto_error(e)
        raise HTTPException(status_code=500, detail=f"Failed to list buckets: {error_message}")


@app.get("/api/buckets/{bucket_name}/files")
async def list_files(
    bucket_name: str,
    path: str = Query("", description="Path prefix to list files from"),
    role: Optional[str] = Query(None, description="Role name to use"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """List files and directories in a bucket at the specified path"""
    try:
        # Validate and sanitize inputs
        try:
            bucket_name = sanitize_bucket_name(bucket_name)
            path = sanitize_path(path)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        # Validate role access
        validated_role = validate_role_access(role, current_user)
        s3_client = get_s3_client(validated_role)
        # Normalize path - remove leading/trailing slashes
        prefix = path + '/' if path else ''

        files = []
        directories = set()  # Track directories to avoid duplicates

        # Use paginator to get all pages
        paginator = s3_client.get_paginator('list_objects_v2')
        pages = paginator.paginate(
            Bucket=bucket_name,
            Prefix=prefix,
            Delimiter='/'
        )

        # Process all pages
        for page in pages:
            # Add directories (common prefixes)
            if 'CommonPrefixes' in page:
                for prefix_obj in page['CommonPrefixes']:
                    dir_name = prefix_obj['Prefix'][len(prefix):].rstrip('/')
                    if dir_name and dir_name not in directories:  # Skip empty names and duplicates
                        directories.add(dir_name)
                        files.append({
                            'name': dir_name,
                            'is_directory': True,
                            'size': 0
                        })

            # Add files
            if 'Contents' in page:
                for obj in page['Contents']:
                    # Skip the directory marker itself
                    if obj['Key'].endswith('/') and obj['Size'] == 0:
                        continue

                    file_name = obj['Key'][len(prefix):]
                    if file_name:  # Skip empty names
                        files.append({
                            'name': file_name,
                            'is_directory': False,
                            'size': obj['Size'],
                            'last_modified': obj['LastModified'].isoformat()
                        })

        # Sort: directories first, then files
        files.sort(key=lambda x: (not x['is_directory'], x['name'].lower()))

        return {'files': files, 'path': path, 'total_count': len(files)}
    except HTTPException:
        raise
    except (ClientError, BotoCoreError) as e:
        error_code = e.response.get('Error', {}).get('Code', '') if hasattr(e, 'response') else ''
        if error_code == 'NoSuchBucket':
            raise HTTPException(status_code=404, detail=f"Bucket '{bucket_name}' not found")
        error_message = format_boto_error(e)
        raise HTTPException(status_code=500, detail=f"Failed to list files: {error_message}")
    except Exception as e:
        error_message = format_boto_error(e)
        raise HTTPException(status_code=500, detail=f"Failed to list files: {error_message}")


@app.post("/api/buckets/{bucket_name}/upload")
async def upload_file(
    request: Request,
    bucket_name: str,
    file: UploadFile = File(...),
    key: str = Form(..., description="S3 object key (path)"),
    role: Optional[str] = Form(None, description="Role name to use"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    csrf_verified: bool = Depends(verify_csrf_token)
):
    """Upload a file to S3 bucket using streaming to minimize memory usage"""
    try:
        # Validate and sanitize inputs
        try:
            bucket_name = sanitize_bucket_name(bucket_name)
            key = sanitize_path(key)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        # Validate role access
        validated_role = validate_role_access(role, current_user)
        s3_client = get_s3_client(validated_role)

        # Get max_file_size from config (with fallback to env var)
        config = load_config(force_reload=False)
        max_file_size = config.get("max_file_size")
        if max_file_size is None:
            max_file_size = int(os.getenv("MAX_FILE_SIZE", str(100 * 1024 * 1024)))
        else:
            max_file_size = int(max_file_size)

        # Check file size if available (some clients provide Content-Length)
        # If not available, we'll check during streaming
        file_size = None
        if hasattr(file, 'size') and file.size is not None:
            file_size = file.size
        elif hasattr(request, 'headers') and 'content-length' in request.headers:
            try:
                file_size = int(request.headers['content-length'])
            except (ValueError, TypeError):
                pass

        if file_size and file_size > max_file_size:
            size_mb = max_file_size / (1024 * 1024)
            raise HTTPException(status_code=400, detail=f"File size exceeds maximum allowed size of {size_mb}MB")

        # Stream file content in chunks to minimize memory usage
        # This allows handling large files without loading entire file into memory at once
        chunk_size = 8 * 1024 * 1024  # 8MB chunks - good balance between memory and performance
        total_read = 0

        # Use BytesIO for efficient memory management
        # This allows us to stream data without keeping all chunks in a list
        content_buffer = BytesIO()

        # Reset file pointer to beginning (in case it was read before)
        await file.seek(0)

        # Read file in chunks and write to buffer
        while True:
            chunk = await file.read(chunk_size)
            if not chunk:
                break

            total_read += len(chunk)

            # Check size limit during streaming (fail fast)
            if total_read > max_file_size:
                size_mb = max_file_size / (1024 * 1024)
                raise HTTPException(status_code=400, detail=f"File size exceeds maximum allowed size of {size_mb}MB")

            # Write chunk to buffer
            content_buffer.write(chunk)

        # Get content from buffer
        content_buffer.seek(0)
        content = content_buffer.getvalue()
        content_buffer.close()

        # Upload to S3
        s3_client.put_object(
            Bucket=bucket_name,
            Key=key,
            Body=content,
            ContentType=file.content_type or 'application/octet-stream'
        )

        return {'message': 'File uploaded successfully', 'key': key}
    except HTTPException:
        raise
    except (ClientError, BotoCoreError) as e:
        error_message = format_boto_error(e)
        raise HTTPException(status_code=500, detail=f"Failed to upload file: {error_message}")
    except Exception as e:
        error_message = format_boto_error(e)
        raise HTTPException(status_code=500, detail=f"Failed to upload file: {error_message}")


@app.get("/api/buckets/{bucket_name}/download")
async def download_file(
    bucket_name: str,
    path: str = Query(..., description="Path to file to download"),
    role: Optional[str] = Query(None, description="Role name to use"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Download a file from S3 bucket directly"""
    try:
        # Validate and sanitize inputs
        try:
            bucket_name = sanitize_bucket_name(bucket_name)
            path = sanitize_path(path)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        # Validate role access
        validated_role = validate_role_access(role, current_user)
        s3_client = get_s3_client(validated_role)

        # Get file from S3
        try:
            response = s3_client.get_object(Bucket=bucket_name, Key=path)
            file_content = response['Body'].read()
            content_type = response.get('ContentType', 'application/octet-stream')
            filename = path.split('/')[-1]  # Get filename from path
        except (ClientError, BotoCoreError) as e:
            error_code = e.response.get('Error', {}).get('Code', '') if hasattr(e, 'response') else ''
            if error_code == '404' or error_code == 'NoSuchKey':
                raise HTTPException(status_code=404, detail=f"File '{path}' not found")
            error_message = format_boto_error(e)
            raise HTTPException(status_code=500, detail=f"Failed to download file: {error_message}")
        except Exception as e:
            error_message = format_boto_error(e)
            raise HTTPException(status_code=500, detail=f"Failed to download file: {error_message}")

        # Return file as streaming response
        from fastapi.responses import StreamingResponse
        from io import BytesIO
        return StreamingResponse(
            BytesIO(file_content),
            media_type=content_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            }
        )
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/buckets/{bucket_name}/files")
async def delete_file(
    request: Request,
    bucket_name: str,
    path: str = Query(..., description="Path to file or directory to delete"),
    role: Optional[str] = Query(None, description="Role name to use"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    csrf_verified: bool = Depends(verify_csrf_token)
):
    """Delete a file or recursively delete a directory from S3"""
    # Check if deletion is disabled (from environment variable or config)
    config = load_config(force_reload=False)
    disable_deletion_env = os.getenv("DISABLE_DELETION", "").lower() == "true"
    disable_deletion_config = config.get("disable_deletion", False)

    if disable_deletion_env or disable_deletion_config:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="File deletion is disabled by administrator"
        )
    try:
        # Validate and sanitize inputs
        try:
            bucket_name = sanitize_bucket_name(bucket_name)
            path = sanitize_path(path)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        # Validate role access
        validated_role = validate_role_access(role, current_user)
        s3_client = get_s3_client(validated_role)
        # Normalize path
        prefix = path
        if not prefix:
            raise HTTPException(status_code=400, detail="Cannot delete root path")

        # Check if it's a directory (ends with /) or a file
        is_directory = prefix.endswith('/')
        if is_directory:
            prefix = prefix.rstrip('/')

        deleted_count = 0

        # List all objects with this prefix
        paginator = s3_client.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=bucket_name, Prefix=prefix + ('/' if is_directory else ''))

        objects_to_delete = []
        for page in pages:
            if 'Contents' in page:
                for obj in page['Contents']:
                    objects_to_delete.append({'Key': obj['Key']})

        # If it's a single file (not a directory), check if it exists
        if not is_directory and not objects_to_delete:
            # Try to delete as a single file
            try:
                s3_client.delete_object(Bucket=bucket_name, Key=prefix)
                deleted_count = 1
            except (ClientError, BotoCoreError) as e:
                error_code = e.response.get('Error', {}).get('Code', '') if hasattr(e, 'response') else ''
                if error_code == '404' or error_code == 'NoSuchKey':
                    raise HTTPException(status_code=404, detail=f"File or directory '{path}' not found")
                error_message = format_boto_error(e)
                raise HTTPException(status_code=500, detail=f"Failed to delete: {error_message}")
            except Exception as e:
                error_message = format_boto_error(e)
                raise HTTPException(status_code=500, detail=f"Failed to delete: {error_message}")
        else:
            # Delete all objects in batch
            if objects_to_delete:
                # S3 allows up to 1000 objects per delete request
                for i in range(0, len(objects_to_delete), 1000):
                    batch = objects_to_delete[i:i + 1000]
                    s3_client.delete_objects(
                        Bucket=bucket_name,
                        Delete={
                            'Objects': batch,
                            'Quiet': True
                        }
                    )
                    deleted_count += len(batch)

        if deleted_count == 0:
            raise HTTPException(status_code=404, detail=f"File or directory '{path}' not found")

        return {'message': f'Successfully deleted {deleted_count} object(s)', 'count': deleted_count}
    except HTTPException:
        raise
    except (ClientError, BotoCoreError) as e:
        error_message = format_boto_error(e)
        raise HTTPException(status_code=500, detail=f"Failed to delete: {error_message}")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        error_message = format_boto_error(e)
        raise HTTPException(status_code=500, detail=f"Failed to delete: {error_message}")


if __name__ == "__main__":  # pragma: no cover
    import uvicorn
    port = int(os.getenv("PORT", "8080"))
    log_level = str(os.getenv("LOG_LEVEL", "info")).lower()
    host = str(os.getenv("UVICORN_HOST", "0.0.0.0"))
    uvicorn.run(app, host=host, port=port, log_level=log_level)
