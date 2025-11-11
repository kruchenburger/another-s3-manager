"""
User management module
"""
import os
import json
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

try:
    from constants import get_users_file, get_bans_file
except ImportError:
    # Fallback for direct execution
    from pathlib import Path
    def get_users_file():
        return Path(__file__).parent / "users.json"
    def get_bans_file():
        return Path(__file__).parent / "bans.json"


def load_users() -> Dict[str, Any]:
    """Load users from file or create default admin user."""
    users_file = get_users_file()
    try:
        if users_file.exists():
            with open(users_file, 'r', encoding='utf-8') as f:
                users_data = json.load(f)
                # Validate structure
                if "users" not in users_data or not isinstance(users_data["users"], list):
                    raise ValueError("Invalid users.json structure")
                # Migrate old users to have allowed_roles and theme fields
                needs_save = False
                for user in users_data.get("users", []):
                    if "allowed_roles" not in user:
                        user["allowed_roles"] = []
                        needs_save = True
                    if "theme" not in user:
                        user["theme"] = "auto"
                        needs_save = True
                if needs_save:
                    save_users(users_data)
                return users_data
    except (json.JSONDecodeError, ValueError) as e:
        print(f"Warning: Error loading users.json: {e}. Creating new file.")

    # Create default admin user
    admin_password = os.getenv("ADMIN_PASSWORD", "change_me_pls")
    # Import here to avoid circular dependency
    from auth import hash_password
    hashed_password = hash_password(admin_password)

    default_users = {
        "users": [
            {
                "username": "admin",
                "password_hash": hashed_password,
                "is_admin": True,
                "allowed_roles": [],  # Admins have access to all roles
                "theme": "auto",
                "created_at": datetime.now().isoformat()
            }
        ]
    }
    save_users(default_users)
    return default_users


def save_users(users: Dict[str, Any]) -> None:
    """Save users to file."""
    users_file = get_users_file()
    with open(users_file, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=2, ensure_ascii=False)


def load_bans() -> Dict[str, Any]:
    """Load bans from file and remove expired ones."""
    bans_file = get_bans_file()
    if bans_file.exists():
        with open(bans_file, 'r', encoding='utf-8') as f:
            bans = json.load(f)
            # Remove expired bans
            import time
            current_time = time.time()
            active_bans = {
                username: ban_data for username, ban_data in bans.items()
                if ban_data.get("banned_until", 0) > current_time
            }
            if len(active_bans) != len(bans):
                save_bans(active_bans)
            return active_bans
    return {}


def save_bans(bans: Dict[str, Any]) -> None:
    """Save bans to file."""
    bans_file = get_bans_file()
    with open(bans_file, 'w', encoding='utf-8') as f:
        json.dump(bans, f, indent=2, ensure_ascii=False)


def get_user_by_username(username: str) -> Dict[str, Any]:
    """Get user by username."""
    users = load_users()
    return next((u for u in users.get("users", []) if u.get("username") == username), None)


def get_all_users() -> List[Dict[str, Any]]:
    """Get all users."""
    users = load_users()
    return users.get("users", [])


def create_user(username: str, password_hash: str, is_admin: bool = False,
                allowed_roles: List[str] = None) -> Dict[str, Any]:
    """Create a new user."""
    users = load_users()

    # Check if user already exists
    if get_user_by_username(username):
        raise ValueError(f"User {username} already exists")

    new_user = {
        "username": username,
        "password_hash": password_hash,
        "is_admin": is_admin,
        "allowed_roles": allowed_roles or [],
        "theme": "auto",
        "created_at": None  # Will be set by caller
    }

    users.setdefault("users", []).append(new_user)
    save_users(users)
    return new_user


def update_user(username: str, **kwargs) -> Dict[str, Any]:
    """Update user properties."""
    users = load_users()
    user = get_user_by_username(username)

    if not user:
        raise ValueError(f"User {username} not found")

    # Update user properties
    for key, value in kwargs.items():
        if key in user:
            user[key] = value

    # Update in users list
    for u in users.get("users", []):
        if u.get("username") == username:
            u.update(user)
            break

    save_users(users)
    return user


def delete_user(username: str) -> None:
    """Delete a user."""
    users = load_users()
    users["users"] = [u for u in users.get("users", []) if u.get("username") != username]
    save_users(users)


def get_available_roles() -> List[str]:
    """Get list of available role names from config."""
    # Import here to avoid circular dependency
    try:
        from config import load_config
        config = load_config(force_reload=False)
        return [role.get("name") for role in config.get("roles", []) if role.get("name")]
    except ImportError:
        return []

