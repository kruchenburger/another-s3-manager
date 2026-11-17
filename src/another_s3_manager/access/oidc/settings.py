"""Strict effective security settings; secrets never enter stored configuration."""

import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from another_s3_manager.access.sessions import validate_lifetime_minutes
from another_s3_manager.constants import parse_cookie_secure


def env_boolean(name, default=False):
    raw = os.environ.get(name)
    if raw is None:
        return default
    if raw not in {"true", "false"}:
        raise ValueError(f"{name} must be true or false")
    return raw == "true"


def origin(url, *, allow_http=False, origin_only=False):
    if (
        not isinstance(url, str)
        or not url
        or any(ord(c) <= 32 or ord(c) == 127 for c in url)
        or "\\" in url
        or "*" in url
    ):
        raise ValueError("Invalid OIDC URL")
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    try:
        port = parsed.port if parsed.port is not None else (443 if scheme == "https" else 80)
    except ValueError:
        raise ValueError("Invalid OIDC port") from None
    if (
        not 1 <= port <= 65535
        or parsed.netloc.endswith(":")
        or scheme not in ({"https", "http"} if allow_http else {"https"})
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or "#" in url
    ):
        raise ValueError("Invalid OIDC URL")
    if origin_only and (parsed.path or parsed.query or "?" in url):
        raise ValueError("OIDC origin cannot contain a path or query")
    host = parsed.hostname.lower()
    host = f"[{host}]" if ":" in host else host
    return f"{scheme}://{host}:{port}"


class InsecureOrigin(ValueError):
    """A plain-HTTP IdP origin that is not explicitly allow-listed."""


def outbound_origin(url, settings):
    """The one rule for IdP origins: plain HTTP only for an explicitly listed origin."""
    identity = origin(url, allow_http=settings.allow_http)
    if identity.startswith("http://") and identity not in settings.private_origins:
        raise InsecureOrigin("Plain HTTP OIDC origins must be listed in OIDC_ALLOWED_PRIVATE_ORIGINS")
    return identity


def client_secret():
    """Read the current client secret on demand; the file source wins over the variable.

    Nothing caches it, so a rotated secret file takes effect on the next token exchange.
    Errors never carry the path or the file contents.
    """
    if "OIDC_CLIENT_SECRET_FILE" not in os.environ:
        return os.environ.get("OIDC_CLIENT_SECRET", "")
    try:
        secret = Path(os.environ["OIDC_CLIENT_SECRET_FILE"]).read_text(encoding="utf-8").rstrip("\r\n")
    except (OSError, ValueError):
        raise ValueError("Cannot read OIDC client secret file") from None
    if not secret:
        raise ValueError("Empty OIDC client secret file")
    return secret


@dataclass(frozen=True)
class OidcSettings:
    issuer: str
    public_url: str
    client_id: str
    allow_http: bool
    private_origins: frozenset[str]
    secure_cookie: bool
    local_login: str
    display_name: str
    scopes: tuple[str, ...]
    username_claim: str
    groups_claim: str
    lifetime_minutes: int
    mode: str

    @property
    def enabled(self):
        return bool(self.issuer)

    @property
    def redirect_uri(self):
        return self.public_url + "/api/auth/oidc/callback"


def object_field(parent, key):
    value = parent.get(key, {})
    if type(value) is not dict:
        raise ValueError(f"{key} must be an object")
    return value


def oidc_settings(config):
    auth = object_field(config, "auth")
    oidc = object_field(auth, "oidc")
    mapping = object_field(oidc, "role_mapping")
    if (
        set(auth) - {"local_login", "oidc"}
        or set(oidc)
        - {"display_name", "scopes", "username_claim", "groups_claim", "session_max_minutes", "role_mapping"}
        or set(mapping) - {"mode", "require_match", "rules"}
    ):
        raise ValueError("Unsupported authentication setting")
    local = os.environ.get("LOCAL_LOGIN", auth.get("local_login", "all"))
    if local not in ("all", "admins", "off") or auth.get("local_login", "all") not in ("all", "admins", "off"):
        raise ValueError("Invalid local login policy")
    mode = mapping.get("mode", "sync")
    if mode not in ("sync", "initial"):
        raise ValueError("Invalid mapping mode")
    if mapping.get("require_match", True) is not True:
        raise ValueError("require_match must be true")
    rules = mapping.get("rules", [])
    if type(rules) is not list:
        raise ValueError("rules must be an array")
    for rule in rules:
        if type(rule) is not dict or set(rule) - {"claim", "value", "roles", "admin"}:
            raise ValueError("Invalid mapping rule")
        if not isinstance(rule.get("claim"), str) or not re.fullmatch(r"[^.\s]+(?:\.[^.\s]+)*", rule["claim"]):
            raise ValueError("Invalid claim path")
        if not isinstance(rule.get("value"), str) or not rule["value"]:
            raise ValueError("Invalid rule value")
        if (
            type(rule.get("admin", False)) is not bool
            or type(rule.get("roles", [])) is not list
            or any(not isinstance(r, str) or not r for r in rule.get("roles", []))
        ):
            raise ValueError("Invalid rule grant")
        if not rule.get("admin", False) and not rule.get("roles", []):
            raise ValueError("Empty mapping rule")
        if rule["claim"] == "preferred_username":
            raise ValueError(
                "Rules on preferred_username are not allowed: the IdP user can often change it. "
                "Use a group or app-role claim."
            )
    scopes = oidc.get("scopes", ["openid", "profile", "email"])
    if (
        type(scopes) is not list
        or "openid" not in scopes
        or any(not isinstance(s, str) or not s or any(c.isspace() for c in s) for s in scopes)
    ):
        raise ValueError("Invalid OIDC scopes")
    for name in ("display_name", "username_claim", "groups_claim"):
        if name in oidc and (not isinstance(oidc[name], str) or not oidc[name] or len(oidc[name]) > 255):
            raise ValueError("Invalid OIDC label or claim")
    ttl = validate_lifetime_minutes(oidc.get("session_max_minutes"))
    issuer = os.environ.get("OIDC_ISSUER", "")
    public = os.environ.get("PUBLIC_URL", "")
    client = os.environ.get("OIDC_CLIENT_ID", "")
    allow_http = env_boolean("OIDC_ALLOW_INSECURE_HTTP")
    secure = parse_cookie_secure(os.environ.get("COOKIE_SECURE"))
    private = os.environ.get("OIDC_ALLOWED_PRIVATE_ORIGINS", "")
    private_origins = (
        frozenset(origin(part.strip(), allow_http=allow_http, origin_only=True) for part in private.split(","))
        if private
        else frozenset()
    )
    if issuer:
        if not client or not public:
            raise ValueError("OIDC requires PUBLIC_URL and OIDC_CLIENT_ID")
        origin(issuer, allow_http=allow_http)
        if urlsplit(issuer).query or "?" in issuer:
            raise ValueError("Issuer cannot contain a query")
        origin(public, allow_http=allow_http, origin_only=True)
        if urlsplit(public).scheme.lower() == "https" and not secure:
            raise ValueError("HTTPS OIDC requires secure cookies")
    elif local == "off":
        raise ValueError("Local login off requires configured OIDC")
    settings = OidcSettings(
        issuer,
        public,
        client,
        allow_http,
        private_origins,
        secure,
        local,
        oidc.get("display_name", "Company SSO"),
        tuple(scopes),
        oidc.get("username_claim", "preferred_username"),
        oidc.get("groups_claim", "groups"),
        ttl,
        mode,
    )
    if issuer:
        outbound_origin(issuer, settings)
    return settings
