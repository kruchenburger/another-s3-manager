"""Print the tail of a private CI log with OIDC auth material removed.

Remote CI only. Query strings, sensitive key/value pairs (quoted or not),
JWT-looking strings, bearer tokens and any long opaque token are redacted; if a
fixture canary still survives, nothing is printed.
"""

import re
import sys

CANARIES = ("oidc-ci-session-secret-canary", "FixturePassword1")
KEYS = (
    r"(?:code|state|nonce|token|id_token|id_token_hint|access_token|refresh_token|"
    r"client_secret|code_verifier|password|secret|csrf_token)"
)
# key=value, key: value, 'key': 'value', "key": "value", key 'value'.
KEY_VALUE = re.compile(r"""(["']?\b""" + KEYS + r"""["']?(?:\s*[=:]\s*|\s+)["']?)[^\s,;&"'}\])]+""", re.I)
JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+")
BEARER = re.compile(r"(Bearer |as3m_)[A-Za-z0-9_.-]+")
QUERY = re.compile(r"\?[^\s\"'<>]*")
OPAQUE = re.compile(r"[A-Za-z0-9_-]{20,}")
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def sanitize(line: str) -> str:
    line = ANSI.sub("", line)
    line = QUERY.sub("?<query>", line)
    line = JWT.sub("<jwt>", line)
    line = BEARER.sub(r"\1<redacted>", line)
    line = KEY_VALUE.sub(r"\1<redacted>", line)
    # Codes, verifiers, state and secrets that appear without a recognizable key.
    line = OPAQUE.sub("<opaque>", line)
    return line[:300]


def main() -> None:
    path, count = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 40
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()[-count:]
    except OSError:
        return
    text = "\n".join(sanitize(line) for line in lines)
    if any(canary in text for canary in CANARIES):
        print("(diagnostics withheld: a canary survived redaction)")
    else:
        print(text)


if __name__ == "__main__":
    main()
