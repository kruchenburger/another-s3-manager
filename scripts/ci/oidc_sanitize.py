"""Print the tail of a private CI log with OIDC auth material removed.

Remote CI only. Query strings, sensitive key=value pairs, JWT-looking strings,
bearer tokens and the fixture canaries are redacted; if a canary still survives,
nothing is printed.
"""

import re
import sys

CANARIES = ("oidc-ci-session-secret-canary", "FixturePassword1")
KEYS = (
    r"(code|state|nonce|token|id_token|id_token_hint|access_token|refresh_token|"
    r"client_secret|code_verifier|password|secret|csrf_token)"
)


def sanitize(line: str) -> str:
    line = re.sub(r"\x1b\[[0-9;]*m", "", line)
    line = re.sub(r"\?[^\s\"'<>]*", "?<query>", line)
    line = re.sub(KEYS + r"(\s*[=:]\s*)[^\s,;&\"']+", r"\1\2<redacted>", line, flags=re.I)
    line = re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+", "<jwt>", line)
    line = re.sub(r"(Bearer |as3m_)[A-Za-z0-9_.-]+", r"\1<redacted>", line)
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
