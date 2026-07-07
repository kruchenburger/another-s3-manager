#!/usr/bin/env python3
"""
Extract changelog section for a specific version from CHANGELOG.md
"""

import os
import re
import sys

_HEADER_RE = re.compile(r"^#{1,6}\s")
_LIST_RE = re.compile(r"^(\s*)([-*+]|\d+\.)\s")
_FENCE_RE = re.compile(r"^\s*```")


def _is_joinable_prev(line: str) -> bool:
    """A previous line a continuation may be appended to (a paragraph or bullet),
    as opposed to a header / table row / blockquote / fence / blank."""
    stripped = line.strip()
    if stripped == "" or _HEADER_RE.match(stripped) or _FENCE_RE.match(line):
        return False
    return not (stripped.startswith("|") or stripped.startswith(">"))


def reflow_release_notes(text: str) -> str:
    """Collapse soft-wrapped continuation lines into single physical lines.

    GitHub renders release notes with GFM ``breaks: true``, so every single
    newline inside a paragraph or bullet becomes a ``<br>``. A CHANGELOG that is
    hard-wrapped at ~80 columns (nice to read in an editor) therefore renders as
    a narrow, ragged left column on the release page. Joining each wrapped
    paragraph/bullet back into one line lets it wrap naturally to the page width.

    Preserved verbatim: blank lines, ATX headers, list markers (so separate
    bullets stay separate), Markdown table rows, blockquotes, and fenced code
    blocks (nothing inside ``` fences is touched).
    """
    out: list[str] = []
    in_fence = False
    for raw in text.split("\n"):
        line = raw.rstrip("\r")

        if _FENCE_RE.match(line):
            in_fence = not in_fence
            out.append(line)
            continue
        if in_fence:
            out.append(line)
            continue

        stripped = line.strip()
        starts_new_block = (
            stripped == ""
            or bool(_HEADER_RE.match(stripped))
            or bool(_LIST_RE.match(line))
            or stripped.startswith("|")
            or stripped.startswith(">")
        )

        if out and not starts_new_block and _is_joinable_prev(out[-1]):
            out[-1] = out[-1].rstrip() + " " + stripped
        else:
            out.append(line)

    return "\n".join(out)


def extract_changelog(version: str, changelog_path: str = "CHANGELOG.md", output_path: str = "release_notes.md"):
    """
    Extract changelog section for a specific version.

    Args:
        version: Version string (e.g., "0.1.0")
        changelog_path: Path to CHANGELOG.md file
        output_path: Path to output file
    """
    # Remove 'v' prefix if present
    version = version.lstrip("v")

    try:
        with open(changelog_path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: {changelog_path} not found", file=sys.stderr)
        sys.exit(1)

    # Try to find version section
    if version:
        # Match section like "## [0.1.0] - 2025-11-11" or "## [0.1.0]"
        pattern = rf"^## \[{re.escape(version)}\].*?(?=^## \[|\Z)"
        match = re.search(pattern, content, re.MULTILINE | re.DOTALL)

        if match:
            notes = match.group(0).strip()
        else:
            # Fallback to Unreleased section
            pattern = r"^## \[Unreleased\].*?(?=^## \[|\Z)"
            match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
            if match:
                notes = match.group(0).strip()
            else:
                # Final fallback - use full changelog
                notes = content
    else:
        # No version, use Unreleased or full changelog
        pattern = r"^## \[Unreleased\].*?(?=^## \[|\Z)"
        match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
        if match:
            notes = match.group(0).strip()
        else:
            notes = content

    # Unwrap hard-wrapped lines so the release page doesn't render as a narrow
    # <br>-separated column (GitHub release notes use GFM breaks: true).
    notes = reflow_release_notes(notes)

    # Write to output file
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(notes)

    # Output for debugging
    print(f"Extracted changelog for version: {version}")
    print(f"Length: {len(notes)} characters")
    return notes


if __name__ == "__main__":
    # Get version from environment variable or command line argument
    version = os.environ.get("VERSION", "")
    if len(sys.argv) > 1:
        version = sys.argv[1]

    if not version:
        print("Error: VERSION environment variable or argument required", file=sys.stderr)
        sys.exit(1)

    extract_changelog(version)
