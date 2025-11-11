#!/usr/bin/env python3
"""
Extract changelog section for a specific version from CHANGELOG.md
"""
import re
import os
import sys


def extract_changelog(version: str, changelog_path: str = "CHANGELOG.md", output_path: str = "release_notes.md"):
    """
    Extract changelog section for a specific version.

    Args:
        version: Version string (e.g., "0.1.0")
        changelog_path: Path to CHANGELOG.md file
        output_path: Path to output file
    """
    # Remove 'v' prefix if present
    version = version.lstrip('v')

    try:
        with open(changelog_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: {changelog_path} not found", file=sys.stderr)
        sys.exit(1)

    # Try to find version section
    if version:
        # Match section like "## [0.1.0] - 2025-11-11" or "## [0.1.0]"
        pattern = rf'^## \[{re.escape(version)}\].*?(?=^## \[|\Z)'
        match = re.search(pattern, content, re.MULTILINE | re.DOTALL)

        if match:
            notes = match.group(0).strip()
        else:
            # Fallback to Unreleased section
            pattern = r'^## \[Unreleased\].*?(?=^## \[|\Z)'
            match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
            if match:
                notes = match.group(0).strip()
            else:
                # Final fallback - use full changelog
                notes = content
    else:
        # No version, use Unreleased or full changelog
        pattern = r'^## \[Unreleased\].*?(?=^## \[|\Z)'
        match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
        if match:
            notes = match.group(0).strip()
        else:
            notes = content

    # Write to output file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(notes)

    # Output for debugging
    print(f"Extracted changelog for version: {version}")
    print(f"Length: {len(notes)} characters")
    return notes


if __name__ == "__main__":
    # Get version from environment variable or command line argument
    version = os.environ.get('VERSION', '')
    if len(sys.argv) > 1:
        version = sys.argv[1]

    if not version:
        print("Error: VERSION environment variable or argument required", file=sys.stderr)
        sys.exit(1)

    extract_changelog(version)

