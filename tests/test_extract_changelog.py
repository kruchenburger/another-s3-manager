"""Tests for .github/scripts/extract_changelog.py (release-notes extraction)."""

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / ".github" / "scripts" / "extract_changelog.py"


def _load():
    spec = importlib.util.spec_from_file_location("extract_changelog", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ec = _load()


def test_reflow_joins_wrapped_bullet_into_one_line():
    src = "### Added\n\n- A long bullet that was hard-wrapped\n  across two source lines."
    out = ec.reflow_release_notes(src)
    assert "- A long bullet that was hard-wrapped across two source lines." in out
    # The continuation line must be gone.
    assert "\n  across" not in out


def test_reflow_keeps_separate_bullets_separate():
    src = "- first bullet\n- second bullet"
    assert ec.reflow_release_notes(src) == "- first bullet\n- second bullet"


def test_reflow_preserves_headers_blanks_and_nested_bullets():
    src = "### Changed\n\n- parent\n  - child stays a child\n\n### Fixed\n\n- done"
    out = ec.reflow_release_notes(src)
    assert "### Changed" in out and "### Fixed" in out
    # Blank line between sections survives.
    assert "\n\n### Fixed" in out
    # A nested list item is a new block, not joined onto its parent.
    assert "  - child stays a child" in out


def test_reflow_leaves_code_fences_untouched():
    src = "- run:\n\n```bash\ndocker run \\\n  --rm hello\n```"
    out = ec.reflow_release_notes(src)
    # The wrapped command inside the fence keeps its own lines.
    assert "docker run \\\n  --rm hello" in out


def test_reflow_does_not_merge_paragraph_into_header():
    src = "## [1.0.0] - 2026-07-04\ntext right under the header"
    out = ec.reflow_release_notes(src)
    assert out.startswith("## [1.0.0] - 2026-07-04\n")


def test_reflow_output_has_no_short_wrapped_bullet_lines():
    # Simulate an editor-wrapped bullet (~40 cols); after reflow it is one line.
    src = "- alpha beta gamma\n  delta epsilon\n  zeta eta"
    out = ec.reflow_release_notes(src)
    assert out == "- alpha beta gamma delta epsilon zeta eta"


def test_extract_reflows_the_written_file(tmp_path):
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        "# Changelog\n\n"
        "## [1.0.0] - 2026-07-04\n\n"
        "### Added\n\n"
        "- A feature described across\n  two wrapped lines.\n\n"
        "## [0.9.0] - 2026-01-01\n\n"
        "### Added\n\n- old\n",
        encoding="utf-8",
    )
    out_file = tmp_path / "release_notes.md"
    ec.extract_changelog("v1.0.0", str(changelog), str(out_file))
    body = out_file.read_text(encoding="utf-8")
    assert "- A feature described across two wrapped lines." in body
    # Must not bleed into the next version's section.
    assert "0.9.0" not in body


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
