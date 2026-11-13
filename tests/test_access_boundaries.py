"""Keep the prepared import contracts exhaustive as the package grows."""

import ast
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "another_s3_manager"


def _contract():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return next(c for c in config["tool"]["importlinter"]["contracts"] if c["id"] == "access-api-only")


def _covered(children, consumers, contract):
    return children <= set(contract["forbidden_modules"]) and consumers <= set(contract["source_modules"])


def test_every_access_child_and_top_level_consumer_is_covered():
    children = {
        "another_s3_manager." + ".".join(p.relative_to(PACKAGE).with_suffix("").parts)
        for p in (PACKAGE / "access").rglob("*.py")
        if p.name != "__init__.py"
    }
    children |= {
        "another_s3_manager." + ".".join(p.parent.relative_to(PACKAGE).parts)
        for p in (PACKAGE / "access").rglob("__init__.py")
        if p.parent != PACKAGE / "access"
    }
    consumers = {
        "another_s3_manager." + p.stem
        for p in PACKAGE.glob("*.py")
        if p.stem not in {"__init__", "users", "api_tokens"}
    }
    assert _covered(children, consumers, _contract())
    assert not _covered(children | {"another_s3_manager.access.future"}, consumers, _contract())
    assert not _covered(children, consumers | {"another_s3_manager.future"}, _contract())


@pytest.mark.parametrize("name", ["users.py", "api_tokens.py"])
def test_shims_only_import_and_declare_exports(name):
    tree = ast.parse((PACKAGE / name).read_text(encoding="utf-8"))
    for node in tree.body:
        assert isinstance(node, (ast.Import, ast.ImportFrom)) or (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "__all__"
            and isinstance(ast.literal_eval(node.value), list)
        )
    assert not any(isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names) for node in tree.body)


def test_existing_contracts_are_retained_without_new_broad_ignores():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    contracts = {c["id"]: c for c in config["tool"]["importlinter"]["contracts"]}
    assert {"adapters-independent", "access-no-adapters", "storage-no-adapters"} <= contracts.keys()
    assert not _contract().get("ignore_imports")
