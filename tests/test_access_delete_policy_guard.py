"""Deletion decisions belong to Access, never individual adapters."""

import ast
from pathlib import Path


def test_deletion_flag_calls_stay_in_policy_or_serialization():
    root = Path(__file__).parents[1] / "src" / "another_s3_manager"
    violations = []
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_bytes())
        relative = path.relative_to(root).as_posix()
        parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", getattr(node.func, "attr", ""))
            if name not in {"deletion_disabled", "is_deletion_disabled"}:
                continue
            if relative == "access/policies.py":
                continue
            ancestor = node
            while ancestor in parents and not isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)):
                ancestor = parents[ancestor]
            function = getattr(ancestor, "name", "")
            if relative == "config.py" and function == "is_deletion_disabled":
                continue
            if relative == "main.py" and function in {"get_current_user_info", "get_config"}:
                continue
            violations.append(f"{relative}:{node.lineno}")
    assert violations == []
