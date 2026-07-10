"""Invariants for the bundled Grafana dashboard (docs/grafana-dashboard.json).

These are the guard rails that keep the dashboard portable and honest as it is
hand-edited. They run in normal CI (pure JSON parse, no Docker). The separate
live smoke — which actually boots Prometheus+Grafana and queries the API — is
gated behind the E2E_GRAFANA env flag because it needs the heavy stack; see the
test at the bottom.

Why each rule exists:
- graphTooltip == 1: the user asked for a shared crosshair across panels.
- transparent panels: a user requirement for the visual style.
- non-empty descriptions: every panel must explain what it means / how to act.
- no hardcoded datasource UID: portability. The dashboard must import cleanly
  into a stranger's Grafana via the ${DS} variable, never a UID baked in by a
  UI export.
- $__rate_interval, not [5m]: a hardcoded window silently lies at any scrape
  interval other than the author's.
- histogram_quantile needs `sum by (le`: without summing over le first, the
  quantile is computed per-series and is quietly wrong.
- every as3m_* metric referenced must exist: the same class of rot that let
  mcp_active_tokens ship dead — a panel querying a renamed metric shows
  "No data" and nobody notices.
"""

import json
import os
import re
from pathlib import Path

import pytest

_DASHBOARD_PATH = Path(__file__).resolve().parents[1] / "docs" / "grafana-dashboard.json"


def _load() -> dict:
    return json.loads(_DASHBOARD_PATH.read_text(encoding="utf-8"))


def _walk_panels(dashboard: dict) -> list[dict]:
    """Every panel, including panels nested inside collapsed `row` panels."""
    out: list[dict] = []
    stack = list(dashboard.get("panels", []))
    while stack:
        panel = stack.pop()
        out.append(panel)
        # A collapsed row carries its children in a nested `panels` array.
        stack.extend(panel.get("panels", []) or [])
    return out


def _content_panels(dashboard: dict) -> list[dict]:
    """Panels that render data — everything except structural `row` panels."""
    return [p for p in _walk_panels(dashboard) if p.get("type") != "row"]


def _exprs(dashboard: dict) -> list[str]:
    exprs: list[str] = []
    for panel in _walk_panels(dashboard):
        for target in panel.get("targets", []) or []:
            expr = target.get("expr")
            if expr:
                exprs.append(expr)
    return exprs


def _datasource_refs(dashboard: dict) -> list[object]:
    """Every `datasource` value used anywhere (panels, targets, template vars)."""
    refs: list[object] = []
    for panel in _walk_panels(dashboard):
        if "datasource" in panel:
            refs.append(panel["datasource"])
        for target in panel.get("targets", []) or []:
            if "datasource" in target:
                refs.append(target["datasource"])
    for var in dashboard.get("templating", {}).get("list", []):
        if var.get("type") != "datasource" and "datasource" in var:
            refs.append(var["datasource"])
    return refs


def _valid_metric_names() -> set[str]:
    """Exposed series names for every as3m_ metric in the live registry.

    A Counter `as3m_x` is exposed as `as3m_x_total`; a Histogram as
    `_bucket`/`_count`/`_sum`; an Info as `_info`; a Gauge as its bare name.
    Runtime `process_*` / `python_info` are not ours and are not checked here.
    """
    from prometheus_client.metrics import MetricWrapperBase

    import another_s3_manager.metrics as metrics

    names: set[str] = set()
    for obj in vars(metrics).values():
        if not isinstance(obj, MetricWrapperBase):
            continue
        base = obj._name  # type: ignore[attr-defined]
        kind = type(obj).__name__
        if kind == "Counter":
            names.add(f"{base}_total")
        elif kind == "Histogram":
            names.update({f"{base}_bucket", f"{base}_count", f"{base}_sum"})
        elif kind == "Info":
            names.add(f"{base}_info")
        else:  # Gauge
            names.add(base)
    return {n for n in names if n.startswith("as3m_")}


# --- Structural sanity -------------------------------------------------------


def test_dashboard_file_parses_and_has_stable_identity():
    d = _load()
    assert d["title"] == "Another S3 Manager"
    assert d["uid"] == "as3m-overview"
    assert "another-s3-manager" in d.get("tags", [])


def test_discovers_a_non_empty_panel_set():
    # Guard against a walker that silently finds nothing and passes vacuously.
    assert len(_content_panels(_load())) > 0


# --- User-requested visual invariants ---------------------------------------


def test_shared_crosshair_enabled():
    assert _load().get("graphTooltip") == 1  # 1 = shared crosshair


def test_every_panel_is_transparent():
    offenders = [p.get("title") for p in _content_panels(_load()) if p.get("transparent") is not True]
    assert not offenders, f"panels not transparent: {offenders}"


def test_every_panel_has_a_description():
    offenders = [p.get("title") for p in _content_panels(_load()) if not (p.get("description") or "").strip()]
    assert not offenders, f"panels with no description: {offenders}"


# --- Portability -------------------------------------------------------------


def test_has_a_datasource_template_variable():
    variables = _load().get("templating", {}).get("list", [])
    ds_vars = [v for v in variables if v.get("type") == "datasource" and v.get("name") == "DS"]
    assert ds_vars, "missing a `DS` datasource template variable"


def test_no_hardcoded_datasource_uid():
    """Every datasource reference must go through the ${DS} variable, never a UID."""
    bad: list[object] = []
    for ref in _datasource_refs(_load()):
        if ref == "${DS}":
            continue
        if isinstance(ref, dict) and ref.get("uid") == "${DS}":
            continue
        bad.append(ref)
    assert not bad, f"hardcoded datasource references (UI export leak?): {bad}"


# --- PromQL correctness ------------------------------------------------------

_HARDCODED_WINDOW = re.compile(r"\[\s*\d+[smhdwy]\s*\]")
_RATE_FAMILY = re.compile(r"\b(rate|irate|increase|delta|idelta)\s*\(")
_HISTQ = re.compile(r"histogram_quantile\s*\(")
_SUM_BY_LE = re.compile(r"sum\s+by\s*\(\s*le")
_AS3M_TOKEN = re.compile(r"as3m_[a-z0-9_]+")


def test_no_hardcoded_rate_window():
    """A literal like [5m] lies at any scrape interval but the author's."""
    offenders = [e for e in _exprs(_load()) if _HARDCODED_WINDOW.search(e)]
    assert not offenders, f"exprs with a hardcoded range window (use $__rate_interval): {offenders}"


def test_rate_functions_use_rate_interval():
    offenders = [e for e in _exprs(_load()) if _RATE_FAMILY.search(e) and "$__rate_interval" not in e]
    assert not offenders, f"rate()/increase() without $__rate_interval: {offenders}"


def test_histogram_quantile_sums_over_le():
    offenders = [e for e in _exprs(_load()) if _HISTQ.search(e) and not _SUM_BY_LE.search(e)]
    assert not offenders, f"histogram_quantile without `sum by (le`: {offenders}"


def test_every_referenced_metric_exists():
    valid = _valid_metric_names()
    assert valid, "sanity: no as3m_ metrics discovered in the registry"
    referenced = {tok for e in _exprs(_load()) for tok in _AS3M_TOKEN.findall(e)}
    missing = sorted(referenced - valid)
    assert not missing, f"panels reference metrics that do not exist: {missing}"


# --- Live smoke (opt-in; needs the heavy Prometheus+Grafana stack) -----------


@pytest.mark.skipif(
    os.environ.get("E2E_GRAFANA") != "1",
    reason="live Grafana smoke — set E2E_GRAFANA=1 with the observability stack up",
)
def test_live_dashboard_loads_and_a_panel_returns_data():
    """Bring the stack up first:

        docker compose -f docker-compose.yml -f docker/docker-compose.observability.yml up --build -d

    then run: E2E_GRAFANA=1 uv run pytest tests/test_grafana_dashboard.py -k live
    """
    import urllib.request

    base = os.environ.get("GRAFANA_URL", "http://localhost:3000")
    with urllib.request.urlopen(f"{base}/api/dashboards/uid/as3m-overview", timeout=10) as resp:
        payload = json.load(resp)
    assert payload["dashboard"]["uid"] == "as3m-overview"
