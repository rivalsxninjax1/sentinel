"""Dashboard page templates.

SECURITY NOTE, same as app/reporting/renderers/html_renderer.py: attack-surface
data (endpoint paths, parameter names, technology names, JS asset URLs) and
finding content all originate from the SCANNED TARGET, not from SENTINEL itself —
a malicious target could shape its responses to inject markup into a page a human
later views in this dashboard. Every template here uses a Jinja2 `Environment`
with `autoescape=True`, so every `{{ variable }}` interpolation is HTML-escaped by
default. Do not add `| safe` to any variable that ultimately traces back to
crawled/scanned content — only SENTINEL's own static strings should ever bypass
escaping, and none currently need to.
"""

from __future__ import annotations

from jinja2 import Environment
from markupsafe import Markup

_env = Environment(autoescape=True)

_STYLE = """
body{font-family:-apple-system,Helvetica,Arial,sans-serif;max-width:1100px;
margin:2rem auto;padding:0 1rem;color:#1f2937;background:#fafafa;}
nav{margin-bottom:1.5rem;}
nav a{color:#2563eb;text-decoration:none;margin-right:1rem;}
h1{font-size:1.4rem;} h2{font-size:1.1rem;margin-top:2rem;border-bottom:1px solid
#e5e7eb;padding-bottom:.25rem;}
table{border-collapse:collapse;width:100%;margin:.5rem 0;background:white;}
td,th{padding:.4rem .75rem;text-align:left;border-bottom:1px solid #e5e7eb;
font-size:.9rem;}
th{background:#f3f4f6;}
.badge{display:inline-block;padding:.1rem .5rem;border-radius:4px;color:white;
font-size:.75rem;}
.status-complete{background:#15803d;} .status-stopped{background:#b91c1c;}
.status-default{background:#6b7280;}
code{background:#f3f4f6;padding:.1rem .3rem;border-radius:3px;font-size:.85rem;}
.muted{color:#6b7280;font-size:.85rem;}
"""

_LAYOUT = _env.from_string(
    """<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>{{ title }} - SENTINEL Dashboard</title>
<style>{{ style }}</style></head><body>
<nav><a href="/">Scans</a>{% if scan_id %}
 &raquo; <a href="/scans/{{ scan_id }}">{{ scan_id[:8] }}</a>{% endif %}</nav>
<h1>{{ title }}</h1>
{{ body }}
</body></html>"""
)


def render_page(title: str, body: str, scan_id: str | None = None) -> str:
    """`body` is always the output of one of this module's own `_env.from_string(...)`
    sub-templates below, each of which already auto-escapes every variable it
    interpolates. Wrapping it in `Markup()` here tells the outer layout template
    not to re-escape it — without this, entities like `&lt;` produced by the inner
    template's escaping would themselves get escaped again into `&amp;lt;`,
    corrupting (not un-escaping) the output. This is safe specifically because
    every caller of `render_page()` in this module passes only its own
    already-autoescaped template output, never raw target-controlled data."""
    return _LAYOUT.render(title=title, style=_STYLE, body=Markup(body), scan_id=scan_id)


_HOME_BODY = _env.from_string(
    """
<table>
<tr><th>Target</th><th>Mode</th><th>Status</th><th>Started</th><th></th></tr>
{% for row in scans %}
<tr>
<td>{{ row.target_name }}</td>
<td>{{ row.mode }}</td>
<td><span class="badge status-{{ row.status_class }}">{{ row.status }}</span></td>
<td class="muted">{{ row.started_at }}</td>
<td><a href="/scans/{{ row.id }}">view</a></td>
</tr>
{% endfor %}
</table>
{% if not scans %}<p class="muted">No scans yet. Run <code>sentinel scan create</code> to start one.</p>{% endif %}
"""
)


def render_home(scans: list[dict]) -> str:
    body = _HOME_BODY.render(scans=scans)
    return render_page("Scans", body)


_SCAN_OVERVIEW_BODY = _env.from_string(
    """
<p><strong>Target:</strong> {{ target_name }}<br>
<strong>Mode:</strong> {{ mode }}<br>
<strong>Status:</strong> <span class="badge status-{{ status_class }}">{{ status }}</span><br>
{% if stopped_reason %}<strong>Stopped reason:</strong> {{ stopped_reason }}<br>{% endif %}
<strong>Started:</strong> {{ started_at }}</p>

<h2>Attack Surface</h2>
<table>
<tr><th>Hosts</th><th>Endpoints</th><th>Parameters</th><th>Technologies</th><th>JS assets</th></tr>
<tr>
<td>{{ counts.hosts }}</td><td>{{ counts.endpoints }}</td><td>{{ counts.parameters }}</td>
<td>{{ counts.technologies }}</td><td>{{ counts.js_assets }}</td>
</tr>
</table>
<p><a href="/scans/{{ scan_id }}/attack-surface">View attack surface &raquo;</a></p>

<h2>Findings</h2>
<table>
<tr><th>Disposition</th><th>Count</th></tr>
{% for label, count in disposition_counts.items() %}
<tr><td>{{ label }}</td><td>{{ count }}</td></tr>
{% endfor %}
</table>
{% if not disposition_counts %}<p class="muted">No findings yet — run <code>scan test</code> and
<code>scan verify</code>.</p>{% endif %}
<p><a href="/scans/{{ scan_id }}/findings">View full findings report &raquo;</a></p>

<h2>AI Reasoning</h2>
<p>{{ classification_count }} classification(s) recorded
({{ ai_count }} via AI, {{ fallback_count }} fallback).</p>
<p><a href="/scans/{{ scan_id }}/classifications">View AI reasoning &raquo;</a></p>
"""
)


def render_scan_overview(
    scan_id: str,
    target_name: str,
    mode: str,
    status: str,
    status_class: str,
    stopped_reason: str | None,
    started_at: str,
    counts: dict,
    disposition_counts: dict,
    classification_count: int,
    ai_count: int,
    fallback_count: int,
) -> str:
    body = _SCAN_OVERVIEW_BODY.render(
        scan_id=scan_id,
        target_name=target_name,
        mode=mode,
        status=status,
        status_class=status_class,
        stopped_reason=stopped_reason,
        started_at=started_at,
        counts=counts,
        disposition_counts=disposition_counts,
        classification_count=classification_count,
        ai_count=ai_count,
        fallback_count=fallback_count,
    )
    return render_page(f"Scan {scan_id[:8]}", body, scan_id=scan_id)


_ATTACK_SURFACE_BODY = _env.from_string(
    """
{% for host in hosts %}
<h2>{{ host.hostname }}</h2>
{% if host.technologies %}
<p><strong>Technologies:</strong>
{% for t in host.technologies %}<span class="badge status-default">{{ t.name }}
{% if t.version %}{{ t.version }}{% endif %}</span> {% endfor %}</p>
{% endif %}
<table>
<tr><th>Method</th><th>Path</th><th>Source</th><th>Parameters</th></tr>
{% for e in host.endpoints %}
<tr>
<td>{{ e.method }}</td>
<td><code>{{ e.path }}</code></td>
<td class="muted">{{ e.source }}</td>
<td>{% for p in e.parameters %}<code>{{ p }}</code> {% endfor %}</td>
</tr>
{% endfor %}
</table>
{% endfor %}
{% if not hosts %}<p class="muted">No attack surface discovered yet — run <code>scan crawl</code>.</p>{% endif %}
"""
)


def render_attack_surface(scan_id: str, hosts: list[dict]) -> str:
    body = _ATTACK_SURFACE_BODY.render(hosts=hosts)
    return render_page("Attack Surface", body, scan_id=scan_id)


_CLASSIFICATIONS_BODY = _env.from_string(
    """
<table>
<tr><th>Endpoint</th><th>Parameter</th><th>Classification</th><th>Risk</th>
<th>Recommended tests</th><th>Source</th><th>Reason</th></tr>
{% for c in classifications %}
<tr>
<td>{{ c.endpoint_method }} <code>{{ c.endpoint_path }}</code></td>
<td>{% if c.parameter_name %}<code>{{ c.parameter_name }}</code>{% else %}
<span class="muted">-</span>{% endif %}</td>
<td>{{ c.classification }}</td>
<td>{{ c.risk_score }}</td>
<td>{{ c.recommended_tests | join(', ') }}</td>
<td>{{ c.source }}</td>
<td class="muted">{{ c.reason }}</td>
</tr>
{% endfor %}
</table>
{% if not classifications %}<p class="muted">No AI classifications recorded yet — run
<code>scan classify</code>.</p>{% endif %}
"""
)


def render_classifications(scan_id: str, classifications: list[dict]) -> str:
    body = _CLASSIFICATIONS_BODY.render(classifications=classifications)
    return render_page("AI Reasoning", body, scan_id=scan_id)
