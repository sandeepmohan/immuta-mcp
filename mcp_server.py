"""MCP server exposing the Immuta query toolkit.

Wraps the eleven functions from ``immuta_queries`` as MCP tools. Supports two
transports:

  * ``streamable-http`` (default for containers) — bound to ``0.0.0.0:8080``,
    MCP endpoint at ``/mcp``, protected by a shared bearer token taken from
    the ``MCP_BEARER_TOKEN`` env var.
  * ``stdio`` (default when run locally) — no auth; for LLM clients that
    spawn the server as a subprocess.

Each tool returns the same Pydantic-shaped data the underlying function
produces, dumped to plain JSON. On failure, returns
``{"error": ImmutaError}`` — never raises across the MCP boundary.
"""

from __future__ import annotations

import argparse
import hmac
import os
import sys
from typing import Any

import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import ValidationError
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from immuta_queries import (
    ImmutaAPIException,
    TimeSpan,
    audit_aggregate,
    audit_events,
    datasource_requirements,
    datasources_without_policies,
    list_datasources,
    list_domains,
    list_policies,
    policy_attributes_with_user_counts,
    tag_usage,
    user_access,
    who_has_access,
)

# Disable the SDK's DNS-rebinding Host/Origin allowlist. The bearer-token
# middleware is the real auth on the HTTP transport, and the server is reached
# via cluster-internal DNS and an ingress hostname that vary by deployment.
mcp = FastMCP(
    "immuta-mcp",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    ),
)


def _safe(call) -> Any:
    """Run an Immuta function; convert any ImmutaAPIException to a JSON envelope."""
    try:
        result = call()
    except ImmutaAPIException as e:
        return {"error": e.err.model_dump()}
    if isinstance(result, list):
        return [r.model_dump() for r in result]
    return result.model_dump() if hasattr(result, "model_dump") else result


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def immuta_who_has_access(datasource_id: int) -> Any:
    """Who has access to an Immuta datasource and why.

    Returns one row per user (direct subscribers + domain-granted), each
    enriched with attributes, group memberships, and the governing
    subscription policy.

    Args:
        datasource_id: Immuta datasource id (integer).
    """
    return _safe(lambda: who_has_access(datasource_id))


@mcp.tool()
def immuta_datasources_without_policies() -> Any:
    """List datasources that have neither a subscription nor any data policy.

    Each row includes the datasource id, name, and the full set of tags
    currently bound to it.
    """
    return _safe(datasources_without_policies)


@mcp.tool()
def immuta_tag_usage() -> Any:
    """Count datasources per tag (full dotted hierarchy), sorted desc."""
    return _safe(tag_usage)


@mcp.tool()
def immuta_policy_attributes_with_user_counts() -> Any:
    """Every user attribute referenced in any policy, plus number of holders.

    Returned rows: (attribute_name, attribute_value, referenced_in_policies,
    user_count).
    """
    return _safe(policy_attributes_with_user_counts)


@mcp.tool()
def immuta_datasources(
    search: str | None = None,
    tag: str | None = None,
    domain_id: str | None = None,
) -> Any:
    """List Immuta datasources, optionally filtered by name, tag, or domain.

    With no arguments, returns every datasource — useful for finding the
    datasource ids the other tools take. Filters are applied server-side and
    combinable: `search` matches a name substring (e.g. "customer" finds all
    customer tables), `tag` matches an exact tag name, `domain_id` a domain
    uuid (from immuta_domains).

    Each row: id, name, schema_name, table, subscription_type,
    subscription_condition (the boolean attribute expression a user must
    satisfy to be subscribed, e.g. "@hasAttribute('Location', 'NJ') ..."),
    access_grant.

    Args:
        search: Case-insensitive name substring.
        tag: Exact tag name.
        domain_id: Domain uuid.
    """
    return _safe(lambda: list_datasources(search=search, tag=tag, domain_id=domain_id))


@mcp.tool()
def immuta_policies() -> Any:
    """List every Immuta global policy with its actions, rules, and conditions.

    Each row: policy_key, name, type ("subscription" policies control who may
    read a datasource; "data" policies mask columns or restrict rows for
    subscribed users), staged flag, actions (verbatim Immuta rule JSON plus
    human-readable descriptions), and circumstances — the tag/domain
    conditions deciding which datasources the policy applies to.
    """
    return _safe(list_policies)


@mcp.tool()
def immuta_datasource_requirements(datasource_id: int) -> Any:
    """What a user must satisfy to read one datasource, and what gets masked.

    Combines the datasource's effective subscription policy (after global
    policy inheritance and merging — the "Merged (system-generated)" entry in
    global_policies is the effective combination) with the data policies
    compiled onto it (masking / row-restriction rules and their exception
    conditions).

    `subscription_condition` and each rule's `exception_conditions` are
    boolean expressions over user attributes — compare them against a user's
    `attributes` map (from immuta_who_has_access or immuta_user_access) to
    determine why someone has access or what they still need. Empty
    data_policy_rules means no data policy is compiled for this datasource.

    Args:
        datasource_id: Immuta datasource id (from immuta_datasources).
    """
    return _safe(lambda: datasource_requirements(datasource_id))


@mcp.tool()
def immuta_domains() -> Any:
    """List every Immuta domain: its datasources, assignment rules, and people.

    Each row: domain id (uuid), name, assignment_type ("dynamic" means
    datasources are assigned automatically by tag — `tags` lists the driving
    tags), the datasources currently in the domain, and per-user domain
    permissions (e.g. Manage Policies, Audit Activity) with their source.
    """
    return _safe(list_domains)


@mcp.tool()
def immuta_user_access(user: str, datasource_id: int | None = None) -> Any:
    """What one user can access and why — or what a datasource would require.

    Finds the user by email/userid/name substring and returns their Immuta
    permissions and attribute map, plus datasource access. With
    `datasource_id`: reports has_access for that one datasource along with its
    subscription_condition — a boolean expression over user attributes;
    compare it against the user's `attributes` to explain existing access or
    list the minimum attributes still needed. Without it: returns every
    datasource the user can access (this fans out one HTTP call per
    datasource — pass datasource_id when you only care about one).

    If several users match, the result is `{"error": ...}` with the candidate
    list in `payload` — re-call with the exact email.

    Args:
        user: Email, userid, or name substring (e.g. "sandeep").
        datasource_id: Optional datasource id to restrict the check to.
    """
    return _safe(lambda: user_access(user, datasource_id=datasource_id))


@mcp.tool()
def immuta_audit_events(
    preset: str = "1h",
    start: str | None = None,
    end: str | None = None,
    actor: str | None = None,
    action: str | None = None,
    limit: int = 100,
    include_raw: bool = False,
) -> Any:
    """Fetch individual Immuta audit events for a time span.

    For counts, trends, or visualizations ("query activity by user over the
    last month") use immuta_audit_aggregate instead — it aggregates
    server-side and never ships individual events.

    Data source: the Immuta audit Elasticsearch store, queried through the same
    `/api/audit/rest/v1/search` proxy the Insights→Audit UI uses. Events follow
    Immuta's Universal Audit Model (UAM): `event_timestamp`, `action`,
    `action_status`, `target_type`, `actor`, `targets`. Coverage is the full
    configured ES retention (not a log buffer). `actor` and `action` filters
    are pushed down to Elasticsearch.

    Returns up to `limit` newest events; the envelope's `truncated` is True
    when more matched than were returned (narrow the span or filters).
    `effective_window` is the min/max eventTimestamp actually returned.

    Returns: `{events: [...], requested_window: {start, end},
    effective_window: {start, end}, truncated: bool, source: str}`.

    Args:
        preset: One of ``all``, ``ytd``, ``1y``, ``90d``, ``30d``, ``1d``,
            ``12h``, ``6h``, ``1h``, ``custom``. Default ``1h``.
        start: ISO 8601 UTC timestamp; required when ``preset='custom'``.
        end: ISO 8601 UTC timestamp; optional, defaults to now.
        actor: Filter by actor name (forgiving match).
        action: Filter by UAM action type, e.g. QUERY (case-insensitive).
        limit: Max events returned, 1..1000. Default 100.
        include_raw: Attach each event's full ES `_source` document (large;
            only set when the summary fields are not enough).
    """
    try:
        span = TimeSpan(preset=preset, start=start, end=end)  # type: ignore[arg-type]
        return _safe(lambda: audit_events(span, actor=actor, action=action, limit=limit, include_raw=include_raw))
    except (ValueError, ValidationError) as e:
        return {"error": {"endpoint": "<input>", "message": str(e)}}


@mcp.tool()
def immuta_audit_aggregate(
    group_by: list[str],
    preset: str = "30d",
    start: str | None = None,
    end: str | None = None,
    actor: str | None = None,
    action: str | None = None,
    exclude_unknown_actors: bool = False,
    top_n: int = 10,
) -> Any:
    """Aggregate Immuta audit event counts server-side — built for trends and charts.

    Elasticsearch does the counting (`size: 0` aggregation), so a month of
    activity collapses to a handful of bucket rows regardless of event volume
    — use this instead of immuta_audit_events whenever the question is "how
    many / by whom / over time" rather than "show me the events".

    Group by 1 or 2 dimensions from: ``actor``, ``action``, ``action_status``,
    ``target_type``, ``day``, ``hour``, ``week`` (the last three bucket the
    event timestamp). With two dimensions the second nests inside the first —
    e.g. ``["actor", "day"]`` gives per-user daily activity. Native query
    events whose actor Immuta cannot resolve appear as actor "Unknown" and
    usually dominate totals; set exclude_unknown_actors=True to drop them.

    Returns: `{total: int, group_by: [...], buckets: [{key: {dim: value},
    count: int}, ...], requested_window: {start, end}, source: str}`.

    Args:
        group_by: 1-2 dimensions, e.g. ``["actor", "day"]``.
        preset: One of ``all``, ``ytd``, ``1y``, ``90d``, ``30d``, ``1d``,
            ``12h``, ``6h``, ``1h``, ``custom``. Default ``30d``.
        start: ISO 8601 UTC timestamp; required when ``preset='custom'``.
        end: ISO 8601 UTC timestamp; optional, defaults to now.
        actor: Filter by actor name (forgiving match).
        action: Filter by UAM action type, e.g. QUERY (case-insensitive).
        exclude_unknown_actors: Drop events whose actor is "Unknown".
        top_n: Max buckets per terms dimension, 1..100. Default 10.
    """
    try:
        span = TimeSpan(preset=preset, start=start, end=end)  # type: ignore[arg-type]
        return _safe(lambda: audit_aggregate(
            span, group_by, actor=actor, action=action,
            exclude_unknown_actors=exclude_unknown_actors, top_n=top_n,
        ))
    except (ValueError, ValidationError) as e:
        return {"error": {"endpoint": "<input>", "message": str(e)}}


# ---------------------------------------------------------------------------
# Bearer-token ASGI middleware (HTTP transport only)
# ---------------------------------------------------------------------------


class BearerAuthMiddleware:
    """Reject any request whose ``Authorization: Bearer <token>`` does not
    constant-time match ``MCP_BEARER_TOKEN``. Fails closed if the env var
    is unset."""

    def __init__(self, app: ASGIApp, expected_token: str) -> None:
        self.app = app
        self.expected = expected_token

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        auth = headers.get("authorization", "")
        prefix = "Bearer "
        ok = auth.startswith(prefix) and hmac.compare_digest(auth[len(prefix):], self.expected)
        if not ok:
            response = JSONResponse({"error": "unauthorized"}, status_code=401)
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def _run_http(host: str, port: int) -> None:
    token = os.environ.get("MCP_BEARER_TOKEN", "")
    if not token:
        print(
            '{"error":"MCP_BEARER_TOKEN must be set when --transport http"}',
            file=sys.stderr,
        )
        raise SystemExit(2)
    app = mcp.streamable_http_app()
    app.add_middleware(BearerAuthMiddleware, expected_token=token)
    uvicorn.run(app, host=host, port=port, log_level="info")


def main() -> None:
    parser = argparse.ArgumentParser(prog="mcp_server", description=__doc__)
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        _run_http(args.host, args.port)


if __name__ == "__main__":
    main()
