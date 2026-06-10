"""Immuta self-managed 2026.1.4 query toolkit.

Eleven governance questions, one file, one HTTP helper, one error type. Auth
is read from the environment (`IMMUTA_API_KEY`, `IMMUTA_BASE_URL`); every
public function returns Pydantic models and raises a single structured
exception on failure.
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator, Literal

import httpx
import typer
from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError, model_validator

load_dotenv()

# ---------------------------------------------------------------------------
# Settings, errors, HTTP
# ---------------------------------------------------------------------------


class Settings(BaseModel):
    """Env-loaded API credentials. Fails fast if either var is missing."""

    api_key: str = Field(min_length=1)
    base_url: str = Field(min_length=1)

    @model_validator(mode="after")
    def _strip_slash(self) -> "Settings":
        self.base_url = self.base_url.rstrip("/")
        return self

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            api_key=os.environ.get("IMMUTA_API_KEY", ""),
            base_url=os.environ.get("IMMUTA_BASE_URL", ""),
        )


class ImmutaError(BaseModel):
    """Structured error payload returned for every failed API interaction."""

    endpoint: str
    status_code: int | None = None
    message: str
    payload: Any | None = None


class ImmutaAPIException(Exception):
    def __init__(self, err: ImmutaError) -> None:
        self.err = err
        super().__init__(err.model_dump_json(indent=2))


_TIMEOUT = httpx.Timeout(30.0)


def _get(path: str, params: dict[str, Any] | None = None) -> Any:
    """GET a JSON endpoint. Wraps all failures in ImmutaAPIException."""
    try:
        cfg = Settings.from_env()
    except ValidationError as e:
        raise ImmutaAPIException(
            ImmutaError(endpoint=path, message="missing/invalid IMMUTA_API_KEY or IMMUTA_BASE_URL", payload=e.errors())
        )
    url = f"{cfg.base_url}{path}"
    headers = {"Authorization": f"Bearer {cfg.api_key}", "Accept": "application/json"}
    try:
        r = httpx.get(url, headers=headers, params=params, timeout=_TIMEOUT)
    except httpx.HTTPError as e:
        raise ImmutaAPIException(ImmutaError(endpoint=path, message=f"transport error: {e}"))
    if r.status_code >= 400:
        try:
            body: Any = r.json()
        except json.JSONDecodeError:
            body = r.text
        raise ImmutaAPIException(
            ImmutaError(endpoint=path, status_code=r.status_code, message=r.reason_phrase, payload=body)
        )
    try:
        return r.json()
    except json.JSONDecodeError as e:
        raise ImmutaAPIException(ImmutaError(endpoint=path, message=f"non-JSON response: {e}"))


def _post(path: str, json_body: dict[str, Any]) -> Any:
    """POST a JSON body to an endpoint. Wraps all failures in ImmutaAPIException."""
    try:
        cfg = Settings.from_env()
    except ValidationError as e:
        raise ImmutaAPIException(
            ImmutaError(endpoint=path, message="missing/invalid IMMUTA_API_KEY or IMMUTA_BASE_URL", payload=e.errors())
        )
    url = f"{cfg.base_url}{path}"
    headers = {
        "Authorization": f"Bearer {cfg.api_key}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    try:
        r = httpx.post(url, headers=headers, json=json_body, timeout=_TIMEOUT)
    except httpx.HTTPError as e:
        raise ImmutaAPIException(ImmutaError(endpoint=path, message=f"transport error: {e}"))
    if r.status_code >= 400:
        try:
            body: Any = r.json()
        except json.JSONDecodeError:
            body = r.text
        raise ImmutaAPIException(
            ImmutaError(endpoint=path, status_code=r.status_code, message=r.reason_phrase, payload=body)
        )
    try:
        return r.json()
    except json.JSONDecodeError as e:
        raise ImmutaAPIException(ImmutaError(endpoint=path, message=f"non-JSON response: {e}"))


def _paginate(path: str, params: dict[str, Any] | None = None, page_size: int = 200) -> Iterator[dict]:
    """Yield every item from an Immuta `size`/`offset` paginated endpoint.

    Envelope shapes seen in self-managed 2026.x: `{"hits": [...]}`,
    `{"dataSources": [...]}`, `{"results": [...]}`, `{"data": [...]}` (the
    `/domain*` endpoints), or a bare top-level list. We probe in that order so
    the helper works across endpoints without per-caller wiring.
    """
    offset = 0
    while True:
        page_params = {**(params or {}), "size": page_size, "offset": offset}
        data = _get(path, page_params)
        if isinstance(data, dict):
            items = data.get("hits") or data.get("dataSources") or data.get("results") or data.get("data") or []
        else:
            items = data
        if not items:
            return
        for item in items:
            yield item
        if len(items) < page_size:
            return
        offset += page_size


# ---------------------------------------------------------------------------
# Output models
# ---------------------------------------------------------------------------


class UserAccess(BaseModel):
    user_id: str
    name: str | None = None
    email: str | None = None
    access_via: Literal["direct", "domain", "policy"]
    reason: str
    attributes: dict[str, list[str]] = Field(default_factory=dict)
    groups: list[str] = Field(default_factory=list)
    policy_name: str | None = None
    policy_id: str | None = None


class DatasourceTags(BaseModel):
    datasource_id: int
    name: str
    tags: list[str] = Field(default_factory=list)


class TagUsage(BaseModel):
    tag: str
    datasource_count: int


class PolicyAttributeUsage(BaseModel):
    attribute_name: str
    attribute_value: str
    referenced_in_policies: list[str]
    user_count: int


class DatasourceSummary(BaseModel):
    """One row of the `/dataSource` list payload (no per-datasource detail calls)."""

    id: int
    name: str
    schema_name: str | None = None
    table: str | None = None
    subscription_type: str | None = None
    subscription_condition: str | None = None  # subscriptionPolicy.advanced, verbatim
    access_grant: str | None = None


class PolicyAction(BaseModel):
    type: str | None = None
    description: str | None = None
    rules: Any | None = None  # raw policy-rule JSON, passed through verbatim


class PolicySummary(BaseModel):
    policy_key: str | None = None
    name: str
    type: str  # "data" | "subscription"
    staged: bool = False
    actions: list[PolicyAction] = Field(default_factory=list)
    circumstances: Any | None = None  # where/when the policy applies, verbatim


class GlobalPolicyRef(BaseModel):
    id: int | None = None
    name: str
    type: str | None = None
    disabled: bool | None = None
    access_grant: str | None = None


class DataPolicyRule(BaseModel):
    policy_type: str  # "masking" | "rowOrObjectRestriction" | ...
    fields: list[Any] = Field(default_factory=list)
    masking: Any | None = None  # maskingConfig, verbatim
    exception_conditions: Any | None = None  # exceptions tree (masking rules), verbatim
    qualifications: Any | None = None  # row-restriction visibility conditions, verbatim


class DatasourceRequirements(BaseModel):
    """Everything a user must satisfy to read a datasource, plus the data
    policies (masking / row restrictions) layered onto it."""

    datasource_id: int
    name: str
    domains: list[dict[str, Any]] = Field(default_factory=list)  # [{id, name}]
    subscription_type: str | None = None
    subscription_condition: str | None = None  # the READ requirement, verbatim
    access_grant: str | None = None
    global_policies: list[GlobalPolicyRef] = Field(default_factory=list)
    data_policy_rules: list[DataPolicyRule] = Field(default_factory=list)
    rules_dsl: str | None = None  # compiled policy-handler rule DSL, verbatim


class DomainDatasourceRef(BaseModel):
    id: int
    name: str


class DomainPermission(BaseModel):
    user_name: str | None = None
    user_object_id: str | None = None
    permissions: list[str] = Field(default_factory=list)
    source: list[str] = Field(default_factory=list)


class DomainInfo(BaseModel):
    id: str  # domain uuid
    name: str
    description: str | None = None
    assignment_type: str | None = None  # "dynamic" assigns datasources by tag
    tags: list[str] = Field(default_factory=list)  # the dynamic-assignment tags
    datasources: list[DomainDatasourceRef] = Field(default_factory=list)
    permissions: list[DomainPermission] = Field(default_factory=list)


class UserDatasourceAccess(BaseModel):
    datasource_id: int
    name: str
    has_access: bool
    subscription_condition: str | None = None  # what access requires, verbatim


class UserAccessReport(BaseModel):
    user_id: str  # BIM userid (email)
    name: str | None = None
    email: str | None = None
    permissions: list[str] = Field(default_factory=list)
    attributes: dict[str, list[str]] = Field(default_factory=dict)
    groups: list[str] = Field(default_factory=list)
    datasources: list[UserDatasourceAccess] = Field(default_factory=list)


class AuditEvent(BaseModel):
    """One Universal Audit Model (UAM) event from the Immuta audit ES store."""

    event_timestamp: str | None = None
    id: str | None = None
    action: str | None = None
    action_status: str | None = None
    target_type: str | None = None
    actor: dict[str, Any] | None = None
    targets: list[dict[str, Any]] = Field(default_factory=list)
    raw: dict | None = None  # full ES _source; populated only when include_raw=True


class AuditResult(BaseModel):
    """Wrapped audit response: events plus diagnostics about coverage.

    `effective_window` is the min/max eventTimestamp actually returned.
    `truncated` is True when more events matched the window than the
    MAX_AUDIT_EVENTS cap returned (narrow the span to see the rest).
    """

    events: list[AuditEvent]
    requested_window: dict[str, str]
    effective_window: dict[str, str]
    truncated: bool
    source: str = "Immuta audit Elasticsearch API (POST /api/audit/rest/v1/search)"


class AuditBucket(BaseModel):
    key: dict[str, str]  # {group_by dim: bucket value} — one entry per dim
    count: int


class AuditAggregate(BaseModel):
    """Server-side aggregated audit counts — tiny payload, full-window coverage."""

    total: int
    group_by: list[str]
    buckets: list[AuditBucket]
    requested_window: dict[str, str]
    source: str = "Immuta audit Elasticsearch API (POST /api/audit/rest/v1/search, size:0 aggs)"


SpanPreset = Literal["all", "ytd", "1y", "90d", "30d", "1d", "12h", "6h", "1h", "custom"]


class TimeSpan(BaseModel):
    """Audit time span. Use a preset or `custom` with `start`/`end` (ISO 8601 UTC)."""

    preset: SpanPreset = "30d"
    start: datetime | None = None
    end: datetime | None = None

    def _resolve_range(self) -> tuple[datetime, datetime]:
        now = datetime.now(timezone.utc)
        end = self.end or now
        if self.preset == "custom":
            if not self.start:
                raise ValueError("custom span requires `start`")
            start = self.start
        elif self.preset == "all":
            start = datetime(1970, 1, 1, tzinfo=timezone.utc)
        elif self.preset == "ytd":
            start = datetime(now.year, 1, 1, tzinfo=timezone.utc)
        else:
            hours = {
                "1y": 365 * 24,
                "90d": 90 * 24,
                "30d": 30 * 24,
                "1d": 24,
                "12h": 12,
                "6h": 6,
                "1h": 1,
            }[self.preset]
            start = now - timedelta(hours=hours)
        return start, end

    def resolve_iso(self) -> tuple[str, str]:
        start, end = self._resolve_range()
        return _to_rfc3339(start), _to_rfc3339(end)


def _to_rfc3339(d: datetime) -> str:
    return d.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Q1 — who has access to a datasource
# ---------------------------------------------------------------------------


def who_has_access(datasource_id: int) -> list[UserAccess]:
    """Return every user with access to a datasource and *why* they have it.

    Explanation
    -----------
    Resolves users with access from `/dataSource/{id}/access` (carries name,
    email, and grant state per user), then — for each domain the datasource
    belongs to — adds the domain's permission holders from
    `/domain/{uuid}/permissions` (people with Manage Policies / Audit Activity
    etc. on the domain, not data subscribers). Each user is enriched with their
    attribute map (Immuta "authorizations") via a single paginated pass over
    `/bim/user`, keyed by `userid`; domain rows key on `userObjectId` so they
    may miss that enrichment. The governing subscription policy on the
    datasource is attached as policy_name/policy_id.

    I/O
    ---
    Input  : datasource_id (int) — Immuta datasource id.
    Output : list[UserAccess] — one row per user, deduplicated by user_id.
    Raises : ImmutaAPIException on any HTTP/JSON failure.
    """
    ds = _get(f"/dataSource/{datasource_id}")
    sub_policy = ds.get("subscriptionPolicy") or {}
    policy_name = sub_policy.get("name")
    policy_id = sub_policy.get("id")
    out: dict[str, UserAccess] = {}

    access = _get(f"/dataSource/{datasource_id}/access") or {}
    for u in access.get("users") or []:
        uid = str(u.get("userid") or u.get("profile"))
        out[uid] = UserAccess(
            user_id=uid,
            name=u.get("name"),
            email=u.get("email"),
            access_via="direct",
            reason=u.get("state") or u.get("subscriptionContext") or "direct subscription",
            policy_name=policy_name,
            policy_id=str(policy_id) if policy_id else None,
        )

    for dom in ds.get("domains") or []:
        for u in _paginate(f"/domain/{dom.get('id')}/permissions"):
            uid = str(u.get("userObjectId") or u.get("profileId"))
            if uid in out:
                continue
            out[uid] = UserAccess(
                user_id=uid,
                name=u.get("name"),
                access_via="domain",
                reason=f"holds {', '.join(u.get('permissions') or [])} in domain {dom.get('name')}",
                policy_name=policy_name,
                policy_id=str(policy_id) if policy_id else None,
            )

    # Enrich each row with its attribute map ("authorizations" in BIM) via one
    # paginated pass over /bim/user, keyed by userid. Groups are not exposed on
    # the BIM user object, so groups stays empty.
    if out:
        authz_by_user = {
            str(u.get("userid")): (u.get("authorizations") or {})
            for u in _paginate("/bim/user")
        }
        for uid, row in out.items():
            row.attributes = authz_by_user.get(uid, {})

    return list(out.values())


# ---------------------------------------------------------------------------
# Q2 — datasources with no policies
# ---------------------------------------------------------------------------


def datasources_without_policies() -> list[DatasourceTags]:
    """List datasources that have neither a subscription nor any data policy.

    Explanation
    -----------
    Streams `/dataSource` (the list payload carries neither tags nor policy
    detail), then fetches `/dataSource/{id}` for each — that detail response
    carries the policy signals (`subscriptionPolicy`, `accessPolicies`,
    `policyHandler`, `globalPolicies`) *and* the bound `tags` in one call. Keeps
    rows where every policy signal is null/empty, attaching the datasource's tags.

    I/O
    ---
    Input  : none
    Output : list[DatasourceTags] — id, name, tags for each unprotected datasource.
    Raises : ImmutaAPIException on any HTTP/JSON failure.
    """
    out: list[DatasourceTags] = []
    for ds in _paginate("/dataSource"):
        ds_id = ds.get("id")
        d = _get(f"/dataSource/{ds_id}")
        if d.get("subscriptionPolicy") or d.get("accessPolicies") \
                or d.get("policyHandler") or d.get("globalPolicies"):
            continue
        tag_names = [t.get("name") for t in (d.get("tags") or []) if isinstance(t, dict) and t.get("name")]
        out.append(DatasourceTags(datasource_id=ds_id, name=ds.get("name", ""), tags=tag_names))
    return out


# ---------------------------------------------------------------------------
# Q3 — tag usage (full hierarchy)
# ---------------------------------------------------------------------------


def tag_usage() -> list[TagUsage]:
    """Tally how many datasources carry each tag (full dotted hierarchy).

    Explanation
    -----------
    Streams `/dataSource` (whose list payload carries no tags), then fetches
    `/dataSource/{id}/tags` per datasource — that returns `{"tags": [...]}` with
    each tag's full hierarchical `name` (e.g. `PII.Identifier.Email`). Counts
    distinct datasources per tag. Result sorted by count descending.

    I/O
    ---
    Input  : none
    Output : list[TagUsage] — (tag, datasource_count) sorted desc.
    Raises : ImmutaAPIException on any HTTP/JSON failure.
    """
    counts: Counter[str] = Counter()
    for ds in _paginate("/dataSource"):
        resp = _get(f"/dataSource/{ds.get('id')}/tags") or {}
        seen = {t.get("name") for t in (resp.get("tags") or []) if isinstance(t, dict) and t.get("name")}
        counts.update(seen)
    return [TagUsage(tag=t, datasource_count=n) for t, n in counts.most_common()]


# ---------------------------------------------------------------------------
# Q4 — attributes referenced in policies + user counts
# ---------------------------------------------------------------------------


def _walk_attributes(node: Any, found: dict[tuple[str, str], set[str]], policy_label: str) -> None:
    """Recursively pull (attribute_name, attribute_value) pairs from a policy node.

    Matches both attribute-typed condition nodes and `authorizations`
    condition leaves, whose shape is `{"auth": <name>, "value": <value>}`.
    """
    if isinstance(node, dict):
        n = node.get("name") or node.get("key") or node.get("attribute") or node.get("auth")
        v = node.get("value")
        t = (node.get("type") or "").lower()
        if n and v is not None and (
            "attribute" in t or "hasattribute" in t or node.get("attribute") or node.get("auth")
        ):
            found[(str(n), str(v))].add(policy_label)
        for child in node.values():
            _walk_attributes(child, found, policy_label)
    elif isinstance(node, list):
        for child in node:
            _walk_attributes(child, found, policy_label)


def policy_attributes_with_user_counts() -> list[PolicyAttributeUsage]:
    """Find every user attribute referenced in any policy and count holders.

    Explanation
    -----------
    Attempts `/policy/global` and `/policy/data`, skipping either endpoint
    that returns 404 (Immuta 2026.x dropped `/policy/data`; older builds may
    still expose it). Walks each policy's JSON tree for nodes that look like
    attribute predicates ((name, value) pairs on attribute-typed conditions).
    Then streams `/bim/user` once and tallies how many users hold each
    (name, value) pair in their `authorizations` map (BIM stores a user's
    attribute values under `authorizations`, not `attributes`).

    I/O
    ---
    Input  : none
    Output : list[PolicyAttributeUsage] sorted by user_count desc. An empty
             list means policies were scanned but none reference user
             attributes (not a failure).
    Raises : ImmutaAPIException on any HTTP/JSON failure, and when *every*
             candidate policy endpoint returns 404 (so a total endpoint
             failure is never silently reported as "no attributes").
    """
    found: dict[tuple[str, str], set[str]] = defaultdict(set)
    candidates = ("/policy/global", "/policy/data")
    reached_any = False
    for endpoint in candidates:
        try:
            policies = _get(endpoint) or []
        except ImmutaAPIException as e:
            if e.err.status_code == 404:
                continue
            raise
        reached_any = True
        items = policies.get("hits") if isinstance(policies, dict) else policies
        for p in items or []:
            label = p.get("name") or p.get("id") or endpoint
            _walk_attributes(p, found, str(label))

    # If *every* candidate endpoint 404'd, that's a real failure, not "no
    # attribute policies" — surface it instead of returning a misleading [].
    if not reached_any:
        raise ImmutaAPIException(
            ImmutaError(
                endpoint=" / ".join(candidates),
                status_code=404,
                message="no policy endpoint reachable (all candidates returned 404)",
            )
        )

    # User attribute values live under "authorizations" in BIM, not "attributes".
    user_attrs: list[dict[str, list[str]]] = []
    for u in _paginate("/bim/user"):
        user_attrs.append(u.get("authorizations") or {})

    out: list[PolicyAttributeUsage] = []
    for (name, value), policies in found.items():
        count = sum(1 for a in user_attrs if value in (a.get(name) or []))
        out.append(
            PolicyAttributeUsage(
                attribute_name=name,
                attribute_value=value,
                referenced_in_policies=sorted(policies),
                user_count=count,
            )
        )
    out.sort(key=lambda r: r.user_count, reverse=True)
    return out


# ---------------------------------------------------------------------------
# Q6 — list / search datasources
# ---------------------------------------------------------------------------


def list_datasources(
    search: str | None = None,
    tag: str | None = None,
    domain_id: str | None = None,
) -> list[DatasourceSummary]:
    """List datasources, optionally filtered by name substring, tag, or domain.

    Explanation
    -----------
    Streams `/dataSource` with Immuta's server-side filters: `searchText`
    (case-insensitive name substring), `tag` (exact tag name), and `domainId`
    (domain uuid). All filters are optional and combinable; with none given,
    every datasource is returned. Rows come straight from the list payload —
    including the subscription policy's `advanced` condition string — with no
    per-datasource detail calls.

    I/O
    ---
    Input  : search (str|None) — name substring; tag (str|None) — exact tag
             name; domain_id (str|None) — domain uuid.
    Output : list[DatasourceSummary] — id, name, schema/table, subscription
             type, condition string, access grant. Empty list when no
             datasource matches the filters.
    Raises : ImmutaAPIException on any HTTP/JSON failure.
    """
    params: dict[str, Any] = {}
    if search:
        params["searchText"] = search
    if tag:
        params["tag"] = tag
    if domain_id:
        params["domainId"] = domain_id

    out: list[DatasourceSummary] = []
    for ds in _paginate("/dataSource", params):
        if ds.get("deleted"):
            continue
        sub = ds.get("subscriptionPolicy") or {}
        out.append(
            DatasourceSummary(
                id=ds.get("id"),
                name=ds.get("name", ""),
                schema_name=ds.get("remoteSchema"),
                table=ds.get("remoteTable"),
                subscription_type=sub.get("subscriptionType"),
                subscription_condition=sub.get("advanced"),
                access_grant=sub.get("accessGrant"),
            )
        )
    return out


# ---------------------------------------------------------------------------
# Q7 — global policies and their conditions
# ---------------------------------------------------------------------------


def list_policies() -> list[PolicySummary]:
    """List every global policy with its actions, rules, and conditions.

    Explanation
    -----------
    Reads `/policy/global` and returns each non-deleted policy with its type
    (`subscription` controls who may read a datasource; `data` masks columns
    or restricts rows for subscribed users), staged flag, actions (rule JSON
    passed through verbatim, plus Immuta's own human-readable descriptions),
    and `circumstances` — the tag/domain conditions that decide which
    datasources the policy applies to.

    I/O
    ---
    Input  : none
    Output : list[PolicySummary]. Rule and circumstance JSON is verbatim
             Immuta policy structure for the caller to reason over.
    Raises : ImmutaAPIException on any HTTP/JSON failure.
    """
    policies = _get("/policy/global") or []
    items = policies.get("hits") if isinstance(policies, dict) else policies
    out: list[PolicySummary] = []
    for p in items or []:
        if p.get("deleted"):
            continue
        actions = [
            PolicyAction(type=a.get("type"), description=a.get("description"), rules=a.get("rules"))
            for a in (p.get("actions") or [])
        ]
        out.append(
            PolicySummary(
                policy_key=p.get("policyKey"),
                name=p.get("name", ""),
                type=p.get("type", ""),
                staged=bool(p.get("staged")),
                actions=actions,
                circumstances=p.get("circumstances"),
            )
        )
    return out


# ---------------------------------------------------------------------------
# Q8 — effective read/write requirements on one datasource
# ---------------------------------------------------------------------------


def datasource_requirements(datasource_id: int) -> DatasourceRequirements:
    """What a user must satisfy to read a datasource, and what is masked/filtered.

    Explanation
    -----------
    Combines `/dataSource/{id}` (the subscription policy's `advanced` condition
    string — the read requirement after global policy inheritance and merging —
    plus the contributing `globalPolicies`, where the "Merged (system-generated)"
    entry is the effective combination) with `/policy/handler/{id}` (the data
    policies actually compiled onto the datasource: masking rules with their
    `exception_conditions`, row-restriction rules with their `qualifications` —
    the attribute predicates a user must meet to see unmasked/unfiltered data).
    Condition strings and condition trees are returned verbatim for the caller
    to reason over.

    A 404 from `/policy/handler/{id}` means no data-policy handler is compiled
    for this datasource (not a moved endpoint — the detail call above already
    proved the instance reachable) and yields empty `data_policy_rules`.

    I/O
    ---
    Input  : datasource_id (int) — Immuta datasource id.
    Output : DatasourceRequirements — domains, subscription condition,
             contributing global policies, effective data-policy rules.
    Raises : ImmutaAPIException on any HTTP/JSON failure (including an unknown
             datasource id).
    """
    ds = _get(f"/dataSource/{datasource_id}")
    sub = ds.get("subscriptionPolicy") or {}
    global_policies = [
        GlobalPolicyRef(
            id=g.get("id"),
            name=g.get("name", ""),
            type=g.get("type"),
            disabled=g.get("disabled"),
            access_grant=g.get("accessGrant"),
        )
        for g in (ds.get("globalPolicies") or [])
    ]

    rules_dsl: str | None = None
    data_rules: list[DataPolicyRule] = []
    try:
        handler = _get(f"/policy/handler/{datasource_id}") or {}
    except ImmutaAPIException as e:
        if e.err.status_code != 404:
            raise
        handler = {}
    rules_dsl = handler.get("rules")
    for jp in handler.get("jsonPolicies") or []:
        for rule in jp.get("rules") or []:
            cfg = rule.get("config") or {}
            data_rules.append(
                DataPolicyRule(
                    policy_type=jp.get("type", ""),
                    fields=cfg.get("fields") or [],
                    masking=cfg.get("maskingConfig"),
                    exception_conditions=rule.get("exceptions"),
                    qualifications=cfg.get("qualifications"),
                )
            )

    return DatasourceRequirements(
        datasource_id=datasource_id,
        name=ds.get("name", ""),
        domains=ds.get("domains") or [],
        subscription_type=sub.get("subscriptionType"),
        subscription_condition=sub.get("advanced"),
        access_grant=sub.get("accessGrant"),
        global_policies=global_policies,
        data_policy_rules=data_rules,
        rules_dsl=rules_dsl,
    )


# ---------------------------------------------------------------------------
# Q9 — domains: datasources, assignment conditions, user permissions
# ---------------------------------------------------------------------------


def list_domains() -> list[DomainInfo]:
    """List every domain with its datasources and per-user domain permissions.

    Explanation
    -----------
    Streams `/domain`, then per domain fetches `/domain/{uuid}/datasources`
    (which datasources belong to it) and `/domain/{uuid}/permissions` (who
    holds which domain permissions, e.g. Manage Policies / Audit Activity, and
    from what source). `assignment_type == "dynamic"` means datasources are
    assigned by tag — `tags` lists the tags that drive that assignment.

    I/O
    ---
    Input  : none
    Output : list[DomainInfo] — one row per domain.
    Raises : ImmutaAPIException on any HTTP/JSON failure.
    """
    out: list[DomainInfo] = []
    for d in _paginate("/domain"):
        dom_id = d.get("id")
        datasources = [
            DomainDatasourceRef(id=ds.get("dataSourceId"), name=ds.get("name", ""))
            for ds in _paginate(f"/domain/{dom_id}/datasources")
            if not ds.get("deleted")
        ]
        permissions = [
            DomainPermission(
                user_name=p.get("name"),
                user_object_id=str(p.get("userObjectId")) if p.get("userObjectId") is not None else None,
                permissions=p.get("permissions") or [],
                source=p.get("source") or [],
            )
            for p in _paginate(f"/domain/{dom_id}/permissions")
        ]
        out.append(
            DomainInfo(
                id=str(dom_id),
                name=d.get("name", ""),
                description=d.get("description"),
                assignment_type=d.get("assignmentType"),
                tags=[t.get("name") for t in (d.get("tags") or []) if isinstance(t, dict) and t.get("name")],
                datasources=datasources,
                permissions=permissions,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Q10 — one user's access: attributes, datasources, and why
# ---------------------------------------------------------------------------


def user_access(user: str, datasource_id: int | None = None) -> UserAccessReport:
    """What a user can access and why — or what one datasource would require.

    Explanation
    -----------
    Finds the user via `/bim/user` searched by both `userid` (email) and
    `name` (display name), each substring-matched (an exact case-insensitive
    match on email/userid or display name wins; a single hit is accepted as-is;
    zero or multiple ambiguous hits raise a structured error whose payload
    lists the candidates — re-call with the exact email). Returns their Immuta
    permissions and attribute map (`authorizations`), then resolves datasource
    access. With `datasource_id`: checks that one datasource's subscriber list
    and reports `has_access` plus the datasource's subscription condition —
    comparing that condition against the user's attributes shows why they have
    access or what they still need. Without it: fans out across every
    datasource's `/dataSource/{id}/access` list (O(datasources) HTTP calls —
    pass datasource_id when you only care about one) and returns only the
    datasources the user can access.

    I/O
    ---
    Input  : user (str) — email, userid, or name substring;
             datasource_id (int|None) — restrict the check to one datasource.
    Output : UserAccessReport — identity, permissions, attributes, and
             per-datasource access rows with the governing condition string.
    Raises : ImmutaAPIException on any HTTP/JSON failure, when no user matches,
             or when several users match ambiguously (candidates in payload).
    """
    # `userid` matches emails, `name` matches display names; both are
    # substring searches, so query each and merge by user id.
    hits_by_id: dict[Any, dict] = {h.get("id"): h for h in _paginate("/bim/user", {"userid": user})}
    for h in _paginate("/bim/user", {"name": user}):
        hits_by_id.setdefault(h.get("id"), h)
    hits = list(hits_by_id.values())
    needle = user.strip().lower()
    exact = [
        h for h in hits
        if needle in (
            str(h.get("userid", "")).lower(),
            str((h.get("profile") or {}).get("name", "")).lower(),
            str((h.get("profile") or {}).get("email", "")).lower(),
        )
    ]
    if len(exact) == 1:
        match = exact[0]
    elif len(hits) == 1:
        match = hits[0]
    elif not hits:
        raise ImmutaAPIException(
            ImmutaError(endpoint="/bim/user", message=f"no user matched {user!r}")
        )
    else:
        candidates = [
            {"id": h.get("id"), "userid": h.get("userid"), "name": (h.get("profile") or {}).get("name")}
            for h in hits
        ]
        raise ImmutaAPIException(
            ImmutaError(
                endpoint="/bim/user",
                message=f"multiple users matched {user!r}; re-call with the exact email",
                payload=candidates,
            )
        )

    profile = match.get("profile") or {}
    userid = str(match.get("userid", ""))
    report = UserAccessReport(
        user_id=userid,
        name=profile.get("name"),
        email=profile.get("email"),
        permissions=match.get("permissions") or [],
        attributes=match.get("authorizations") or {},
        groups=match.get("groups") or [],
    )

    def _row(ds_id: int, name: str, condition: str | None) -> UserDatasourceAccess:
        access = _get(f"/dataSource/{ds_id}/access") or {}
        subscribed = any(str(u.get("userid")) == userid for u in access.get("users") or [])
        return UserDatasourceAccess(
            datasource_id=ds_id, name=name, has_access=subscribed,
            subscription_condition=condition,
        )

    if datasource_id is not None:
        ds = _get(f"/dataSource/{datasource_id}")
        condition = (ds.get("subscriptionPolicy") or {}).get("advanced")
        report.datasources.append(_row(datasource_id, ds.get("name", ""), condition))
    else:
        for ds in _paginate("/dataSource"):
            if ds.get("deleted"):
                continue
            condition = (ds.get("subscriptionPolicy") or {}).get("advanced")
            row = _row(ds.get("id"), ds.get("name", ""), condition)
            if row.has_access:
                report.datasources.append(row)

    return report


# ---------------------------------------------------------------------------
# Q5 — audit events (read from the Immuta audit Elasticsearch API)
# ---------------------------------------------------------------------------
#
# The audit-service pod ingests Universal Audit Model (UAM) events into
# Elasticsearch (POST /api/audit/events is a write endpoint — it does NOT print
# events to stdout). The Insights→Audit UI reads them back through an ES
# `_search` proxy at POST /api/audit/rest/v1/search, authenticated with the same
# Immuta API key. We query that proxy directly.

MAX_AUDIT_EVENTS = 1000  # cap on events returned per call (ES from+size max is 10000)

# group_by vocabulary → ES aggregation clause. Terms aggs MUST hit `.keyword`
# subfields (bare text fields 400 with a fielddata error). Single home for
# every audit ES field name used in aggregations.
AUDIT_AGG_FIELDS: dict[str, dict[str, Any]] = {
    "actor":         {"terms": {"field": "actor.name.keyword"}},
    "action":        {"terms": {"field": "action.keyword"}},
    "action_status": {"terms": {"field": "actionStatus.keyword"}},
    "target_type":   {"terms": {"field": "targetType.keyword"}},
    "day":  {"date_histogram": {"field": "eventTimestamp", "calendar_interval": "day"}},
    "hour": {"date_histogram": {"field": "eventTimestamp", "calendar_interval": "hour"}},
    "week": {"date_histogram": {"field": "eventTimestamp", "calendar_interval": "week"}},
}


def _audit_filters(start_iso: str, end_iso: str, actor: str | None, action: str | None) -> list[dict]:
    """Build the bool/filter clauses shared by audit_events and audit_aggregate."""
    filters: list[dict] = [{"range": {"eventTimestamp": {"gte": start_iso, "lte": end_iso}}}]
    if actor:
        filters.append({"match": {"actor.name": actor}})  # analyzed text → forgiving match
    if action:
        filters.append({"term": {"action.keyword": action.upper()}})  # closed uppercase vocabulary
    return filters


def audit_events(
    span: TimeSpan,
    actor: str | None = None,
    action: str | None = None,
    limit: int = 100,
    include_raw: bool = False,
) -> AuditResult:
    """Fetch Immuta audit events for a time span from the audit Elasticsearch API.

    Explanation
    -----------
    POSTs an Elasticsearch query to `/api/audit/rest/v1/search` (the same ES
    `_search` proxy the Insights→Audit UI uses), filtering on the UAM
    `eventTimestamp` range — optionally narrowed by actor name and/or action
    type, pushed down to Elasticsearch — and sorting newest-first. Returns up
    to `limit` events; `truncated=True` when more matched than were returned
    (narrow the span or filters to see the rest). For counts and trends use
    `audit_aggregate` instead — it never ships individual events. This reads
    the durable ES audit store, so coverage is the full configured retention.

    I/O
    ---
    Input  : span (TimeSpan) — preset like "1h"/"6h"/"30d"/"ytd"/"all" or "custom";
             actor (str|None) — actor name to match; action (str|None) — UAM
             action type, e.g. QUERY (case-insensitive); limit (int) — max
             events returned, 1..MAX_AUDIT_EVENTS, default 100; include_raw
             (bool) — attach each event's full ES `_source` (large).
    Output : AuditResult — events plus diagnostics (requested/effective windows,
             truncated flag, source description).
    Raises : ImmutaAPIException on any HTTP/JSON failure; ValueError if `custom`
             is chosen without `start` or `limit` is out of range.
    """
    if not 1 <= limit <= MAX_AUDIT_EVENTS:
        raise ValueError(f"limit must be 1..{MAX_AUDIT_EVENTS}, got {limit}")
    start_iso, end_iso = span.resolve_iso()
    body = {
        "size": limit,
        "track_total_hits": True,
        "sort": [{"eventTimestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": _audit_filters(start_iso, end_iso, actor, action)}},
    }
    resp = _post("/api/audit/rest/v1/search", body)

    hits = (resp.get("hits") or {}).get("hits") or []
    total = ((resp.get("hits") or {}).get("total") or {}).get("value", len(hits))
    out: list[AuditEvent] = []
    for h in hits:
        s = h.get("_source")
        if not isinstance(s, dict):
            continue
        out.append(
            AuditEvent(
                event_timestamp=s.get("eventTimestamp"),
                id=str(s.get("id")) if s.get("id") is not None else None,
                action=s.get("action"),
                action_status=s.get("actionStatus"),
                target_type=s.get("targetType"),
                actor=s.get("actor") if isinstance(s.get("actor"), dict) else None,
                targets=s.get("targets") if isinstance(s.get("targets"), list) else [],
                raw=s if include_raw else None,
            )
        )

    timestamps = [ev.event_timestamp for ev in out if ev.event_timestamp]
    effective = {"start": min(timestamps), "end": max(timestamps)} if timestamps else {"start": "", "end": ""}

    return AuditResult(
        events=out,
        requested_window={"start": start_iso, "end": end_iso},
        effective_window=effective,
        truncated=total > len(out),
    )


def audit_aggregate(
    span: TimeSpan,
    group_by: list[str],
    actor: str | None = None,
    action: str | None = None,
    exclude_unknown_actors: bool = False,
    top_n: int = 10,
) -> AuditAggregate:
    """Aggregate audit event counts server-side in Elasticsearch.

    Explanation
    -----------
    POSTs a `size: 0` aggregation query to `/api/audit/rest/v1/search`, so
    Elasticsearch returns bucket counts instead of events — a month of activity
    collapses to a handful of rows regardless of event volume. Group by one or
    two dimensions from: actor, action, action_status, target_type, day, hour,
    week (the last three bucket `eventTimestamp`). With two dimensions the
    second nests inside the first ("actor" + "day" → per-actor daily counts).
    Native query events whose actor Immuta cannot resolve are recorded with
    actor "Unknown" and usually dominate the totals; set
    `exclude_unknown_actors=True` to drop them.

    I/O
    ---
    Input  : span (TimeSpan); group_by (list[str]) — 1 or 2 of the dimensions
             above; actor/action — optional pushdown filters (as in
             audit_events); exclude_unknown_actors (bool); top_n (int) — max
             buckets per terms dimension, 1..100, default 10.
    Output : AuditAggregate — total matching events plus flat bucket rows,
             each keyed by its group_by values.
    Raises : ImmutaAPIException on any HTTP/JSON failure; ValueError on an
             unknown group_by dimension or out-of-range top_n.
    """
    unknown = [g for g in group_by if g not in AUDIT_AGG_FIELDS]
    if unknown or not 1 <= len(group_by) <= 2:
        raise ValueError(
            f"group_by must be 1-2 of {sorted(AUDIT_AGG_FIELDS)}, got {group_by}"
        )
    if not 1 <= top_n <= 100:
        raise ValueError(f"top_n must be 1..100, got {top_n}")
    start_iso, end_iso = span.resolve_iso()

    def _clause(dim: str) -> dict:
        clause = json.loads(json.dumps(AUDIT_AGG_FIELDS[dim]))  # deep copy
        if "terms" in clause:
            clause["terms"]["size"] = top_n
        return clause

    agg = _clause(group_by[0])
    if len(group_by) == 2:
        agg["aggs"] = {"sub": _clause(group_by[1])}

    bool_query: dict[str, Any] = {"filter": _audit_filters(start_iso, end_iso, actor, action)}
    if exclude_unknown_actors:
        bool_query["must_not"] = [{"term": {"actor.name.keyword": "Unknown"}}]

    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": bool_query},
        "aggs": {"primary": agg},
    }
    resp = _post("/api/audit/rest/v1/search", body)

    total = ((resp.get("hits") or {}).get("total") or {}).get("value", 0)
    buckets: list[AuditBucket] = []
    for b in ((resp.get("aggregations") or {}).get("primary") or {}).get("buckets") or []:
        k0 = str(b.get("key_as_string") or b.get("key"))
        sub = b.get("sub")
        if sub:
            for sb in sub.get("buckets") or []:
                buckets.append(
                    AuditBucket(
                        key={group_by[0]: k0, group_by[1]: str(sb.get("key_as_string") or sb.get("key"))},
                        count=sb.get("doc_count", 0),
                    )
                )
        else:
            buckets.append(AuditBucket(key={group_by[0]: k0}, count=b.get("doc_count", 0)))

    return AuditAggregate(
        total=total,
        group_by=list(group_by),
        buckets=buckets,
        requested_window={"start": start_iso, "end": end_iso},
    )


# ---------------------------------------------------------------------------
# Typer CLI
# ---------------------------------------------------------------------------

app = typer.Typer(help="Immuta 2026.1.4 query toolkit.", add_completion=False)


def _emit(rows: list[BaseModel] | BaseModel) -> None:
    if isinstance(rows, list):
        typer.echo(json.dumps([r.model_dump() for r in rows], indent=2, default=str))
    else:
        typer.echo(rows.model_dump_json(indent=2))


def _run(fn, *args, **kwargs) -> None:
    try:
        _emit(fn(*args, **kwargs))
    except ImmutaAPIException as e:
        typer.echo(e.err.model_dump_json(indent=2), err=True)
        raise typer.Exit(code=1)
    except (ValidationError, ValueError) as e:
        err = ImmutaError(endpoint="<input>", message=str(e))
        typer.echo(err.model_dump_json(indent=2), err=True)
        raise typer.Exit(code=2)


@app.command("who-has-access")
def cli_who_has_access(datasource_id: int = typer.Option(..., "--datasource-id", "-d")) -> None:
    _run(who_has_access, datasource_id)


@app.command("datasources-without-policies")
def cli_datasources_without_policies() -> None:
    _run(datasources_without_policies)


@app.command("tag-usage")
def cli_tag_usage() -> None:
    _run(tag_usage)


@app.command("policy-attributes")
def cli_policy_attributes() -> None:
    _run(policy_attributes_with_user_counts)


@app.command("audit")
def cli_audit(
    span: SpanPreset = typer.Option("30d", "--span", help="all|ytd|1y|90d|30d|1d|custom"),
    start: datetime | None = typer.Option(None, "--start", help="ISO 8601, required with --span custom"),
    end: datetime | None = typer.Option(None, "--end", help="ISO 8601, optional with --span custom"),
    actor: str | None = typer.Option(None, "--actor", help="filter by actor name"),
    action: str | None = typer.Option(None, "--action", help="filter by UAM action, e.g. QUERY"),
    limit: int = typer.Option(100, "--limit", help=f"max events returned, 1..{MAX_AUDIT_EVENTS}"),
    include_raw: bool = typer.Option(False, "--include-raw", help="attach each event's full ES _source"),
) -> None:
    _run(audit_events, TimeSpan(preset=span, start=start, end=end),
         actor=actor, action=action, limit=limit, include_raw=include_raw)


@app.command("audit-aggregate")
def cli_audit_aggregate(
    group_by: list[str] = typer.Option(..., "--group-by", "-g",
                                       help=f"1-2 of {sorted(AUDIT_AGG_FIELDS)}"),
    span: SpanPreset = typer.Option("30d", "--span", help="all|ytd|1y|90d|30d|1d|custom"),
    start: datetime | None = typer.Option(None, "--start", help="ISO 8601, required with --span custom"),
    end: datetime | None = typer.Option(None, "--end", help="ISO 8601, optional with --span custom"),
    actor: str | None = typer.Option(None, "--actor", help="filter by actor name"),
    action: str | None = typer.Option(None, "--action", help="filter by UAM action, e.g. QUERY"),
    exclude_unknown_actors: bool = typer.Option(False, "--exclude-unknown-actors",
                                                help="drop events with actor 'Unknown'"),
    top_n: int = typer.Option(10, "--top-n", help="max buckets per terms dimension, 1..100"),
) -> None:
    _run(audit_aggregate, TimeSpan(preset=span, start=start, end=end), group_by,
         actor=actor, action=action, exclude_unknown_actors=exclude_unknown_actors, top_n=top_n)


@app.command("datasources")
def cli_datasources(
    search: str | None = typer.Option(None, "--search", "-s", help="name substring"),
    tag: str | None = typer.Option(None, "--tag", "-t", help="exact tag name"),
    domain_id: str | None = typer.Option(None, "--domain-id", help="domain uuid"),
) -> None:
    _run(list_datasources, search=search, tag=tag, domain_id=domain_id)


@app.command("policies")
def cli_policies() -> None:
    _run(list_policies)


@app.command("datasource-requirements")
def cli_datasource_requirements(datasource_id: int = typer.Option(..., "--datasource-id", "-d")) -> None:
    _run(datasource_requirements, datasource_id)


@app.command("domains")
def cli_domains() -> None:
    _run(list_domains)


@app.command("user-access")
def cli_user_access(
    user: str = typer.Option(..., "--user", "-u", help="email, userid, or name substring"),
    datasource_id: int | None = typer.Option(None, "--datasource-id", "-d",
                                             help="restrict the check to one datasource"),
) -> None:
    _run(user_access, user, datasource_id=datasource_id)


if __name__ == "__main__":
    app()
