"""Associate Lab B — minimal PEP stub (Python).

Teaches: build OPA input, optional PIP enrich, call PDP, fail-closed on error.
Not production code. Vendor-neutral: talks to stock OPA REST API.
Writ is not on this path. Verdict is not used.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Optional


@dataclass
class Decision:
    allow: bool
    reason: str


OwnerLookup = Callable[[str], Optional[str]]


def enrich_owner(resource: dict[str, Any], lookup: OwnerLookup) -> dict[str, Any]:
    """PIP-in-PEP pattern: attach resource.owner if missing."""
    out = dict(resource)
    if "owner" not in out and "id" in out:
        owner = lookup(str(out["id"]))
        if owner is not None:
            out = {**out, "owner": owner}
    return out


def ask_pdp(
    opa_url: str,
    path: str,
    input_doc: dict[str, Any],
    *,
    timeout_s: float = 0.5,
    fail_closed: bool = True,
) -> Decision:
    """POST /v1/data/<path> with {\"input\": ...}. Default fail-closed."""
    url = opa_url.rstrip("/") + "/v1/data/" + path.lstrip("/")
    body = json.dumps({"input": input_doc}).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            if resp.status != 200:
                raise ValueError(f"http_status_{resp.status}")
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # any transport/HTTP/JSON/timeout error
        if fail_closed:
            return Decision(allow=False, reason=f"pdp_error_fail_closed:{type(exc).__name__}")
        return Decision(allow=True, reason=f"pdp_error_fail_open:{type(exc).__name__}")
    # Strict decoder: only a JSON boolean is a decision. `true` is the ONLY allow.
    result = payload.get("result") if isinstance(payload, dict) else None
    if isinstance(result, bool):
        return Decision(allow=result is True, reason="pdp")
    # Missing, null, string, number, list, object (even {"allow": "false"}) -> unexpected shape
    if fail_closed:
        return Decision(allow=False, reason="pdp_bad_shape_fail_closed")
    return Decision(allow=True, reason="pdp_bad_shape_fail_open")

def authorize(
    *,
    subject: dict[str, Any],
    action: str,
    resource: dict[str, Any],
    opa_url: str = "http://127.0.0.1:8181",
    decision_path: str = "university/foundations/authz/allow",
    owner_lookup: Optional[OwnerLookup] = None,
    fail_closed: bool = True,
) -> Decision:
    res = enrich_owner(resource, owner_lookup) if owner_lookup else resource
    input_doc = {"subject": subject, "action": action, "resource": res}
    return ask_pdp(opa_url, decision_path, input_doc, fail_closed=fail_closed)


if __name__ == "__main__":
    # Demo without a live OPA: simulate unreachable PDP
    closed = ask_pdp(
        "http://127.0.0.1:1", "university/foundations/authz/allow", {"action": "read"}
    )
    assert closed.allow is False and "fail_closed" in closed.reason
    opened = ask_pdp(
        "http://127.0.0.1:1",
        "university/foundations/authz/allow",
        {"action": "read"},
        fail_closed=False,
    )
    assert opened.allow is True and "fail_open" in opened.reason
    print("fail-closed demo OK:", closed)
    print("fail-open contrast OK:", opened)
