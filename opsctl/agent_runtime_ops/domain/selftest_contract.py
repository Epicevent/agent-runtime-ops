from __future__ import annotations

import json
from typing import Any

from .common import run_text


CONTRACT_OK_CHECK = "selftest_contract_ok"


def run_image_selftest_contract(container: str, contract: dict[str, Any]) -> list[tuple[bool, str, str | None]]:
    """Invoke the product-attested in-image selftest and map it to ops check tuples.

    ``contract`` is the verified ``selftest_contract`` carried by the wrapper image
    labels (see :func:`image_specs.image_spec_selftest_contract`). The product owns
    the actual customer-truth checks (model round-trip, executor/NAS round-trip, …);
    ops only invokes the attested command in the running container, parses the
    structured JSON result, and gates on the contract's ``required_checks``.

    This is family-agnostic: the command and required set come entirely from the
    verified contract, never hardcoded, so any family that ships a selftest contract
    is gated the same way.

    Expected stdout from the product (single JSON object)::

        {"ok": bool, "contract": "...",
         "checks": [{"name": "...", "ok": bool, "detail": "...", "severity": "required|advisory"}],
         "required_checks": ["..."]}
    """
    command = [str(arg) for arg in (contract.get("command") or [])]
    timeout_raw = contract.get("timeout_seconds")
    timeout = timeout_raw if isinstance(timeout_raw, int) and not isinstance(timeout_raw, bool) and timeout_raw > 0 else 120
    name = str(contract.get("name") or "selftest")

    def _fail(detail: str) -> list[tuple[bool, str, str | None]]:
        # On failure the output (and its required_checks) is unavailable; the checklist's
        # family required-set still backfills the expected selftest_* names as failures.
        return [(False, CONTRACT_OK_CHECK, detail[:200])]

    if not command:
        return _fail("selftest_contract has no command")

    proc = run_text(["docker", "exec", container, *command], timeout=timeout)
    if proc.returncode != 0:
        return _fail((proc.stderr or proc.stdout).strip() or f"returncode={proc.returncode}")
    try:
        payload = json.loads(proc.stdout)
    except Exception as exc:
        return _fail(f"parse_failed:{exc}")
    if not isinstance(payload, dict):
        return _fail("selftest output is not a JSON object")

    # The required set is declared by the product in its OWN output, so the contract
    # (command via image label + required_checks via output) is fully contained in the
    # image; opsctl trusts it because the image digest is root-approved.
    required = [str(c) for c in (payload.get("required_checks") or [])]
    checks: list[tuple[bool, str, str | None]] = []
    results: dict[str, bool] = {}
    raw_checks = payload.get("checks")
    if isinstance(raw_checks, list):
        for item in raw_checks:
            if not isinstance(item, dict):
                continue
            item_name = str(item.get("name") or "")
            if not item_name:
                continue
            ok = bool(item.get("ok"))
            detail = str(item.get("detail") or "")[:200]
            results[item_name] = ok
            checks.append((ok, item_name, detail))

    missing = [check for check in required if check not in results]
    for check in missing:
        checks.append((False, check, "missing_from_selftest"))
    contract_ok = not missing and all(results.get(check, False) for check in required)
    checks.append(
        (
            contract_ok,
            CONTRACT_OK_CHECK,
            f"name={name} required={len(required)} missing={len(missing)}",
        )
    )
    return checks
