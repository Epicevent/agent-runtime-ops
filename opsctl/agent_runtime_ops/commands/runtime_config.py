from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
import urllib.request

from ..domain.actions import append_action_log
from ..domain.common import is_root, state_root
from ..domain.config_contract import config_json_diff, run_config_validate_in_container
from ..domain.hermes_config import (
    current_model,
    hermes_config_path,
    model_endpoint_drift,
    read_hermes_config,
    read_version_notes,
    remove_version_note,
    runtime_provider_id,
    sanitize_config_secret_overrides,
    upsert_version_note,
    version_notes_path,
    write_hermes_config,
    write_version_notes,
)
from ..domain.openclaw_config import (
    build_model_ref,
    capture_openclaw_config_snapshot,
    current_openclaw_model,
    openclaw_config_path,
    openclaw_version_notes_path,
    read_openclaw_config,
    read_openclaw_version_notes,
    restore_openclaw_config_snapshot,
    run_openclaw_models_set,
    write_openclaw_version_notes,
)
from ..domain.runtime_truth import find_gateway_container
from ..domain.hermes_smoke import run_hermes_http_smoke
from ..domain.image_specs import image_spec_config_contract, image_spec_selftest_contract
from ..domain.selftest_contract import CONTRACT_OK_CHECK, run_image_selftest_contract
from ..profiles import load_profile
from ..runtime_secrets import parse_secret_env_text, primary_profile_secret_file
from ..state import load_runtime_target


_PROVIDER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,80}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,160}$")

# runtime config (model read/write) is supported for these product families.
_CONFIG_FAMILIES = frozenset({"hermes", "openclaw"})


def _detail_fields(detail: str | None) -> dict[str, str]:
    """Parse the flat, redaction-safe key=value receipt contract emitted by products."""
    return {
        key: value
        for key, value in re.findall(r"(?:^|\s)([A-Za-z][A-Za-z0-9_]*)=([^\s]+)", detail or "")
    }


def _actual_model_relation(configured_ref: str, actual_ref: str) -> str:
    """Classify only the conservative provider revision form as equivalent."""
    if not configured_ref or configured_ref == "missing" or not actual_ref or actual_ref == "missing":
        return "unknown"
    if actual_ref == configured_ref:
        return "exact"
    configured_provider, separator, configured_model = configured_ref.partition("/")
    actual_provider, actual_separator, actual_model = actual_ref.partition("/")
    if not separator or not actual_separator or configured_provider != actual_provider:
        return "different"
    suffix = actual_model.removeprefix(f"{configured_model}-")
    if actual_model.startswith(f"{configured_model}-") and re.fullmatch(r"\d{3,}", suffix):
        return "provider_revision"
    return "different"


def _print_model_attestation(
    *,
    slot: str,
    family: str,
    configured_ref: str,
    requested_ref: str,
    actual_ref: str,
    actual_relation: str,
    model_matches_configured: bool | None,
    response_observed: bool,
    receipt_present: bool,
    evidence_source: str,
    evidence_response_id: str,
    ok: bool,
    reason: str,
) -> int:
    matches = (
        "yes" if model_matches_configured is True
        else "no" if model_matches_configured is False
        else "unknown"
    )
    print(f"target={slot}")
    print(f"family={family}")
    print(f"configured_model_ref={configured_ref or 'missing'}")
    print(f"provider_requested_model_ref={requested_ref or 'missing'}")
    print(f"actual_model_ref={actual_ref or 'missing'}")
    print(f"response_observed={'yes' if response_observed else 'no'}")
    print(f"provider_receipt_present={'yes' if receipt_present else 'no'}")
    print(f"model_matches_configured={matches}")
    print(f"actual_model_relation={actual_relation or 'unknown'}")
    print(f"evidence_source={evidence_source or 'missing'}")
    print(f"evidence_response_id={evidence_response_id or 'missing'}")
    print("attestation_mode=isolated_completion")
    print("customer_session_mutated=no")
    print(f"reason={reason or 'none'}")
    print("secret_value_printed=no")
    print(f"model_attestation_status={'ok' if ok else 'fail'}")
    return 0 if ok else 1


def _gemini_model_catalog(api_key: str) -> list[str]:
    """Return every model currently advertised for generateContent by Gemini API."""
    models: set[str] = set()
    page_token = ""
    while True:
        query = {"pageSize": "1000"}
        if page_token:
            query["pageToken"] = page_token
        request = urllib.request.Request(
            "https://generativelanguage.googleapis.com/v1beta/models?" + urllib.parse.urlencode(query),
            headers={"x-goog-api-key": api_key, "Accept": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
        for row in payload.get("models") or []:
            if not isinstance(row, dict) or "generateContent" not in (row.get("supportedGenerationMethods") or []):
                continue
            name = str(row.get("name") or "")
            if name.startswith("models/"):
                name = name.removeprefix("models/")
            if _MODEL_RE.fullmatch(name):
                models.add(name)
        page_token = str(payload.get("nextPageToken") or "")
        if not page_token:
            break
    return sorted(models)


def _assert_name(value: str, pattern: re.Pattern[str], label: str) -> str:
    item = value.strip()
    if not item or not pattern.match(item):
        raise ValueError(f"invalid {label}: {value!r}")
    return item


def _load_config_target(slot: str, args: argparse.Namespace):
    desired = load_runtime_target(slot, state_root(args))
    if desired.family not in _CONFIG_FAMILIES:
        raise ValueError(
            f"runtime config is only supported for {sorted(_CONFIG_FAMILIES)} targets: family={desired.family}"
        )
    return desired


def _load_hermes_target(slot: str, args: argparse.Namespace):
    desired = load_runtime_target(slot, state_root(args))
    if desired.family != "hermes":
        raise ValueError(f"runtime config is only supported for hermes targets: family={desired.family}")
    return desired


def cmd_runtime_config_status(args: argparse.Namespace) -> int:
    if not is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl runtime config-status TARGET", file=sys.stderr)
        return 2
    try:
        desired = _load_config_target(args.slot, args)
        if desired.family == "openclaw":
            config_path = openclaw_config_path(desired.slot)
            config = read_openclaw_config(config_path)
            provider, model, ref, source = current_openclaw_model(config)
            provider_runtime = provider  # openclaw provider ids are used verbatim (e.g. "google")
        else:
            config_path = hermes_config_path(desired.slot)
            config = read_hermes_config(config_path)
            provider, model, source = current_model(config)
            provider_runtime = runtime_provider_id(provider) if provider else ""
            ref = f"{provider}/{model}" if provider and model else (model or "")
    except Exception as exc:
        print(f"target={args.slot}")
        print("runtime_config_status=fail")
        print(f"reason={exc}")
        return 1
    print(f"target={desired.slot}")
    print(f"family={desired.family}")
    print(f"config_file={config_path}")
    print(f"provider={provider_runtime or 'missing'}")
    print(f"provider_raw={provider or 'missing'}")
    print(f"provider_runtime={provider_runtime or 'missing'}")
    print(f"model={model or 'missing'}")
    print(f"model_ref={ref or 'missing'}")
    print(f"model_source={source}")
    if desired.family == "hermes":
        drift = model_endpoint_drift(config)
        verdict = str(drift["verdict"])
        routing_keys = drift["routing_keys"]
        print(f"model_base_url_host={drift['host'] or 'none'}")
        print(f"model_routing_keys={','.join(routing_keys) if routing_keys else 'none'}")
        print(f"model_endpoint_drift={'yes' if verdict == 'drift' else verdict if verdict == 'unknown' else 'no'}")
        if verdict != "clean":
            print(f"model_endpoint_drift_reason={drift['reason']}")
    print("secret_value_printed=no")
    print("runtime_config_status=ok")
    return 0


def cmd_runtime_model_catalog(args: argparse.Namespace) -> int:
    if not is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl runtime model-catalog TARGET", file=sys.stderr)
        return 2
    try:
        desired = _load_config_target(args.slot, args)
        profile = load_profile(desired.runtime_profile)
        secret_file = primary_profile_secret_file(profile, desired.slot)
        secrets = parse_secret_env_text(
            secret_file.path.read_text(encoding="utf-8", errors="replace"),
            source=str(secret_file.path),
        )
        api_key = str(secrets.get("GOOGLE_API_KEY") or secrets.get("GEMINI_API_KEY") or "")
        if not api_key:
            raise ValueError("Gemini API key is absent")
        models = _gemini_model_catalog(api_key)
        if not models:
            raise ValueError("Gemini API returned no generateContent models")
    except Exception as exc:
        print(f"target={args.slot}")
        print("model_catalog_status=fail")
        print(f"reason={exc}")
        print("secret_value_printed=no")
        return 1
    print(f"target={desired.slot}")
    print("provider=google")
    print(f"model_count={len(models)}")
    print(f"models_json={json.dumps(models, ensure_ascii=False, separators=(',', ':'))}")
    print("secret_value_printed=no")
    print("model_catalog_status=ok")
    return 0


def cmd_runtime_model_attest(args: argparse.Namespace) -> int:
    """Run one isolated completion and report the provider-observed model separately from config."""
    if not is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl runtime model-attest TARGET", file=sys.stderr)
        return 2
    target = str(args.slot)
    try:
        desired = _load_config_target(target, args)
        profile = load_profile(desired.runtime_profile)
        container, method = find_gateway_container(desired.route, profile)
        if not container:
            raise ValueError(f"no running gateway container for {desired.slot}: {method}")

        if desired.family == "hermes":
            config = read_hermes_config(hermes_config_path(desired.slot))
            provider_raw, configured_model, _source = current_model(config)
            provider = runtime_provider_id(provider_raw) if provider_raw else ""
            configured_ref = (
                f"{provider or provider_raw}/{configured_model}"
                if configured_model
                else "missing"
            )
            checks = run_hermes_http_smoke(container, chat_smoke=True, model_attest=True)
            receipt_check = next(
                (item for item in checks if item[1] == "hermes_smoke_model_attested"),
                None,
            )
            if receipt_check is None:
                return _print_model_attestation(
                    slot=desired.slot,
                    family=desired.family,
                    configured_ref=configured_ref,
                    requested_ref="missing",
                    actual_ref="missing",
                    actual_relation="unknown",
                    model_matches_configured=None,
                    response_observed=False,
                    receipt_present=False,
                    evidence_source="missing",
                    evidence_response_id="missing",
                    ok=False,
                    reason="hermes provider receipt check missing",
                )
            check_ok, _name, detail = receipt_check
            fields = _detail_fields(detail)
            versions = [
                item for item in fields.get("receipt_model_versions", "").split(",")
                if item and item != "missing"
            ]
            requested_models = [
                item for item in fields.get("evidence_requested_models", "").split(",")
                if item and item != "missing"
            ]
            actual_model = versions[0] if len(versions) == 1 else "missing"
            actual_ref = f"{provider}/{actual_model}" if provider and actual_model != "missing" else "missing"
            requested_model = requested_models[0] if len(requested_models) == 1 else "missing"
            requested_ref = (
                f"{provider}/{requested_model}"
                if provider and requested_model != "missing" else "missing"
            )
            response_observed = int(fields.get("done_events", "0") or "0") > 0
            receipt_present = int(fields.get("complete_provider_receipts", "0") or "0") > 0
            response_ids = [
                item for item in fields.get("receipt_response_ids", "").split(",")
                if item and item != "missing"
            ]
            actual_relation = fields.get(
                "actual_model_relation", _actual_model_relation(configured_ref, actual_ref)
            )
            matches = (
                requested_ref == configured_ref
                and actual_relation in {"exact", "provider_revision"}
            )
            ok = bool(check_ok and response_observed and receipt_present and matches)
            reason = (
                "provider receipt validates the configured request and actual response model"
                if ok
                else detail or "hermes provider receipt attestation failed"
            )
            return _print_model_attestation(
                slot=desired.slot,
                family=desired.family,
                configured_ref=configured_ref,
                requested_ref=requested_ref,
                actual_ref=actual_ref,
                actual_relation=actual_relation,
                model_matches_configured=matches if receipt_present else None,
                response_observed=response_observed,
                receipt_present=receipt_present,
                evidence_source=fields.get("evidence_source", "missing"),
                evidence_response_id=response_ids[0] if len(response_ids) == 1 else "missing",
                ok=ok,
                reason=reason,
            )

        config = read_openclaw_config(openclaw_config_path(desired.slot))
        _provider, _model, configured_ref, _source = current_openclaw_model(config)
        selftest_contract = image_spec_selftest_contract(desired.image_spec)
        if not selftest_contract:
            raise ValueError("running OpenClaw image is missing selftest contract")
        checks = run_image_selftest_contract(container, selftest_contract)
        roundtrip = next(
            (item for item in checks if item[1] == "selftest_model_roundtrip_ok"),
            None,
        )
        if roundtrip is None:
            return _print_model_attestation(
                slot=desired.slot,
                family=desired.family,
                configured_ref=configured_ref,
                requested_ref="missing",
                actual_ref="missing",
                actual_relation="unknown",
                model_matches_configured=None,
                response_observed=False,
                receipt_present=False,
                evidence_source="product_selftest_result_missing",
                evidence_response_id="missing",
                ok=False,
                reason="OpenClaw product did not return the model roundtrip check",
            )
        check_ok, _name, detail = roundtrip
        fields = _detail_fields(detail)
        requested_ref = fields.get("requested", "missing")
        response_model = fields.get("response", "missing")
        receipt_status = fields.get("receipt", "missing")
        response_observed = bool(check_ok or receipt_status in {"matched", "mismatch", "missing"})
        actual_model = response_model.removeprefix("models/")
        configured_provider = configured_ref.partition("/")[0]
        actual_ref = (
            f"{configured_provider}/{actual_model}"
            if configured_provider and actual_model not in {"", "missing", "unavailable"}
            else "missing"
        )
        evidence_source = (
            "openclaw_google_response.modelVersion"
            if actual_ref != "missing" and receipt_status in {"matched", "mismatch"}
            else "missing"
        )
        receipt_present = (
            requested_ref != "missing"
            and actual_ref != "missing"
            and evidence_source != "missing"
        )
        actual_relation = _actual_model_relation(configured_ref, actual_ref)
        matches = (
            requested_ref == configured_ref
            and actual_relation in {"exact", "provider_revision"}
            and receipt_status == "matched"
        )
        ok = bool(check_ok and response_observed and receipt_present and matches)
        reason = (
            "provider receipt validates the configured request and actual response model"
            if ok
            else detail or "OpenClaw provider receipt attestation failed"
        )
        return _print_model_attestation(
            slot=desired.slot,
            family=desired.family,
            configured_ref=configured_ref,
            requested_ref=requested_ref,
            actual_ref=actual_ref,
            actual_relation=actual_relation,
            model_matches_configured=matches if receipt_present else None,
            response_observed=response_observed,
            receipt_present=receipt_present,
            evidence_source=evidence_source,
            evidence_response_id="not_exposed_by_openclaw_selftest",
            ok=ok,
            reason=reason,
        )
    except Exception as exc:
        return _print_model_attestation(
            slot=target,
            family="unknown",
            configured_ref="missing",
            requested_ref="missing",
            actual_ref="missing",
            actual_relation="unknown",
            model_matches_configured=None,
            response_observed=False,
            receipt_present=False,
            evidence_source="missing",
            evidence_response_id="missing",
            ok=False,
            reason=str(exc),
        )


def _attest_openclaw_model_change(desired, container: str) -> tuple[bool, str]:
    """Use only product-attested contracts to prove config and customer model truth."""
    config_contract = image_spec_config_contract(desired.image_spec)
    selftest_contract = image_spec_selftest_contract(desired.image_spec)
    if not config_contract or not selftest_contract:
        return False, "running image is missing config or selftest contract"
    valid, config_detail = run_config_validate_in_container(container, config_contract)
    if not valid:
        return False, f"config={config_detail}"
    checks = run_image_selftest_contract(container, selftest_contract)
    contract = next((item for item in checks if item[1] == CONTRACT_OK_CHECK), None)
    if contract is None or not contract[0]:
        failed = ",".join(
            f"{name}:{detail or 'failed'}" for ok, name, detail in checks if not ok
        )
        return False, f"selftest={failed or 'contract result missing'}"[:500]
    return True, f"config={config_detail}; selftest={contract[2] or 'ok'}"


def _set_model_openclaw(desired, provider_raw: str, model: str) -> tuple[str, list[str], str, str, str, str]:
    """Change the slot's default model with the product's OWN ``models set`` command, run inside
    the live gateway container (``docker exec``). This preserves the canonical
    ``agents.defaults.models`` entry, provider-plugin repair, and load-time validation that a raw
    JSON write would skip. A before/after diff of the on-disk config is returned so the operator
    SEES exactly what the product changed. Provider is verbatim (``google/gemini-3.5-flash``).
    Returns (config_path, diff_lines, previous_ref, new_ref, source, container).
    """
    profile = load_profile(desired.runtime_profile)
    container, method = find_gateway_container(desired.route, profile)
    if not container:
        raise ValueError(f"no running gateway container for {desired.slot}: {method}")
    config_path = openclaw_config_path(desired.slot)
    before = read_openclaw_config(config_path)
    snapshot_before_attestation = capture_openclaw_config_snapshot(config_path)
    _prev_provider, _prev_model, previous_ref, source = current_openclaw_model(before)
    new_ref = build_model_ref(provider_raw, model)
    before_ok, before_detail = _attest_openclaw_model_change(desired, container)
    if not before_ok:
        raise ValueError(
            f"refusing model change because current state is not verified-good: {before_detail}"
        )
    verified_snapshot = capture_openclaw_config_snapshot(config_path)
    if verified_snapshot != snapshot_before_attestation:
        raise ValueError("config changed while establishing the verified rollback baseline")
    ok, detail = run_openclaw_models_set(container, new_ref)
    if not ok:
        rollback = "not_needed"
        try:
            partial = read_openclaw_config(config_path)
            if partial != before:
                restore_openclaw_config_snapshot(config_path, verified_snapshot)
                rollback = "restored"
            restored_ok, restored_detail = _attest_openclaw_model_change(desired, container)
            if not restored_ok:
                raise ValueError(f"restored state failed attestation: {restored_detail}")
            rollback += "_verified"
        except Exception as rollback_exc:
            raise ValueError(
                f"product models set failed (container={container}): {detail}; "
                f"rollback failed: {rollback_exc}"
            ) from rollback_exc
        raise ValueError(
            f"product models set failed (container={container}): {detail}; rollback={rollback}"
        )
    after = read_openclaw_config(config_path)
    after_ok, after_detail = _attest_openclaw_model_change(desired, container)
    if not after_ok:
        try:
            restore_openclaw_config_snapshot(config_path, verified_snapshot)
            restored_ok, restored_detail = _attest_openclaw_model_change(desired, container)
            if not restored_ok:
                raise ValueError(f"restored state failed attestation: {restored_detail}")
        except Exception as rollback_exc:
            raise ValueError(
                f"candidate attestation failed: {after_detail}; rollback failed: {rollback_exc}"
            ) from rollback_exc
        raise ValueError(
            f"candidate attestation failed: {after_detail}; rollback=restored_verified"
        )
    diff_lines = config_json_diff(before, after)
    return str(config_path), diff_lines, previous_ref, new_ref, source, f"{container}:{method}"


def cmd_runtime_set_model(args: argparse.Namespace) -> int:
    if not is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl runtime set-model TARGET", file=sys.stderr)
        return 2
    target = str(args.slot)
    diff_lines: list[str] = []
    container = ""
    try:
        provider_raw = _assert_name(str(args.provider), _PROVIDER_RE, "provider")
        model = _assert_name(str(args.model), _MODEL_RE, "model")
        desired = _load_config_target(target, args)
        if desired.family == "openclaw":
            # openclaw: provider verbatim, ref = provider/model, applied via the product's own
            # `models set` in the live container (diff shows exactly what the product changed).
            provider = provider_raw
            provider_runtime = provider_raw
            config_path, diff_lines, previous_ref, new_ref, previous_source, container = _set_model_openclaw(
                desired, provider_raw, model
            )
        else:
            provider = runtime_provider_id(provider_raw)
            provider_runtime = provider
            config_path = hermes_config_path(desired.slot)
            config = read_hermes_config(config_path)
            previous_provider, previous_model, previous_source = current_model(config)
            previous_provider_runtime = runtime_provider_id(previous_provider) if previous_provider else ""
            previous_ref = f"{previous_provider_runtime or previous_provider or 'missing'}/{previous_model or 'missing'}"
            new_ref = f"{provider}/{model}"
            config["provider"] = provider
            current_model_value = config.get("model")
            if isinstance(current_model_value, dict):
                next_model = dict(current_model_value)
                next_model["default"] = model
                next_model["provider"] = provider
                # Drop provider-specific routing left over from the previous
                # provider. A stale base_url/api_key/api_mode (e.g. an OpenRouter
                # base_url carried onto a gemini/google provider) misroutes every
                # request to the wrong endpoint — the exact config drift that made
                # a dev slot's gemini traffic 401 against keyless OpenRouter.
                # set-model writes the canonical provider/model; a custom endpoint
                # must be configured deliberately, not silently inherited.
                for _stale_key in ("base_url", "api_key", "api_mode"):
                    next_model.pop(_stale_key, None)
                config["model"] = next_model
            else:
                config["model"] = model
            write_hermes_config(desired.slot, config_path, config)
    except Exception as exc:
        print(f"target={target}")
        print("runtime_config_status=fail")
        print(f"reason={exc}")
        try:
            append_action_log(state_root(args), "runtime_set_model", target, target, "fail", str(exc))
        except Exception:
            pass
        return 1

    print(f"target={desired.slot}")
    print(f"family={desired.family}")
    print(f"config_file={config_path}")
    print(f"exec_container={container or 'n/a'}")
    print(f"previous_model_ref={previous_ref or 'missing'}")
    print(f"previous_model_source={previous_source}")
    print(f"provider_raw={provider_raw}")
    print(f"provider={provider}")
    print(f"provider_runtime={provider_runtime}")
    print(f"model={model}")
    print(f"model_ref={new_ref}")
    for line in diff_lines:
        print(f"config_diff {line}")
    print(f"config_diff_lines={len(diff_lines)}")
    print("secret_value_printed=no")
    print("runtime_config_status=updated")
    append_action_log(
        state_root(args),
        "runtime_set_model",
        desired.slot,
        desired.slot,
        "ok",
        f"{previous_ref or 'missing'} -> {new_ref}",
    )
    return 0


def cmd_runtime_version_note(args: argparse.Namespace) -> int:
    """Operator-authored patch notes for the in-app version modal — one pen
    for BOTH families (owner rule: the mechanisms must not diverge).

    hermes:   <slot home>/.hermes/version-notes.json, entries
              [{version, date?, notes: [...]}] — one bullet per --note.
    openclaw: <slot home>/.openclaw/version-notes.json, {version: "note"}
              (the product's version-notes-store contract, single string —
              repeated --note values are joined with ", "; --date is baked
              in the OC timeline and not accepted here).

    Both are live overlays on mounted state: the product re-reads the file,
    so edits show on next modal open — no rebuild, no restart.
    """
    if not is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl runtime version-note TARGET", file=sys.stderr)
        return 2
    target = str(args.slot)
    try:
        desired = _load_config_target(target, args)
        version = str(getattr(args, "version", "") or "")
        notes = [str(n) for n in (getattr(args, "note", None) or [])]
        date = str(getattr(args, "date", "") or "")
        clear = bool(getattr(args, "clear", False))
        customer_release = getattr(args, "customer_release", None)
        if clear and not version:
            raise ValueError("--clear requires --version")
        if notes and not version:
            raise ValueError("--note requires --version")
        if customer_release is not None and not version:
            raise ValueError("--publish/--unpublish requires --version")
        action = "show"

        if desired.family == "openclaw":
            if date:
                raise ValueError("openclaw notes carry no date (it comes from the baked build timeline)")
            path = openclaw_version_notes_path(desired.slot)
            oc_notes = read_openclaw_version_notes(path)
            if version and clear:
                removed = version in oc_notes
                oc_notes.pop(version, None)
                write_openclaw_version_notes(desired.slot, path, oc_notes)
                action = "cleared" if removed else "clear_noop"
            elif version:
                joined = ", ".join(n.strip() for n in notes if n.strip())
                # reuse the hermes validator for version format + length limits
                upsert_version_note([], version, [joined] if joined else [])
                oc_notes[version] = joined
                write_openclaw_version_notes(desired.slot, path, oc_notes)
                action = "written"
            print(f"target={desired.slot}")
            print(f"family={desired.family}")
            print(f"notes_file={path}")
            print(f"action={action}")
            print(f"entry_count={len(oc_notes)}")
            for entry_version in sorted(oc_notes, reverse=True):
                print(f"entry {entry_version}")
                print(f"  - {oc_notes[entry_version]}")
        else:
            path = version_notes_path(desired.slot)
            entries = read_version_notes(path)
            if version and clear:
                entries, removed = remove_version_note(entries, version)
                write_version_notes(desired.slot, path, entries)
                action = "cleared" if removed else "clear_noop"
            elif version:
                entries = upsert_version_note(
                    entries, version, notes, date=date, customer_release=customer_release
                )
                write_version_notes(desired.slot, path, entries)
                action = "written"
            print(f"target={desired.slot}")
            print(f"family={desired.family}")
            print(f"notes_file={path}")
            print(f"action={action}")
            print(f"entry_count={len(entries)}")
            for entry in entries:
                entry_notes = entry.get("notes") or []
                published = "yes" if entry.get("customerRelease") else "no"
                print(
                    f"entry {entry.get('version', '?')} date={entry.get('date', '-')} "
                    f"customer_visible={published} "
                    f"notes={len(entry_notes) if isinstance(entry_notes, list) else '?'}"
                )
                if isinstance(entry_notes, list):
                    for note in entry_notes:
                        print(f"  - {note}")
    except Exception as exc:
        print(f"target={target}")
        print("runtime_version_note_status=fail")
        print(f"reason={exc}")
        try:
            append_action_log(state_root(args), "runtime_version_note", target, target, "fail", str(exc))
        except Exception:
            pass
        return 1

    print("runtime_version_note_status=ok")
    if action in {"written", "cleared"}:
        append_action_log(
            state_root(args),
            "runtime_version_note",
            desired.slot,
            desired.slot,
            "ok",
            f"{action} {version}",
        )
    return 0


def cmd_runtime_config_sanitize(args: argparse.Namespace) -> int:
    if not is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl runtime config-sanitize TARGET", file=sys.stderr)
        return 2
    target = str(args.slot)
    try:
        desired = _load_hermes_target(target, args)
        config_path = hermes_config_path(desired.slot)
        config = read_hermes_config(config_path)
        sanitized, removed = sanitize_config_secret_overrides(config)
        apply_changes = bool(getattr(args, "apply", False))
        if apply_changes and removed:
            write_hermes_config(desired.slot, config_path, sanitized)
    except Exception as exc:
        print(f"target={target}")
        print("runtime_config_sanitize_status=fail")
        print(f"reason={exc}")
        try:
            append_action_log(state_root(args), "runtime_config_sanitize", target, target, "fail", str(exc))
        except Exception:
            pass
        return 1

    mode = "apply" if bool(getattr(args, "apply", False)) else "dry_run"
    print(f"target={desired.slot}")
    print(f"config_file={config_path}")
    print(f"runtime_config_sanitize_mode={mode}")
    for path, value_present in removed:
        print(
            f"remove_path={'.'.join(path)} "
            f"value_present={'yes' if value_present else 'no'} "
            "secret_value_printed=no"
        )
    print(f"remove_count={len(removed)}")
    print("secret_value_printed=no")
    print(f"runtime_config_sanitize_status={'updated' if mode == 'apply' else 'dry_run'}")
    if mode == "apply":
        append_action_log(
            state_root(args),
            "runtime_config_sanitize",
            desired.slot,
            desired.slot,
            "ok",
            f"removed={len(removed)} secret_value_printed=no",
        )
    return 0
