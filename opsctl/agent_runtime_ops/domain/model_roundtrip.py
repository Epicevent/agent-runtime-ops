from __future__ import annotations

from .common import run_text

# The deploy gate must prove the customer's configured model actually ANSWERS a
# prompt — the one thing an oc1-style green-but-down incident hides (a 429 /
# expired / blocked key passes every port/health/config check). The product's
# own oneshot (`hermes -z`) is the exact customer transport with no auth
# plumbing, so opsctl invokes it rather than reimplementing a probe.
#
# One completion per call, so this belongs on the deploy gate (rollout verify),
# never routine health polls. hermes-only: openclaw attests its round-trip in
# its own selftest contract.
MODEL_ROUNDTRIP_PROMPT = "Reply with exactly: OK"
_EMPTY_SENTINEL = "(empty)"


def evaluate_roundtrip_reply(stdout: str) -> tuple[bool, str]:
    """Judge a `hermes -z` round-trip from its stdout.

    `run_oneshot` returns exit 0 even when the model produced nothing (it writes
    nothing and still returns 0 — oneshot.py), so the exit code is not proof.
    The proof is the OUTPUT: a non-empty reply that is not the ``(empty)``
    sentinel the agent emits when the model returns no content. The prompt/reply
    are trivial, so a short preview is safe to surface.
    """
    reply = (stdout or "").strip()
    if not reply:
        return False, "no_reply model_produced_no_output"
    if reply == _EMPTY_SENTINEL:
        return False, "empty_sentinel model_returned_no_content"
    ok_token = "OK" in reply.upper()
    preview = reply.replace("\n", " ")[:80]
    return True, f"reply_present ok_token={str(ok_token).lower()} preview={preview!r}"


def run_model_roundtrip_probe(container: str, *, timeout: int = 90) -> tuple[bool, str]:
    """Run one real completion inside the container and judge the reply."""
    proc = run_text(
        ["docker", "exec", container, "hermes", "-z", MODEL_ROUNDTRIP_PROMPT],
        timeout=timeout,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip() or f"returncode={proc.returncode}"
        return False, f"exec_failed {detail[:160]}"
    return evaluate_roundtrip_reply(proc.stdout)
