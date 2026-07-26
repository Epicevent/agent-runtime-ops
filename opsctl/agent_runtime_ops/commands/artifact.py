from __future__ import annotations

import argparse

from ..domain.artifact_probe import (
    ArtifactProbeError,
    KWRAG_SCOPE,
    error_payload,
    probe_kwrag_product_artifact,
    serialize_probe_payload,
)
from ..domain.common import is_root


def cmd_artifact_probe(args: argparse.Namespace) -> int:
    revision = str(args.revision)
    try:
        if str(args.scope) != KWRAG_SCOPE:
            raise ArtifactProbeError("invalid_scope")
        if not is_root():
            raise ArtifactProbeError("root_required")
        payload = probe_kwrag_product_artifact(revision)
    except ArtifactProbeError as exc:
        print(
            serialize_probe_payload(error_payload(revision=revision, code=exc.code)),
            end="",
        )
        return 2
    except Exception:
        print(
            serialize_probe_payload(
                error_payload(revision=revision, code="internal_error")
            ),
            end="",
        )
        return 2
    print(serialize_probe_payload(payload), end="")
    return 0
