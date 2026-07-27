"""Decision-independent typed root-action contracts.

This package deliberately contains no authentication, dispatch, shell execution,
installer, service, or web integration.
"""

from .contracts import (
    MANIFEST_SCHEMA,
    ManifestValidationError,
    SealedJob,
    seal_typed_manifest,
)
from .inventory import INVENTORY_COVERAGE
from .registry import DEFAULT_REGISTRY, REGISTRY_VERSION

__all__ = [
    "DEFAULT_REGISTRY",
    "INVENTORY_COVERAGE",
    "MANIFEST_SCHEMA",
    "ManifestValidationError",
    "REGISTRY_VERSION",
    "SealedJob",
    "seal_typed_manifest",
]
