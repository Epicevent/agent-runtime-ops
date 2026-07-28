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
from .broker import (
    BrokerEventSource,
    PublicProjectionBundle,
    PublicProjectionSink,
    PublicRootActionReader,
    SubmittedJob,
    TypedRootActionBroker,
)
from .inventory import INVENTORY_COVERAGE
from .admission import (
    CIRCUIT_BREAKER_REASON_CODE,
    TECHNICAL_FAILURE_REASON_CODES,
    LineageFailurePolicy,
    LineageSummary,
    SubmissionAdmission,
)
from .client import (
    DEFAULT_BROKER_SOCKET,
    RootActionBrokerClient,
    RootActionClientError,
    RootActionRequestHandle,
)
from .endpoint import RootActionBrokerEndpoint
from .listener import RootActionListenerError, RootActionUnixListener
from .observation import (
    EXECUTION_OBSERVATION_FACT_NAMES,
    EXECUTION_OBSERVATION_FACT_ORDER,
    FORBIDDEN_OBSERVATION_FACT_NAMES,
    MAX_PROVIDER_OBSERVATION_COUNT,
    OBSERVATION_CONTRACT_SCHEMA,
    ObservationValidationError,
    SanitizedExecutionObservation,
    execution_observation_contract_projection,
    validate_public_observation_facts,
)
from .protocol import (
    BROKER_REQUEST_SCHEMA,
    BROKER_RESPONSE_SCHEMA,
    BrokerProtocolError,
)
from .execution import (
    DEFAULT_EXECUTION_POLICIES,
    DEFAULT_OPERATION_HANDLERS,
    ExecutionPolicyRegistry,
    HandlerResult,
    KwragProductArtifactProbeHandler,
    OperationAvailability,
    OperationHandlerRegistry,
)
from .posix_store import PosixRootActionStore, PosixStoreSecurityError
from .public_projection import (
    AtomicPublicProjectionPublisher,
    PUBLIC_PROJECTION_SCHEMA,
    PublicProjectionArtifact,
    PublicProjectionError,
    validate_public_projection,
)
from .receipts import RawReceiptArtifact, seal_raw_receipt
from .submission import (
    BrokerPeerIdentity,
    RootActionSubmissionEndpoint,
    SUBMISSION_RESPONSE_SCHEMA,
    SubmissionPolicy,
    SubmissionRejected,
    decode_submission_frame,
    encode_submission_frame,
)
from .registry import DEFAULT_REGISTRY, REGISTRY_VERSION

__all__ = [
    "DEFAULT_REGISTRY",
    "BROKER_REQUEST_SCHEMA",
    "BROKER_RESPONSE_SCHEMA",
    "BrokerProtocolError",
    "CIRCUIT_BREAKER_REASON_CODE",
    "TECHNICAL_FAILURE_REASON_CODES",
    "LineageFailurePolicy",
    "LineageSummary",
    "SubmissionAdmission",
    "DEFAULT_BROKER_SOCKET",
    "RootActionBrokerClient",
    "RootActionClientError",
    "RootActionRequestHandle",
    "RootActionBrokerEndpoint",
    "RootActionListenerError",
    "RootActionUnixListener",
    "EXECUTION_OBSERVATION_FACT_NAMES",
    "EXECUTION_OBSERVATION_FACT_ORDER",
    "FORBIDDEN_OBSERVATION_FACT_NAMES",
    "MAX_PROVIDER_OBSERVATION_COUNT",
    "OBSERVATION_CONTRACT_SCHEMA",
    "ObservationValidationError",
    "SanitizedExecutionObservation",
    "execution_observation_contract_projection",
    "validate_public_observation_facts",
    "BrokerEventSource",
    "BrokerPeerIdentity",
    "RootActionSubmissionEndpoint",
    "SUBMISSION_RESPONSE_SCHEMA",
    "INVENTORY_COVERAGE",
    "DEFAULT_EXECUTION_POLICIES",
    "DEFAULT_OPERATION_HANDLERS",
    "ExecutionPolicyRegistry",
    "HandlerResult",
    "KwragProductArtifactProbeHandler",
    "OperationAvailability",
    "OperationHandlerRegistry",
    "MANIFEST_SCHEMA",
    "ManifestValidationError",
    "REGISTRY_VERSION",
    "PublicRootActionReader",
    "PublicProjectionBundle",
    "PublicProjectionSink",
    "AtomicPublicProjectionPublisher",
    "PUBLIC_PROJECTION_SCHEMA",
    "PublicProjectionArtifact",
    "PublicProjectionError",
    "RawReceiptArtifact",
    "PosixRootActionStore",
    "PosixStoreSecurityError",
    "SealedJob",
    "SubmittedJob",
    "SubmissionPolicy",
    "SubmissionRejected",
    "TypedRootActionBroker",
    "seal_typed_manifest",
    "seal_raw_receipt",
    "validate_public_projection",
    "decode_submission_frame",
    "encode_submission_frame",
]
