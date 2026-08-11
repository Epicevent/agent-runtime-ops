from ..domain.groupware_runtime_observation import GroupwareRuntimeObservationError, observe_groupware_runtime, unresolved_observation
from .contracts import SealedJob


class GroupwareRuntimeObservationHandler:
    operation_id = "nas.observe_groupware_runtime"
    operation_version = 1

    def run(self, job: SealedJob):
        from .execution import HandlerResult

        slot = str(job.manifest_copy()["parameters"]["slot"])
        try:
            observation = observe_groupware_runtime(slot)
        except GroupwareRuntimeObservationError as exc:
            observation = unresolved_observation(slot, exc.reason_code)
        except Exception:
            observation = unresolved_observation(slot, "runtime_observation_internal_error")
        healthy = observation.status == "healthy"
        return HandlerResult(
            raw_bytes=observation.raw_bytes(),
            public_status=observation.status,
            public_facts=observation.public_facts(),
            terminal_outcome="succeeded" if healthy else "failed",
            reason_code=observation.reason_code,
            exit_code=0 if healthy else 1,
        )
