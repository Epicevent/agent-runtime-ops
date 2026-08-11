from __future__ import annotations

import unittest

from agent_runtime_ops.root_actions import (
    DEFAULT_EXECUTION_POLICIES,
    DEFAULT_OPERATION_HANDLERS,
    DEFAULT_REGISTRY,
    OperationHandlerRegistry,
)


class RootActionExecutionRegistryTests(unittest.TestCase):
    def test_only_fixed_groupware_observer_is_enabled(self) -> None:
        self.assertEqual(
            DEFAULT_EXECUTION_POLICIES.enabled_operation_ids,
            ("nas.observe_groupware_runtime",),
        )
        self.assertEqual(
            set(DEFAULT_EXECUTION_POLICIES.disabled_operation_ids),
            {
                "audit.verify",
                "projection.staging_selftest",
                "agent_loop.campaign_run",
            },
        )
        self.assertTrue(
            all(
                "kwrag" not in operation_id
                for operation_id in DEFAULT_REGISTRY.operation_ids
            )
        )
        self.assertEqual(
            DEFAULT_OPERATION_HANDLERS.handler(
                "nas.observe_groupware_runtime"
            ).operation_version,
            1,
        )
        for operation_id in DEFAULT_EXECUTION_POLICIES.disabled_operation_ids:
            with self.assertRaises(KeyError):
                DEFAULT_OPERATION_HANDLERS.handler(operation_id)

    def test_disabled_generic_operation_cannot_gain_a_handler(self) -> None:
        class ForbiddenAuditHandler:
            operation_id = "audit.verify"
            operation_version = 1

            def run(self, job):  # pragma: no cover - construction must fail
                raise AssertionError

        with self.assertRaisesRegex(ValueError, "disabled operation"):
            OperationHandlerRegistry((ForbiddenAuditHandler(),))


if __name__ == "__main__":
    unittest.main()
