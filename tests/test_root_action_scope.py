from __future__ import annotations

import ast
from pathlib import Path
import unittest

from agent_runtime_ops.root_actions.endpoint import RootActionBrokerEndpoint
from agent_runtime_ops.root_actions.local_fixture import LocalRootActionFixture
from agent_runtime_ops.root_actions.storage import (
    ROOT_OWNED_STORAGE_CONTRACTS,
    RootActionStore,
)


class RootActionTypedCoreScopeTests(unittest.TestCase):
    def test_storage_contracts_name_each_root_owned_area_and_read_boundary(
        self,
    ) -> None:
        by_area = {contract.area: contract for contract in ROOT_OWNED_STORAGE_CONTRACTS}
        self.assertEqual(
            by_area.keys(), {"spool", "ledger", "raw_receipt", "quarantine"}
        )
        self.assertTrue(all(item.required_owner == "root" for item in by_area.values()))
        self.assertEqual(by_area["raw_receipt"].public_read_surface, "none")
        self.assertEqual(
            by_area["quarantine"].public_read_surface, "quarantine-notice-only"
        )
        self.assertIsInstance(LocalRootActionFixture(), RootActionStore)

    def test_core_imports_no_execution_auth_web_or_service_runtime(self) -> None:
        root = Path("opsctl/agent_runtime_ops/root_actions")
        forbidden_modules = {
            "subprocess",
            "http",
            "pam",
            "fastapi",
            "starlette",
            "systemd",
            "ctypes",
        }
        imported: set[str] = set()
        for path in root.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name.split(".", 1)[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module.split(".", 1)[0])
        self.assertEqual(imported & forbidden_modules, set())
        socket_importers = {
            path.name
            for path in root.glob("*.py")
            if "socket" in path.read_text(encoding="utf-8")
        }
        self.assertEqual(socket_importers, {"client.py", "listener.py", "service.py"})
        endpoint_source = (root / "endpoint.py").read_text(encoding="utf-8")
        self.assertNotIn("dispatch", endpoint_source.lower())
        self.assertNotIn("handler.run", endpoint_source)
        self.assertEqual(
            RootActionBrokerEndpoint.ALLOWED_METHODS,
            frozenset({"submit", "retrieve"}),
        )

        pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
        self.assertNotIn("rootact =", pyproject)
        self.assertNotIn("root-action =", pyproject)


if __name__ == "__main__":
    unittest.main()
