from __future__ import annotations

import unittest
import uuid

from agent_runtime_ops.compose_contract import validate_compose_contract
from agent_runtime_ops.image_components import image_component_name, image_repo
from agent_runtime_ops.profiles import load_profile
from agent_runtime_ops.renderer import render_compose
from agent_runtime_ops.routing import RuntimeBinding
from agent_runtime_ops.state import DesiredSlot


def test_route(slot: str, family: str = "openclaw", runtime_class: str = "customer") -> RuntimeBinding:
    ports = {
        "oc1": (28789, 28790),
        "oc2": (28889, 28890),
        "dev-hermess": (30889, 30890),
        "dev-openclaw": (30789, 30790),
    }
    gateway_port, bridge_port = ports.get(slot, (29989, 29990))
    return RuntimeBinding(
        instance_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, slot)),
        linux_account=slot,
        public_host=f"{slot}.ji-tech.co.kr",
        family=family,
        runtime_class=runtime_class,
        gateway_port=gateway_port,
        bridge_port=bridge_port,
    )


def desired_slot(
    slot: str,
    family: str,
    slot_class: str,
    runtime_profile: str,
    product_repo: str | None = None,
) -> DesiredSlot:
    digest = "sha256:" + "a" * 64
    product_repo = product_repo or f"{family}-jitech"
    return DesiredSlot(
        slot=slot,
        lane=f"{family}-{slot_class}-stable",
        lane_data={"family": family, "slot_class": slot_class},
        release_name=f"{family}-release",
        release_data={
            "family": family,
            "wrapper_image": f"ghcr.io/epicevent/agent-runtime-{family}@{digest}",
            "product_image": f"ghcr.io/epicevent/{product_repo}@{digest}",
            "digest": digest,
        },
        runtime_profile=runtime_profile,
        route=test_route(slot, family, slot_class),
    )


def contract_results(profile_name: str, desired: DesiredSlot) -> dict[str, bool]:
    profile = load_profile(profile_name)
    rendered = render_compose(profile, desired)
    return {item.name: item.ok for item in validate_compose_contract(profile, desired, rendered.text)}


class RuntimeContractTests(unittest.TestCase):
    def test_image_component_recipe_identity(self) -> None:
        digest = "sha256:" + "b" * 64
        self.assertEqual(image_repo(f"ghcr.io/epicevent/hermes-workspace@{digest}"), "ghcr.io/epicevent/hermes-workspace")
        self.assertEqual(image_repo("ghcr.io/epicevent/hermes-workspace:main"), "ghcr.io/epicevent/hermes-workspace")
        self.assertEqual(image_component_name(f"ghcr.io/epicevent/hermes-workspace@{digest}"), "hermes-workspace")
        self.assertEqual(image_component_name("ghcr.io/epicevent/openclaw-jitech@sha256:" + "c" * 64), "openclaw-control")

    def test_compose_uses_route_registry_ports(self) -> None:
        desired = desired_slot("oc1", "openclaw", "customer", "openclaw-customer")
        rendered = render_compose(load_profile("openclaw-customer"), desired).text
        self.assertIn("127.0.0.1:28789:18789", rendered)
        self.assertIn("127.0.0.1:28790:18790", rendered)

    def test_openclaw_customer_contract(self) -> None:
        desired = desired_slot("oc1", "openclaw", "customer", "openclaw-customer")
        results = contract_results("openclaw-customer", desired)
        self.assertTrue(results["compose_runtime_user_model"])
        self.assertTrue(results["compose_nas_root_bind_present"])
        self.assertTrue(results["compose_nas_root_readonly"])
        self.assertTrue(results["compose_nas_root_propagation"])
        self.assertTrue(results["compose_customer_surface_port"])
        self.assertTrue(results["compose_customer_source_mount_absent"])

    def test_hermes_customer_contract(self) -> None:
        desired = desired_slot("oc2", "hermes", "customer", "hermes-customer", product_repo="openclaw-nas-agent")
        results = contract_results("hermes-customer", desired)
        self.assertTrue(results["compose_runtime_user_model"])
        self.assertTrue(results["compose_required_command"])
        self.assertTrue(results["compose_required_working_dir"])
        self.assertTrue(results["compose_nas_root_bind_present"])
        self.assertTrue(results["compose_nas_root_readonly"])
        self.assertTrue(results["compose_nas_root_propagation"])
        self.assertTrue(results["compose_customer_surface_port"])
        self.assertTrue(results["compose_customer_source_mount_absent"])

    def test_hermes_workspace_customer_contract(self) -> None:
        desired = desired_slot(
            "oc2",
            "hermes",
            "customer",
            "hermes-workspace-customer",
            product_repo="hermes-workspace",
        )
        results = contract_results("hermes-workspace-customer", desired)
        self.assertTrue(results["compose_runtime_user_model"])
        self.assertTrue(results["compose_uses_image_default_command"])
        self.assertTrue(results["compose_required_working_dir"])
        self.assertTrue(results["compose_nas_root_bind_present"])
        self.assertTrue(results["compose_customer_source_mount_absent"])

    def test_hermes_dev_contract(self) -> None:
        desired = desired_slot("dev-hermess", "hermes", "dev", "hermes-dev", product_repo="openclaw-nas-agent")
        results = contract_results("hermes-dev", desired)
        self.assertTrue(results["compose_runtime_user_model"])
        self.assertTrue(results["compose_required_command"])
        self.assertTrue(results["compose_required_working_dir"])
        self.assertTrue(results["compose_customer_surface_port"])
        self.assertTrue(results["compose_dev_source_mount_present"])

    def test_hermes_workspace_dev_contract(self) -> None:
        desired = desired_slot(
            "dev-hermess",
            "hermes",
            "dev",
            "hermes-workspace-dev",
            product_repo="hermes-workspace",
        )
        results = contract_results("hermes-workspace-dev", desired)
        self.assertTrue(results["compose_runtime_user_model"])
        self.assertTrue(results["compose_uses_image_default_command"])
        self.assertTrue(results["compose_required_working_dir"])
        self.assertTrue(results["compose_customer_surface_port"])
        self.assertTrue(results["compose_dev_source_mount_present"])

    def test_hermes_rejects_missing_required_command(self) -> None:
        desired = desired_slot("oc2", "hermes", "customer", "hermes-customer", product_repo="openclaw-nas-agent")
        profile = load_profile("hermes-customer")
        rendered = render_compose(profile, desired).text.replace(
            "    command:\n      - gateway\n      - run\n",
            "",
            1,
        )
        checks = {item.name: item.ok for item in validate_compose_contract(profile, desired, rendered)}
        self.assertFalse(checks["compose_required_command"])

    def test_hermes_workspace_rejects_command_override(self) -> None:
        desired = desired_slot("oc2", "hermes", "customer", "hermes-workspace-customer", product_repo="hermes-workspace")
        profile = load_profile("hermes-workspace-customer")
        rendered = render_compose(profile, desired).text.replace(
            "    env_file:\n",
            "    command:\n      - gateway\n      - run\n    env_file:\n",
            1,
        )
        checks = {item.name: item.ok for item in validate_compose_contract(profile, desired, rendered)}
        self.assertFalse(checks["compose_uses_image_default_command"])

    def test_hermes_customer_rejects_compose_level_user(self) -> None:
        desired = desired_slot("oc2", "hermes", "customer", "hermes-customer")
        profile = load_profile("hermes-customer")
        rendered = render_compose(profile, desired).text.replace(
            "    group_add:\n",
            '    user: "1000:1000"\n    group_add:\n',
            1,
        )
        checks = {item.name: item.ok for item in validate_compose_contract(profile, desired, rendered)}
        self.assertFalse(checks["compose_runtime_user_model"])

    def test_dev_profile_requires_source_mount(self) -> None:
        desired = desired_slot("dev-openclaw", "openclaw", "dev", "openclaw-dev")
        results = contract_results("openclaw-dev", desired)
        self.assertTrue(results["compose_dev_source_mount_present"])


if __name__ == "__main__":
    unittest.main()
