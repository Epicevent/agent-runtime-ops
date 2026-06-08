from __future__ import annotations

import unittest

from agent_runtime_ops.compose_contract import validate_compose_contract
from agent_runtime_ops.profiles import load_profile
from agent_runtime_ops.renderer import _slot_ports, render_compose
from agent_runtime_ops.state import DesiredSlot


def desired_slot(slot: str, family: str, slot_class: str, runtime_profile: str) -> DesiredSlot:
    digest = "sha256:" + "a" * 64
    return DesiredSlot(
        slot=slot,
        lane=f"{family}-{slot_class}-stable",
        lane_data={"family": family, "slot_class": slot_class},
        release_name=f"{family}-release",
        release_data={
            "family": family,
            "wrapper_image": f"ghcr.io/epicevent/agent-runtime-{family}@{digest}",
            "product_image": f"ghcr.io/epicevent/{family}-jitech@{digest}",
            "digest": digest,
        },
        runtime_profile=runtime_profile,
    )


def contract_results(profile_name: str, desired: DesiredSlot) -> dict[str, bool]:
    profile = load_profile(profile_name)
    rendered = render_compose(profile, desired)
    return {item.name: item.ok for item in validate_compose_contract(profile, desired, rendered.text)}


class RuntimeContractTests(unittest.TestCase):
    def test_oc_slot_port_policy(self) -> None:
        self.assertEqual(_slot_ports("oc1"), ("28789", "28790"))
        self.assertEqual(_slot_ports("oc2"), ("28889", "28890"))
        self.assertEqual(_slot_ports("oc15"), ("30189", "30190"))

    def test_openclaw_customer_contract(self) -> None:
        desired = desired_slot("oc1", "openclaw", "customer", "openclaw-customer")
        results = contract_results("openclaw-customer", desired)
        self.assertTrue(results["compose_runtime_user_model"])
        self.assertTrue(results["compose_nas_root_bind_present"])
        self.assertTrue(results["compose_nas_root_readonly"])
        self.assertTrue(results["compose_nas_root_propagation"])
        self.assertTrue(results["compose_customer_source_mount_absent"])

    def test_hermes_customer_contract(self) -> None:
        desired = desired_slot("oc2", "hermes", "customer", "hermes-customer")
        results = contract_results("hermes-customer", desired)
        self.assertTrue(results["compose_runtime_user_model"])
        self.assertTrue(results["compose_nas_root_bind_present"])
        self.assertTrue(results["compose_nas_root_readonly"])
        self.assertTrue(results["compose_nas_root_propagation"])
        self.assertTrue(results["compose_customer_source_mount_absent"])

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
