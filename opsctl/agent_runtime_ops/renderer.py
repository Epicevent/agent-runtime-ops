from __future__ import annotations

import hashlib
from dataclasses import dataclass

from jinja2 import Environment, StrictUndefined

from .profiles import RuntimeProfile
from .state import DesiredSlot

try:
    import grp
    import pwd
except ImportError:  # pragma: no cover - Windows/dev fallback
    grp = None
    pwd = None


@dataclass(frozen=True)
class RenderedCompose:
    text: str
    sha256: str


def _slot_ports(desired: DesiredSlot) -> tuple[str, str]:
    if desired.route is None:
        raise ValueError(f"slot route is required to render compose: {desired.slot}")
    return str(desired.route.gateway_port), str(desired.route.bridge_port)


def _runtime_ids(slot: str) -> tuple[str, str, str]:
    if pwd is None or grp is None:
        return "${RUNTIME_UID}", "${RUNTIME_GID}", "${DATA_GID}"
    try:
        runtime = pwd.getpwnam(f"{slot}_rt")
        data_group = grp.getgrnam(f"{slot}_data")
    except KeyError:
        return "${RUNTIME_UID}", "${RUNTIME_GID}", "${DATA_GID}"
    return str(runtime.pw_uid), str(runtime.pw_gid), str(data_group.gr_gid)


def render_compose(profile: RuntimeProfile, desired: DesiredSlot, variables: dict | None = None) -> RenderedCompose:
    env = Environment(undefined=StrictUndefined, autoescape=False, keep_trailing_newline=True)
    template = env.from_string((profile.path / "compose.yml.tpl").read_text(encoding="utf-8"))
    runtime_uid, runtime_gid, data_gid = _runtime_ids(desired.slot)
    gateway_port, bridge_port = _slot_ports(desired)
    merged = {
        "slot": desired.slot,
        "instance_id": desired.route.instance_id if desired.route else "",
        "linux_account": desired.route.linux_account if desired.route else desired.slot,
        "public_host": desired.route.public_host if desired.route else "",
        "family": desired.lane_data.get("family"),
        "runtime_class": desired.route.runtime_class if desired.route else desired.lane_data.get("slot_class"),
        "slot_class": desired.lane_data.get("slot_class"),
        "release": desired.release_name,
        "runtime_profile": desired.runtime_profile,
        "image_ref": desired.release_data.get("wrapper_image"),
        "target_home": f"/home/{desired.slot}",
        "runtime_uid": runtime_uid,
        "runtime_gid": runtime_gid,
        "data_gid": data_gid,
        "gateway_port": gateway_port,
        "bridge_port": bridge_port,
        "source_output": "${SOURCE_OUTPUT}",
    }
    if variables:
        merged.update(variables)
    text = template.render(**merged)
    return RenderedCompose(text=text, sha256="sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest())
