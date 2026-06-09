from __future__ import annotations

import hashlib
from dataclasses import dataclass
import re

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


def _slot_ports(slot: str) -> tuple[str, str]:
    dev_ports = {
        "dev-oc": 30789,
        "dev-hermess": 30889,
    }
    if slot in dev_ports:
        gateway_port = dev_ports[slot]
        return str(gateway_port), str(gateway_port + 1)
    match = re.match(r"^oc([0-9]+)$", slot)
    if not match:
        return "${GATEWAY_PORT}", "${BRIDGE_PORT}"
    number = int(match.group(1))
    gateway_port = 28789 + (number - 1) * 100
    return str(gateway_port), str(gateway_port + 1)


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
    gateway_port, bridge_port = _slot_ports(desired.slot)
    merged = {
        "slot": desired.slot,
        "family": desired.lane_data.get("family"),
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
