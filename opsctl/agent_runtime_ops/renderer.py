from __future__ import annotations

import hashlib
from dataclasses import dataclass

from jinja2 import Environment, StrictUndefined

from .profiles import RuntimeProfile
from .state import DesiredSlot


@dataclass(frozen=True)
class RenderedCompose:
    text: str
    sha256: str


def render_compose(profile: RuntimeProfile, desired: DesiredSlot, variables: dict | None = None) -> RenderedCompose:
    env = Environment(undefined=StrictUndefined, autoescape=False, keep_trailing_newline=True)
    template = env.from_string((profile.path / "compose.yml.tpl").read_text(encoding="utf-8"))
    merged = {
        "slot": desired.slot,
        "family": desired.lane_data.get("family"),
        "slot_class": desired.lane_data.get("slot_class"),
        "release": desired.release_name,
        "runtime_profile": desired.runtime_profile,
        "image_ref": desired.release_data.get("wrapper_image"),
        "target_home": f"/home/{desired.slot}",
        "runtime_uid": "${RUNTIME_UID}",
        "runtime_gid": "${RUNTIME_GID}",
        "data_gid": "${DATA_GID}",
        "gateway_port": "${GATEWAY_PORT}",
        "bridge_port": "${BRIDGE_PORT}",
        "source_output": "${SOURCE_OUTPUT}",
    }
    if variables:
        merged.update(variables)
    text = template.render(**merged)
    return RenderedCompose(text=text, sha256="sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest())
