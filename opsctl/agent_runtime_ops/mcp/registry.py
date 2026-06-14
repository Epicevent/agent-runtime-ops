from __future__ import annotations

from typing import Any, Callable

from .handlers import deploy as deploy_handlers
from .handlers import handoff as handoff_handlers
from .handlers import heartbeat as heartbeat_handlers
from .handlers import nas as nas_handlers
from .handlers import recipe as recipe_handlers
from .handlers import rollout as rollout_handlers
from .handlers import routing as routing_handlers
from .handlers import runtime_config as runtime_config_handlers
from .handlers import secrets as secret_handlers

ToolHandler = Callable[[Any, dict[str, Any]], dict[str, Any]]


def _bind(handler: Callable[[Any, dict[str, Any]], dict[str, Any]]) -> ToolHandler:
    return handler


HANDLERS: dict[str, ToolHandler] = {
    "ops_orientation": _bind(routing_handlers.ops_orientation),
    "binding_list": _bind(routing_handlers.binding_list),
    "binding_status": _bind(routing_handlers.binding_status),
    "binding_set_public_host": _bind(routing_handlers.binding_set_public_host),
    "apache_status": _bind(routing_handlers.apache_status),
    "apache_set_host": _bind(routing_handlers.apache_set_host),
    "runtime_truth": _bind(routing_handlers.runtime_truth),
    "document_tools_status": _bind(routing_handlers.document_tools_status),
    "target_check": _bind(routing_handlers.target_check),
    "runtime_config_status": _bind(runtime_config_handlers.status),
    "runtime_config_sanitize": _bind(runtime_config_handlers.sanitize),
    "runtime_set_model": _bind(runtime_config_handlers.set_model),
    "deploy_update": _bind(deploy_handlers.deploy_update),
    "rollout_image_plan": _bind(rollout_handlers.image_plan),
    "rollout_image_dev_apply": _bind(rollout_handlers.image_dev_apply),
    "rollout_image_canary": _bind(rollout_handlers.image_canary),
    "rollout_image_promote": _bind(rollout_handlers.image_promote),
    "projection_verify_target": _bind(rollout_handlers.projection_verify_target),
    "checklist_pack": _bind(rollout_handlers.checklist_pack),
    "canonical_recipe_validate": _bind(recipe_handlers.canonical_validate),
    "dev_recipe_status": _bind(recipe_handlers.dev_status),
    "dev_recipe_apply": _bind(recipe_handlers.dev_apply),
    "runtime_secret_status": _bind(secret_handlers.status),
    "runtime_secret_set_from_file": _bind(secret_handlers.set_from_file),
    "handoff_status": _bind(handoff_handlers.status),
    "handoff_value_command": _bind(handoff_handlers.value_command),
    "heartbeat_status": _bind(heartbeat_handlers.status),
    "heartbeat_disable": _bind(heartbeat_handlers.disable),
    "target_rollback": _bind(routing_handlers.target_rollback),
    "nas_status": _bind(nas_handlers.status),
    "nas_mount": _bind(nas_handlers.mount),
    "nas_unmount": _bind(nas_handlers.unmount),
    "nas_remove": _bind(nas_handlers.remove),
    "nas_credential_status": _bind(nas_handlers.credential_status),
    "nas_approve_auto_once": _bind(nas_handlers.approve_auto_once),
}


def get_handler(name: str) -> ToolHandler | None:
    return HANDLERS.get(name)
