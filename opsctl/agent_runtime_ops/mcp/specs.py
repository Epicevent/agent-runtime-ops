from __future__ import annotations

from typing import Any

from ..runtime_secrets import RUNTIME_SECRET_KEYS


def list_tool_specs() -> list[dict[str, Any]]:
    return [
        {
            "name": "ops_orientation",
            "title": "Orient Agent Runtime Ops",
            "description": "Check installed update status, runtime bindings, repository root, and runtime profiles.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "binding_list",
            "title": "List Runtime Bindings",
            "description": "List intended runtime bindings: instance id, linux account, public host, family, runtime class, and ports.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "binding_status",
            "title": "Runtime Binding Status",
            "description": "Compare intended binding truth with actual Apache route state for one target or all targets.",
            "inputSchema": {
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "additionalProperties": False,
            },
        },
        {
            "name": "binding_set_public_host",
            "title": "Set Binding Public Host",
            "description": "Change intended public host and Apache ServerName together for one runtime binding.",
            "inputSchema": {
                "type": "object",
                "properties": {"target": {"type": "string"}, "host": {"type": "string"}},
                "required": ["target", "host"],
                "additionalProperties": False,
            },
        },
        {
            "name": "apache_status",
            "title": "Apache Route Status",
            "description": "Inspect actual Apache route state and compare it to binding truth.",
            "inputSchema": {
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "additionalProperties": False,
            },
        },
        {
            "name": "apache_set_host",
            "title": "Set Apache Public Host",
            "description": "Low-level Apache-only repair command. Prefer binding_set_public_host for normal changes.",
            "inputSchema": {
                "type": "object",
                "properties": {"linux_account": {"type": "string"}, "host": {"type": "string"}},
                "required": ["linux_account", "host"],
                "additionalProperties": False,
            },
        },
        {
            "name": "runtime_truth",
            "title": "Runtime Image Truth",
            "description": "Inspect running container image labels directly; this is the authoritative runtime truth path.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Linux account, public host, or instance UUID."},
                    "all": {"type": "boolean", "default": False},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "runtime_config_status",
            "title": "Runtime Config Status",
            "description": "Inspect Hermes or OpenClaw runtime provider/model config without printing secret values.",
            "inputSchema": {
                "type": "object",
                "properties": {"target": {"type": "string", "description": "Linux account."}},
                "required": ["target"],
                "additionalProperties": False,
            },
        },
        {
            "name": "runtime_config_sanitize",
            "title": "Sanitize Runtime Config",
            "description": (
                "Dry-run by default. Remove stale provider key override paths from Hermes runtime config "
                "only when apply=true; secret values are never printed."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Linux account."},
                    "apply": {"type": "boolean", "default": False},
                },
                "required": ["target"],
                "additionalProperties": False,
            },
        },
        {
            "name": "runtime_set_model",
            "title": "Set Runtime Model",
            "description": (
                "Set Hermes or OpenClaw runtime provider/model config without accepting or printing provider "
                "secret values. For OpenClaw, provider+model compose into the agents.defaults.model ref "
                "'provider/model' (e.g. provider=google model=gemini-3.5-flash -> google/gemini-3.5-flash); "
                "a shape-preserving diff is printed."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Linux account."},
                    "provider": {"type": "string"},
                    "model": {"type": "string"},
                },
                "required": ["target", "provider", "model"],
                "additionalProperties": False,
            },
        },
        {
            "name": "document_tools_status",
            "title": "Document Tools Status",
        "description": "Inspect the live target container for the baseline HWP/HWPX and document-tool commands.",
        "inputSchema": {
            "type": "object",
            "properties": {
                    "target": {"type": "string", "description": "Linux account, public host, or instance UUID."},
                    "all": {"type": "boolean", "default": False},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "target_check",
            "title": "Check Target",
            "description": (
                "Run binding status, Apache route status, live image truth, and live contract check. "
                "For dev or customer groups, prefer runtime_class over repeated per-target calls."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "targets": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                    "runtime_class": {"type": "string", "enum": ["customer", "dev"]},
                    "family": {"type": "string", "enum": ["hermes", "openclaw"]},
                },
                "oneOf": [{"required": ["target"]}, {"required": ["targets"]}, {"required": ["runtime_class"]}],
                "additionalProperties": False,
            },
        },
        {
            "name": "deploy_update",
            "title": "Deploy Approved Update",
            "description": "Run self-update when the server has an approved full SHA that is not installed.",
            "inputSchema": {
                "type": "object",
                "properties": {"target_ref": {"type": "string"}},
                "additionalProperties": False,
            },
        },
        {
            "name": "rollout_image_plan",
            "title": "Plan Image Rollout",
            "description": "Validate wrapper/product image labels directly against runtime bindings without using release state.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "wrapper_image": {"type": "string"},
                    "product_image": {"type": "string"},
                    "target": {"type": "string"},
                    "targets": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["wrapper_image", "product_image"],
                "additionalProperties": False,
            },
        },
        {
            "name": "rollout_image_dev_apply",
            "title": "Apply Dev Image",
            "description": "Apply a digest-pinned wrapper/product image directly to a dev runtime binding.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "wrapper_image": {"type": "string"},
                    "product_image": {"type": "string"},
                    "allow_first_apply": {"type": "boolean", "default": False},
                },
                "required": ["target", "wrapper_image", "product_image"],
                "additionalProperties": False,
            },
        },
        {
            "name": "rollout_image_canary",
            "title": "Apply Canary Image",
            "description": "Apply a digest-pinned wrapper/product image directly to one customer canary target.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "wrapper_image": {"type": "string"},
                    "product_image": {"type": "string"},
                    "allow_first_apply": {"type": "boolean", "default": False},
                },
                "required": ["target", "wrapper_image", "product_image"],
                "additionalProperties": False,
            },
        },
        {
            "name": "rollout_image_promote",
            "title": "Promote Live Image",
            "description": "Read image truth from a canary target and apply that exact image to explicit customer targets.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "from_target": {"type": "string"},
                    "targets": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                },
                "required": ["from_target", "targets"],
                "additionalProperties": False,
            },
        },
        {
            "name": "projection_verify_target",
            "title": "Verify Target Projection",
            "description": "Run the existing opsctl projection gate for a digest-pinned wrapper/product image, optionally against live truth.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "wrapper_image": {"type": "string"},
                    "product_image": {"type": "string"},
                    "live": {"type": "boolean", "default": True},
                },
                "required": ["target", "wrapper_image", "product_image"],
                "additionalProperties": False,
            },
        },
        {
            "name": "checklist_pack",
            "title": "Run Checklist Pack",
            "description": (
                "Run an opsctl checklist pack (hermes-runtime or openclaw-runtime). The openclaw-runtime "
                "pack gates on the product-attested selftest contract (selftest_contract_ok), config drift, "
                "and the public route. Gemini chat smoke is optional."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "pack": {"type": "string", "enum": ["hermes-runtime", "openclaw-runtime"]},
                    "gemini_chat_smoke": {"type": "boolean", "default": False},
                },
                "required": ["target", "pack"],
                "additionalProperties": False,
            },
        },
        {
            "name": "config_validate",
            "title": "Validate Slot Config",
            "description": (
                "Validate a slot's on-disk config against its target product image, read-only, by running "
                "the product's own `config validate`. Use to see why the apply preflight gate would refuse."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Linux account."},
                    "product_image": {
                        "type": "string",
                        "description": "Optional repo@sha256:... to validate against; defaults to the slot's current image.",
                    },
                },
                "required": ["target"],
                "additionalProperties": False,
            },
        },
        {
            "name": "config_migrate",
            "title": "Migrate Slot Config",
            "description": (
                "Bring a slot's on-disk config into compliance with its target image by running the product's "
                "own doctor --fix (atomic write, timestamped .bak). Use when the apply preflight refuses with "
                "config preflight failed. Prints a diff of exactly what changed. Never hand-edit the config. "
                "Prefer dry_run:true first to review the change before applying."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Linux account."},
                    "product_image": {
                        "type": "string",
                        "description": "Optional repo@sha256:... whose doctor to run; defaults to the slot's current image.",
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "Preview on a throwaway copy and return a diff; write nothing. Review before applying.",
                        "default": False,
                    },
                },
                "required": ["target"],
                "additionalProperties": False,
            },
        },
        {
            "name": "image_status",
            "title": "Image Approval Status",
            "description": (
                "List the root-approved image digests (the image trust gate state). Read-only. The "
                "`image approve` action itself is root-only and is not an MCP tool, like `update approve`."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
        {
            "name": "canonical_recipe_validate",
            "title": "Validate Canonical Recipe",
            "description": "Validate the repo-owned canonical runtime recipe that generates dev/customer projections and wrapper labels.",
            "inputSchema": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
                "additionalProperties": False,
            },
        },
        {
            "name": "dev_recipe_status",
            "title": "Dev Recipe Status",
            "description": "Inspect the source-mode recipe currently recorded for a dev target.",
            "inputSchema": {
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"],
                "additionalProperties": False,
            },
        },
        {
            "name": "dev_recipe_apply",
            "title": "Apply Dev Recipe",
            "description": (
                "Connect a source-mode dev target to external dev output, optionally syncing it into the target stage, "
                "then apply and live-check the target."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "recipe_name": {"type": "string"},
                    "source_output": {"type": "string"},
                    "sync_from": {"type": "string"},
                    "build_command": {"type": "string"},
                    "allow_first_apply": {"type": "boolean", "default": False},
                    "no_apply": {"type": "boolean", "default": False},
                },
                "required": ["target"],
                "oneOf": [{"required": ["source_output"]}, {"required": ["sync_from"]}],
                "additionalProperties": False,
            },
        },
        {
            "name": "runtime_secret_status",
            "title": "Runtime Secret Status",
            "description": (
                "Check whether supported runtime secret keys exist without printing values. "
                "For dev or customer groups, prefer runtime_class over parallel per-target calls."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "targets": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                    "runtime_class": {"type": "string", "enum": ["customer", "dev"]},
                    "family": {"type": "string", "enum": ["hermes", "openclaw"]},
                },
                "oneOf": [{"required": ["target"]}, {"required": ["targets"]}, {"required": ["runtime_class"]}],
                "additionalProperties": False,
            },
        },
        {
            "name": "runtime_secret_set_from_file",
            "title": "Set Runtime Secret From File",
            "description": "Inject one runtime secret from an allowed local file through opsctl stdin.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "key": {"type": "string", "enum": sorted(RUNTIME_SECRET_KEYS)},
                    "secret_file": {"type": "string"},
                    "check": {"type": "boolean", "default": True},
                    "no_restart": {"type": "boolean", "default": False},
                },
                "required": ["target", "key", "secret_file"],
                "additionalProperties": False,
            },
        },
        {
            "name": "handoff_status",
            "title": "Handoff Credential Status",
            "description": (
                "Report handoff credential structure and presence without printing values. "
                "Use this for gateway tokens or workspace passwords instead of runtime_secret_status."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "targets": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                    "runtime_class": {"type": "string", "enum": ["customer", "dev"]},
                    "family": {"type": "string", "enum": ["hermes", "openclaw"]},
                },
                "oneOf": [{"required": ["target"]}, {"required": ["targets"]}, {"required": ["runtime_class"]}],
                "additionalProperties": False,
            },
        },
        {
            "name": "handoff_value_command",
            "title": "Handoff Value Command",
            "description": (
                "Return the exact repo-native CLI command an authorized operator can run in their own terminal "
                "to print a handoff credential value. This MCP tool does not print the value."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"],
                "additionalProperties": False,
            },
        },
        {
            "name": "heartbeat_status",
            "title": "OpenClaw Heartbeat Status",
            "description": (
                "Inspect OpenClaw heartbeat config and optional HEARTBEAT.md metadata without printing file contents. "
                "For dev or customer groups, prefer runtime_class over parallel per-target calls."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "targets": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                    "runtime_class": {"type": "string", "enum": ["customer", "dev"]},
                    "family": {"type": "string", "enum": ["openclaw"]},
                },
                "oneOf": [{"required": ["target"]}, {"required": ["targets"]}, {"required": ["runtime_class"]}],
                "additionalProperties": False,
            },
        },
        {
            "name": "heartbeat_disable",
            "title": "Disable OpenClaw Heartbeat",
            "description": "Set OpenClaw heartbeat cadence to 0m for one target and verify the resulting status.",
            "inputSchema": {
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"],
                "additionalProperties": False,
            },
        },
        {
            "name": "target_rollback",
            "title": "Rollback Target",
            "description": "Rollback one target and run a live check.",
            "inputSchema": {
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"],
                "additionalProperties": False,
            },
        },
        {
            "name": "nas_status",
            "title": "NAS Status",
            "description": "List pending NAS requests and optionally mounted child CIFS shares for a target.",
            "inputSchema": {
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "additionalProperties": False,
            },
        },
        {
            "name": "nas_mount",
            "title": "Mount NAS Share",
            "description": "Policy-check and mount an already-credentialed NAS share for a target.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "share": {"type": "string"},
                    "keep_fstab_on_failure": {"type": "boolean", "default": False},
                },
                "required": ["target", "share"],
                "additionalProperties": False,
            },
        },
        {
            "name": "nas_unmount",
            "title": "Unmount NAS Share",
            "description": "Temporarily unmount a managed NAS child CIFS share while keeping official credentials.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "share": {"type": "string"},
                    "lazy": {"type": "boolean", "default": False},
                    "delete_empty_dir": {"type": "boolean", "default": False},
                },
                "required": ["target", "share"],
                "additionalProperties": False,
            },
        },
        {
            "name": "nas_remove",
            "title": "Remove NAS Share",
            "description": "Unmount a NAS share and remove official credentials plus the managed fstab entry.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "share": {"type": "string"},
                    "lazy": {"type": "boolean", "default": False},
                    "delete_empty_dir": {"type": "boolean", "default": False},
                },
                "required": ["target", "share"],
                "additionalProperties": False,
            },
        },
        {
            "name": "nas_credential_status",
            "title": "NAS Credential Status",
            "description": "Report official root/customer credential presence for a NAS share without printing secrets.",
            "inputSchema": {
                "type": "object",
                "properties": {"target": {"type": "string"}, "share": {"type": "string"}},
                "required": ["target", "share"],
                "additionalProperties": False,
            },
        },
        {
            "name": "nas_approve_auto_once",
            "title": "Approve NAS Requests Once",
            "description": "Run one non-watch nas approve-auto pass.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    ]
