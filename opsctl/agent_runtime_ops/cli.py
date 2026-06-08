from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .paths import DEFAULT_STATE_ROOT
from .profiles import list_profile_names, load_profile
from .renderer import render_compose
from .state import load_desired_slot


def _state_root(args: argparse.Namespace) -> Path:
    return Path(args.state_root)


def cmd_profile_list(args: argparse.Namespace) -> int:
    for name in list_profile_names():
        profile = load_profile(name)
        print(f"{profile.name} {profile.digest}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    try:
        desired = load_desired_slot(args.slot, _state_root(args))
        profile = load_profile(desired.runtime_profile)
    except Exception as exc:
        print(f"status=unknown")
        print(f"reason={exc}")
        return 1
    print(f"slot={desired.slot}")
    print(f"lane={desired.lane}")
    print(f"release={desired.release_name}")
    print(f"runtime_profile={profile.name}")
    print(f"runtime_profile_digest={profile.digest}")
    print(f"family={profile.metadata.get('family')}")
    print(f"mode={profile.metadata.get('mode')}")
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    try:
        desired = load_desired_slot(args.slot, _state_root(args))
        profile = load_profile(desired.runtime_profile)
    except Exception as exc:
        plan = {
            "slot": args.slot,
            "status": "not_ready",
            "reason": str(exc),
            "mutates": False,
        }
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        return 1
    rendered = render_compose(profile, desired)
    plan = {
        "slot": desired.slot,
        "lane": desired.lane,
        "release": desired.release_name,
        "runtime_profile": profile.name,
        "runtime_profile_digest": profile.digest,
        "compose_sha256": rendered.sha256,
        "mutates": False,
    }
    print(json.dumps(plan, ensure_ascii=False, indent=2))
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    try:
        desired = load_desired_slot(args.slot, _state_root(args))
        profile = load_profile(desired.runtime_profile)
    except Exception as exc:
        print(f"slot={args.slot}")
        print("check_status=not_ready")
        print(f"reason={exc}")
        return 1
    print(f"slot={desired.slot}")
    print(f"runtime_profile={profile.name}")
    print(f"runtime_profile_digest={profile.digest}")
    print("check_mode=non_mutating")
    print("check_status=skeleton")
    return 0


def cmd_blocked_mutation(args: argparse.Namespace) -> int:
    print(f"error: {args.command_name} is intentionally disabled in the initial skeleton", file=sys.stderr)
    print("hint: implement apply/rollback/rollout only after renderer, rollback, and audit tests are in place", file=sys.stderr)
    return 2


def cmd_release_add(args: argparse.Namespace) -> int:
    print("error: release add is intentionally disabled in the initial skeleton", file=sys.stderr)
    return 2


def cmd_release_promote(args: argparse.Namespace) -> int:
    print("error: release promote is intentionally disabled in the initial skeleton", file=sys.stderr)
    return 2


def cmd_nas_requests(args: argparse.Namespace) -> int:
    print("nas_requests_status=skeleton")
    print("mutates=false")
    return 0


def cmd_nas_approve_auto(args: argparse.Namespace) -> int:
    print("error: nas approve-auto is intentionally disabled in the initial skeleton", file=sys.stderr)
    return 2


def cmd_nas_policy_check(args: argparse.Namespace) -> int:
    print(f"slot={args.slot}")
    print(f"share={args.share}")
    print("policy_check_status=skeleton")
    print("mutates=false")
    return 0


def cmd_admin_serve(args: argparse.Namespace) -> int:
    from .admin_server import main as admin_main

    return admin_main(["--host", args.host, "--port", str(args.port)])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="opsctl")
    parser.add_argument("--state-root", default=str(DEFAULT_STATE_ROOT))
    sub = parser.add_subparsers(dest="command", required=True)

    profile = sub.add_parser("profile")
    profile_sub = profile.add_subparsers(dest="profile_command", required=True)
    profile_list = profile_sub.add_parser("list")
    profile_list.set_defaults(func=cmd_profile_list)

    for name, func in (("status", cmd_status), ("plan", cmd_plan), ("check", cmd_check)):
        item = sub.add_parser(name)
        item.add_argument("slot")
        item.set_defaults(func=func)

    for name in ("apply", "rollback"):
        item = sub.add_parser(name)
        item.add_argument("slot")
        item.set_defaults(func=cmd_blocked_mutation, command_name=name)

    rollout = sub.add_parser("rollout")
    rollout.add_argument("lane")
    rollout.set_defaults(func=cmd_blocked_mutation, command_name="rollout")

    release = sub.add_parser("release")
    release_sub = release.add_subparsers(dest="release_command", required=True)
    release_add = release_sub.add_parser("add")
    release_add.add_argument("name")
    release_add.add_argument("image")
    release_add.set_defaults(func=cmd_release_add)
    release_promote = release_sub.add_parser("promote")
    release_promote.add_argument("name")
    release_promote.add_argument("lane")
    release_promote.set_defaults(func=cmd_release_promote)

    nas = sub.add_parser("nas")
    nas_sub = nas.add_subparsers(dest="nas_command", required=True)
    nas_requests = nas_sub.add_parser("requests")
    nas_requests.set_defaults(func=cmd_nas_requests)
    nas_auto = nas_sub.add_parser("approve-auto")
    nas_auto.set_defaults(func=cmd_nas_approve_auto)
    nas_policy = nas_sub.add_parser("policy-check")
    nas_policy.add_argument("slot")
    nas_policy.add_argument("share")
    nas_policy.set_defaults(func=cmd_nas_policy_check)

    admin = sub.add_parser("admin")
    admin_sub = admin.add_subparsers(dest="admin_command", required=True)
    serve = admin_sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", default=18088, type=int)
    serve.set_defaults(func=cmd_admin_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
