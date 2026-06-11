from __future__ import annotations

import argparse
import sys


def cmd_blocked_mutation(args: argparse.Namespace) -> int:
    print(f"error: {args.command_name} is intentionally disabled in the initial skeleton", file=sys.stderr)
    print("hint: enable lane rollout only after single-slot apply/rollback migration tests pass", file=sys.stderr)
    return 2
