from __future__ import annotations

import argparse


def cmd_admin_serve(args: argparse.Namespace) -> int:
    from ..admin_server import main as admin_main

    return admin_main(["--host", args.host, "--port", str(args.port)])
