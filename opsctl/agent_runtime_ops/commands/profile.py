from __future__ import annotations

import argparse

from ..profiles import list_profile_names, load_profile


def cmd_profile_list(args: argparse.Namespace) -> int:
    for name in list_profile_names():
        profile = load_profile(name)
        print(f"{profile.name} {profile.digest}")
    return 0
