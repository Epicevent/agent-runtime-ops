from __future__ import annotations

from typing import Any


def apache_route_checks(binding: Any, apache_route: Any) -> list[tuple[bool, str, str | None]]:
    checks = [
        (
            apache_route.public_host == binding.public_host,
            "apache_public_host_matches_binding",
            f"apache={apache_route.public_host} binding={binding.public_host}",
        ),
        (
            apache_route.gateway_port == binding.gateway_port,
            "apache_gateway_port_matches_binding",
            f"apache={apache_route.gateway_port} binding={binding.gateway_port}",
        ),
    ]
    if apache_route.websocket_port is not None:
        checks.append(
            (
                apache_route.websocket_port == binding.gateway_port,
                "apache_websocket_port_matches_binding",
                f"apache={apache_route.websocket_port} binding={binding.gateway_port}",
            )
        )
    return checks
