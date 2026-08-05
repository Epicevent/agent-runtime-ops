from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import subprocess

from .routing import validate_linux_account

DEFAULT_APACHE_OPENCLAW_DIR = Path(os.environ.get("AGENT_RUNTIME_APACHE_OPENCLAW_DIR", "/etc/apache2/openclaw"))
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
SERVER_NAME_RE = re.compile(r"^(\s*ServerName\s+)(\S+)(\s*(?:#.*)?)$")
HTTP_PROXY_RE = re.compile(r"^\s*ProxyPass\s+/\s+http://127\.0\.0\.1:(\d+)/", re.MULTILINE)
WS_PROXY_RE = re.compile(r"ws://127\.0\.0\.1:(\d+)/", re.MULTILINE)


@dataclass(frozen=True)
class ApacheRoute:
    linux_account: str
    public_host: str
    gateway_port: int
    websocket_port: int | None
    path: Path


@dataclass(frozen=True)
class ApacheHostChange:
    linux_account: str
    old_host: str
    new_host: str
    path: Path
    backup_path: Path
    configtest_stdout: str
    configtest_stderr: str
    reload_stdout: str
    reload_stderr: str


@dataclass(frozen=True)
class ApachePortChange:
    linux_account: str
    old_port: int
    new_port: int
    path: Path
    backup_path: Path


def validate_public_host(host: str) -> str:
    value = str(host or "").strip().lower().rstrip(".")
    if not HOST_RE.match(value):
        raise ValueError("public host must be a DNS name without scheme, port, path, or whitespace")
    return value


def apache_route_path(linux_account: str, apache_dir: Path | None = None) -> Path:
    account = validate_linux_account(linux_account)
    return (apache_dir or DEFAULT_APACHE_OPENCLAW_DIR) / f"apache-subdomain-{account}.conf"


def _active_lines(text: str) -> list[str]:
    lines = []
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(raw_line)
    return lines


def parse_apache_route(linux_account: str, apache_dir: Path | None = None) -> ApacheRoute:
    account = validate_linux_account(linux_account)
    path = apache_route_path(account, apache_dir)
    if path.is_symlink():
        raise ValueError(f"apache route file must not be symlink: {path}")
    text = path.read_text(encoding="utf-8")
    host = ""
    http_ports: list[int] = []
    ws_ports: list[int] = []
    for line in _active_lines(text):
        match = SERVER_NAME_RE.match(line)
        if match:
            if host:
                raise ValueError(f"multiple ServerName directives in {path}")
            host = validate_public_host(match.group(2))
        match = HTTP_PROXY_RE.match(line)
        if match:
            http_ports.append(int(match.group(1)))
        for ws_match in WS_PROXY_RE.finditer(line):
            ws_ports.append(int(ws_match.group(1)))
    if not host:
        raise ValueError(f"missing ServerName in {path}")
    if not http_ports:
        raise ValueError(f"missing ProxyPass gateway port in {path}")
    if len(set(http_ports)) != 1:
        raise ValueError(f"inconsistent ProxyPass ports in {path}: {http_ports}")
    if ws_ports and len(set(ws_ports)) != 1:
        raise ValueError(f"inconsistent websocket ports in {path}: {ws_ports}")
    if ws_ports and ws_ports[0] != http_ports[0]:
        raise ValueError(f"websocket port does not match ProxyPass port in {path}: ws={ws_ports[0]} http={http_ports[0]}")
    return ApacheRoute(
        linux_account=account,
        public_host=host,
        gateway_port=http_ports[0],
        websocket_port=ws_ports[0] if ws_ports else None,
        path=path,
    )


def replace_server_name(text: str, host: str) -> tuple[str, str]:
    new_host = validate_public_host(host)
    old_host = ""
    replaced = 0
    lines = []
    for line in text.splitlines(keepends=True):
        body = line[:-1] if line.endswith("\n") else line
        newline = "\n" if line.endswith("\n") else ""
        match = SERVER_NAME_RE.match(body)
        if match and not body.lstrip().startswith("#"):
            old_host = validate_public_host(match.group(2))
            lines.append(f"{match.group(1)}{new_host}{match.group(3)}{newline}")
            replaced += 1
        else:
            lines.append(line)
    if replaced != 1:
        raise ValueError(f"expected exactly one active ServerName directive, found {replaced}")
    return "".join(lines), old_host


def replace_proxy_port(text: str, port: int) -> tuple[str, int]:
    if not 1024 <= int(port) <= 65535:
        raise ValueError("proxy port must be between 1024 and 65535")
    active = "\n".join(_active_lines(text))
    old_http = {int(value) for value in HTTP_PROXY_RE.findall(active)}
    old_ws = {int(value) for value in WS_PROXY_RE.findall(active)}
    if len(old_http) != 1 or (old_ws and old_ws != old_http):
        raise ValueError("apache route has inconsistent proxy ports")
    old_port = next(iter(old_http))
    updated = re.sub(r"(http://127\.0\.0\.1:)\d+(/)", rf"\g<1>{int(port)}\2", text)
    updated = re.sub(r"(ws://127\.0\.0\.1:)\d+(/)", rf"\g<1>{int(port)}\2", updated)
    return updated, old_port


def set_apache_proxy_port(linux_account: str, port: int, *, backup_suffix: str) -> ApachePortChange:
    account = validate_linux_account(linux_account)
    path = apache_route_path(account)
    if path.is_symlink():
        raise ValueError(f"apache route file must not be symlink: {path}")
    original = path.read_text(encoding="utf-8")
    updated, old_port = replace_proxy_port(original, port)
    backup_path = path.with_name(f"{path.name}.{backup_suffix}.bak")
    if old_port == int(port):
        return ApachePortChange(account, old_port, int(port), path, backup_path)
    shutil.copy2(path, backup_path)
    path.write_text(updated, encoding="utf-8")
    configtest = subprocess.run(["apache2ctl", "configtest"], text=True, capture_output=True, check=False)
    if configtest.returncode != 0:
        shutil.copy2(backup_path, path)
        raise RuntimeError((configtest.stderr or configtest.stdout).strip() or "apache configtest failed")
    reload_proc = subprocess.run(["systemctl", "reload", "apache2"], text=True, capture_output=True, check=False)
    if reload_proc.returncode != 0:
        shutil.copy2(backup_path, path)
        subprocess.run(["systemctl", "reload", "apache2"], check=False)
        raise RuntimeError((reload_proc.stderr or reload_proc.stdout).strip() or "apache reload failed")
    return ApachePortChange(account, old_port, int(port), path, backup_path)


def set_apache_host(
    linux_account: str,
    host: str,
    *,
    apache_dir: Path | None = None,
    backup_suffix: str,
) -> ApacheHostChange:
    account = validate_linux_account(linux_account)
    path = apache_route_path(account, apache_dir)
    if path.is_symlink():
        raise ValueError(f"apache route file must not be symlink: {path}")
    original = path.read_text(encoding="utf-8")
    updated, old_host = replace_server_name(original, host)
    new_host = validate_public_host(host)
    if old_host == new_host:
        backup_path = path.with_name(f"{path.name}.{backup_suffix}.bak")
        return ApacheHostChange(account, old_host, new_host, path, backup_path, "", "", "", "")

    backup_path = path.with_name(f"{path.name}.{backup_suffix}.bak")
    shutil.copy2(path, backup_path)
    path.write_text(updated, encoding="utf-8")
    configtest = subprocess.run(["apache2ctl", "configtest"], text=True, capture_output=True, check=False)
    if configtest.returncode != 0:
        shutil.copy2(backup_path, path)
        raise RuntimeError((configtest.stderr or configtest.stdout).strip() or "apache configtest failed")
    reload_proc = subprocess.run(["systemctl", "reload", "apache2"], text=True, capture_output=True, check=False)
    if reload_proc.returncode != 0:
        shutil.copy2(backup_path, path)
        subprocess.run(["apache2ctl", "configtest"], text=True, capture_output=True, check=False)
        subprocess.run(["systemctl", "reload", "apache2"], text=True, capture_output=True, check=False)
        raise RuntimeError((reload_proc.stderr or reload_proc.stdout).strip() or "apache reload failed")
    return ApacheHostChange(
        linux_account=account,
        old_host=old_host,
        new_host=new_host,
        path=path,
        backup_path=backup_path,
        configtest_stdout=configtest.stdout,
        configtest_stderr=configtest.stderr,
        reload_stdout=reload_proc.stdout,
        reload_stderr=reload_proc.stderr,
    )
