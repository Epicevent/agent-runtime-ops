from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_runtime_ops.apache import parse_apache_route, replace_proxy_port, replace_server_name, set_apache_host


def write_route(root: Path, slot: str = "oc3", host: str = "oc3.ji-tech.co.kr", port: int = 28989) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"apache-subdomain-{slot}.conf"
    path.write_text(
        f"""
# comment ServerName ignored.example.com
<VirtualHost *:443>
    ServerName {host}
    RewriteRule ^/(.*)$ ws://127.0.0.1:{port}/$1 [P,L]
    ProxyPass        / http://127.0.0.1:{port}/ retry=0 timeout=3600
    ProxyPassReverse / http://127.0.0.1:{port}/
</VirtualHost>
""".lstrip(),
        encoding="utf-8",
    )
    return path


class ApacheRouteTests(unittest.TestCase):
    def test_replace_proxy_port_updates_http_and_websocket(self) -> None:
        text = "ProxyPass / http://127.0.0.1:30001/\nRewriteRule ^/(.*) ws://127.0.0.1:30001/$1 [P,L]\n"
        updated, old = replace_proxy_port(text, 31889)
        self.assertEqual(old, 30001)
        self.assertIn("http://127.0.0.1:31889/", updated)
        self.assertIn("ws://127.0.0.1:31889/", updated)

    def test_replace_proxy_port_handles_full_virtualhost_before_proxy_lines(self) -> None:
        text = """<VirtualHost *:443>
ServerName dev-hermess.ji-tech.co.kr
RewriteRule ^/(.*)$ ws://127.0.0.1:30889/$1 [P,L]
ProxyPass / http://127.0.0.1:30889/ retry=0
ProxyPassReverse / http://127.0.0.1:30889/
</VirtualHost>
"""
        updated, old = replace_proxy_port(text, 31889)
        self.assertEqual(old, 30889)
        self.assertIn("ws://127.0.0.1:31889/", updated)
        self.assertIn("ProxyPass / http://127.0.0.1:31889/", updated)

    def test_replace_proxy_port_rejects_public_port(self) -> None:
        with self.assertRaisesRegex(ValueError, "between 1024"):
            replace_proxy_port("ProxyPass / http://127.0.0.1:30001/\n", 80)

    def test_parse_apache_route_extracts_host_and_port(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = write_route(root)
            route = parse_apache_route("oc3", root)
        self.assertEqual(route.path, path)
        self.assertEqual(route.public_host, "oc3.ji-tech.co.kr")
        self.assertEqual(route.gateway_port, 28989)
        self.assertEqual(route.websocket_port, 28989)

    def test_replace_server_name_changes_only_active_server_name(self) -> None:
        text = "# ServerName old.example.com\n    ServerName OC3.JI-TECH.CO.KR\n"
        updated, old_host = replace_server_name(text, "Demo.JI-TECH.CO.KR.")
        self.assertEqual(old_host, "oc3.ji-tech.co.kr")
        self.assertIn("# ServerName old.example.com", updated)
        self.assertIn("ServerName demo.ji-tech.co.kr", updated)

    def test_parse_rejects_proxy_port_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = write_route(root)
            text = path.read_text(encoding="utf-8").replace("ProxyPass        / http://127.0.0.1:28989/", "ProxyPass        / http://127.0.0.1:29999/")
            path.write_text(text, encoding="utf-8")
            with self.assertRaises(ValueError):
                parse_apache_route("oc3", root)

    def test_set_apache_host_rolls_back_on_configtest_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = write_route(root)
            before = path.read_text(encoding="utf-8")
            with patch("agent_runtime_ops.apache.subprocess.run") as run:
                run.return_value.returncode = 1
                run.return_value.stdout = ""
                run.return_value.stderr = "bad config"
                with self.assertRaises(RuntimeError):
                    set_apache_host("oc3", "demo.ji-tech.co.kr", apache_dir=root, backup_suffix="test")
            self.assertEqual(path.read_text(encoding="utf-8"), before)
            self.assertTrue((root / "apache-subdomain-oc3.conf.test.bak").is_file())

    def test_set_apache_host_preserves_ports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_route(root)
            with patch("agent_runtime_ops.apache.subprocess.run") as run:
                run.return_value.returncode = 0
                run.return_value.stdout = ""
                run.return_value.stderr = ""
                change = set_apache_host("oc3", "demo.ji-tech.co.kr", apache_dir=root, backup_suffix="test")
            route = parse_apache_route("oc3", root)
        self.assertEqual(change.old_host, "oc3.ji-tech.co.kr")
        self.assertEqual(change.new_host, "demo.ji-tech.co.kr")
        self.assertEqual(route.public_host, "demo.ji-tech.co.kr")
        self.assertEqual(route.gateway_port, 28989)

    def test_set_apache_host_rolls_back_and_reloads_on_reload_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = write_route(root)
            before = path.read_text(encoding="utf-8")
            with patch("agent_runtime_ops.apache.subprocess.run") as run:
                run.side_effect = [
                    type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})(),
                    type("Result", (), {"returncode": 1, "stdout": "", "stderr": "reload failed"})(),
                    type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})(),
                    type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})(),
                ]
                with self.assertRaises(RuntimeError):
                    set_apache_host("oc3", "demo.ji-tech.co.kr", apache_dir=root, backup_suffix="test")
            self.assertEqual(path.read_text(encoding="utf-8"), before)
            self.assertEqual(run.call_args_list[-1].args[0], ["systemctl", "reload", "apache2"])


if __name__ == "__main__":
    unittest.main()
