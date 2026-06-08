# Install

`agent-runtime-ops` is the public tooling package. It does not contain live
server state.

Install on a server from an administrator account. The command may ask for the
administrator sudo password. The operating-account model stays in place:
administrator installs the package, and `svcops` runs `opsctl` against
`/srv/openclaw-ops`.

```bash
curl -fsSL https://raw.githubusercontent.com/Epicevent/agent-runtime-ops/main/install.sh | sudo bash
sudo bash /opt/agent-runtime-ops/install.sh --check
```

Live state remains under:

```text
/srv/openclaw-ops
```

Expected boundary:

```text
/opt/agent-runtime-ops   root:svcops
/usr/local/bin/opsctl    symlink to /opt/agent-runtime-ops/.venv/bin/opsctl
/srv/openclaw-ops        root:svcops
```

Operator smoke test:

```bash
sudo -u svcops opsctl profile list
sudo -u svcops opsctl status oc1
```
