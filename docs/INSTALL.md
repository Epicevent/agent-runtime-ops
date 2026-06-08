# Install

`agent-runtime-ops` is the public tooling package. It does not contain live
server state.

Install on a server after cloning a reviewed release:

```bash
python3 -m venv /opt/agent-runtime-ops/.venv
/opt/agent-runtime-ops/.venv/bin/pip install /opt/agent-runtime-ops
```

Live state remains under:

```text
/srv/openclaw-ops
```

