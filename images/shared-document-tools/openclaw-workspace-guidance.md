# OpenClaw Workspace Runtime Notes

This workspace runs inside a managed OpenClaw container.

Important paths:

```text
/home/node/.openclaw/workspace
/home/node/nas_docs
```

Use `/home/node/nas_docs` as the canonical NAS document root. Treat it as
read-only unless an operator explicitly says otherwise.

For `.hwp` or `.hwpx` files, search under `/home/node/nas_docs` and run the
terminal helper before saying the format is unsupported:

```bash
openclaw-document-tools
openclaw-hwp-text "/home/node/nas_docs/SHARE/path/to/file.hwp" | sed -n '1,160p'
openclaw-hwp-text "/home/node/nas_docs/SHARE/path/to/file.hwpx" | sed -n '1,160p'
```

The helper is also available as `read-hwp`, `hwp-read`, and `hwp2txt`. Do not
use `pandoc` for `.hwp` files.

For PDFs, use `pdftotext`. For spreadsheets, use `xlsx2csv`, `in2csv`, or
Python. For plain text search, use `rg`.

Do not print or store provider API keys, gateway tokens, NAS passwords, or
credential file contents.
