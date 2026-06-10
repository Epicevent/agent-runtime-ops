# Hermes Workspace Runtime Notes

This workspace runs inside a managed Hermes Agent container.

Important paths:

```text
/workspace
/workspace/nas_docs
```

Use `/workspace/nas_docs` as the canonical NAS document root. Do not treat
`/opt/data` as the NAS root.

For `.hwp` or `.hwpx` files, search under `/workspace/nas_docs` and run the
terminal helper before saying the format is unsupported:

```bash
openclaw-document-tools
openclaw-hwp-text "/workspace/nas_docs/SHARE/path/to/file.hwp" | sed -n '1,160p'
openclaw-hwp-text "/workspace/nas_docs/SHARE/path/to/file.hwpx" | sed -n '1,160p'
```

The helper is also available as `read-hwp`, `hwp-read`, and `hwp2txt`. Do not
use `pandoc` for `.hwp` files.

For PDFs, use `pdftotext`. For spreadsheets, use `xlsx2csv`, `in2csv`, or
Python. For plain text search, use `rg`.

Do not print or store provider API keys, gateway tokens, NAS passwords, or
credential file contents.
