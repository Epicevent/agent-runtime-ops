#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from xml.etree import ElementTree


DEFAULT_MAX_CHARS = 200_000


def eprint(message: str) -> None:
    print(message, file=sys.stderr)


def clean_text(text: str) -> str:
    lines = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = " ".join(raw.split())
        if line:
            lines.append(line)
    return "\n".join(lines).strip()


def run_command(args: list[str], timeout: int = 120) -> tuple[int, str, str]:
    proc = subprocess.run(
        args,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


def extract_with_hwp5txt(path: Path) -> tuple[str, str]:
    if not shutil.which("hwp5txt"):
        return "", "hwp5txt: command not found"
    try:
        rc, out, err = run_command(["hwp5txt", str(path)])
    except subprocess.TimeoutExpired:
        return "", "hwp5txt: timed out"
    text = clean_text(out)
    if rc == 0 and text:
        return text, "hwp5txt"
    return "", f"hwp5txt: exit={rc} {clean_text(err)[:300]}"


def extract_hwpx_zip(path: Path) -> tuple[str, str]:
    if not zipfile.is_zipfile(path):
        return "", "hwpx_zip: not a zip file"

    texts: list[str] = []
    try:
        with zipfile.ZipFile(path) as zf:
            names = sorted(
                name
                for name in zf.namelist()
                if name.lower().endswith(".xml")
                and not name.startswith("/")
                and ".." not in Path(name).parts
            )
            for name in names:
                if not (name.startswith("Contents/") or name.startswith("content/") or "section" in name.lower()):
                    continue
                try:
                    root = ElementTree.fromstring(zf.read(name))
                except ElementTree.ParseError:
                    continue
                for node in root.iter():
                    tag = node.tag.rsplit("}", 1)[-1].lower()
                    if tag in {"t", "text", "p"} and node.text:
                        texts.append(node.text)
                    if node.tail:
                        texts.append(node.tail)
    except (OSError, zipfile.BadZipFile) as exc:
        return "", f"hwpx_zip: {exc}"

    text = clean_text("\n".join(texts))
    if text:
        return text, "hwpx_zip"
    return "", "hwpx_zip: no text extracted"


def extract_hwp_preview(path: Path) -> tuple[str, str]:
    try:
        import olefile  # type: ignore
    except Exception:
        return "", "ole_preview: olefile module not available"

    try:
        ole = olefile.OleFileIO(str(path))
    except Exception as exc:
        return "", f"ole_preview: {exc}"

    try:
        candidates = []
        for stream in ole.listdir():
            joined = "/".join(stream)
            if joined.lower().endswith("prvtext") or "prvtext" in joined.lower():
                candidates.append(stream)
        for stream in candidates:
            data = ole.openstream(stream).read()
            for encoding in ("utf-16le", "utf-8", "cp949"):
                try:
                    text = clean_text(data.decode(encoding, errors="ignore"))
                except Exception:
                    continue
                if text:
                    return text, "ole_preview"
    finally:
        ole.close()

    return "", "ole_preview: no preview text"


def extract_with_libreoffice(path: Path) -> tuple[str, str]:
    soffice = shutil.which("libreoffice") or shutil.which("soffice")
    if not soffice:
        return "", "libreoffice: command not found"

    with tempfile.TemporaryDirectory(prefix="openclaw-hwp-") as tmp:
        try:
            rc, _out, err = run_command(
                [soffice, "--headless", "--convert-to", "txt", "--outdir", tmp, str(path)],
                timeout=180,
            )
        except subprocess.TimeoutExpired:
            return "", "libreoffice: timed out"
        txt_files = list(Path(tmp).glob("*.txt"))
        if rc == 0 and txt_files:
            text = clean_text(txt_files[0].read_text(encoding="utf-8", errors="replace"))
            if text:
                return text, "libreoffice"
        return "", f"libreoffice: exit={rc} {clean_text(err)[:300]}"


def extract_text(path: Path) -> tuple[str, list[str]]:
    suffix = path.suffix.lower()
    attempts: list[str] = []
    extractors = []
    if suffix == ".hwpx":
        extractors.append(extract_hwpx_zip)
    extractors.extend([extract_with_hwp5txt, extract_hwp_preview, extract_with_libreoffice])

    for extractor in extractors:
        text, detail = extractor(path)
        attempts.append(detail)
        if text:
            return text, attempts
    return "", attempts


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract readable text from HWP/HWPX files for OpenClaw NAS agents.")
    parser.add_argument("path", help="HWP/HWPX file path")
    parser.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS)
    args = parser.parse_args()

    path = Path(args.path).expanduser()
    if not path.exists():
        eprint(f"error: file not found: {path}")
        return 1
    if not path.is_file():
        eprint(f"error: not a regular file: {path}")
        return 1
    if path.suffix.lower() not in {".hwp", ".hwpx"}:
        eprint(f"error: expected .hwp or .hwpx file: {path}")
        return 1

    text, attempts = extract_text(path)
    if not text:
        eprint("error: could not extract HWP/HWPX text")
        for attempt in attempts:
            eprint(f"attempt={attempt}")
        return 1

    if args.max_chars > 0 and len(text) > args.max_chars:
        text = text[: args.max_chars] + "\n[openclaw-hwp-text: truncated]"
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
