from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_document_baseline_installs_into_path_selected_python() -> None:
    script = (
        ROOT / "images" / "shared-document-tools" / "install-document-baseline.sh"
    ).read_text(encoding="utf-8")
    workflow = (
        ROOT / ".github" / "workflows" / "publish-openclaw-wrapper.yml"
    ).read_text(encoding="utf-8")

    assert 'active_python="$(command -v python3)"' in script
    assert 'readlink -f "$active_python"' in script
    assert 'readlink -f /usr/bin/python3' in script
    assert '"$active_python" -m pip install --no-cache-dir' in script
    assert '"${document_python_packages[@]}"' in script

    # The image gate must import through the same PATH-selected interpreter,
    # otherwise a successful package install could still test the wrong Python.
    assert 'python3 -c "import docx, pandas, openpyxl' in workflow


def test_document_package_set_covers_wrapper_smoke_imports() -> None:
    script = (
        ROOT / "images" / "shared-document-tools" / "install-document-baseline.sh"
    ).read_text(encoding="utf-8")

    for package in (
        "python-docx",
        "pandas",
        "openpyxl",
        "python-pptx",
        "lxml",
        "beautifulsoup4",
        "olefile",
        "pypdf",
        "pdfplumber",
        "pymupdf",
    ):
        assert package in script
