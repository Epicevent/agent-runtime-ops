#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "error: this script must run as root inside the image build" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

apt-get update

apt-get install -y --no-install-recommends \
  ca-certificates \
  locales \
  fontconfig \
  fonts-noto-cjk \
  curl \
  wget \
  git \
  openssh-client \
  rsync \
  file \
  tree \
  less \
  vim-tiny \
  ripgrep \
  fd-find \
  jq \
  yq \
  zip \
  unzip \
  tar \
  gzip \
  bzip2 \
  xz-utils \
  unrar-free \
  poppler-utils \
  qpdf \
  ghostscript \
  tesseract-ocr \
  tesseract-ocr-eng \
  tesseract-ocr-kor \
  ocrmypdf \
  imagemagick \
  ffmpeg \
  libreoffice \
  libreoffice-writer \
  libreoffice-calc \
  libreoffice-impress \
  python3-uno \
  pandoc \
  antiword \
  catdoc \
  xlsx2csv \
  csvkit \
  gnumeric \
  python3 \
  python3-pip \
  python3-venv \
  python3-dev \
  python3-lxml \
  python3-bs4 \
  python3-pandas \
  python3-openpyxl \
  python3-docx \
  nodejs \
  npm

/usr/bin/python3 -m pip install --no-cache-dir --break-system-packages \
  python-docx \
  python-pptx \
  pyhwp \
  olefile \
  pypdf \
  pdfplumber \
  pymupdf

if [[ -x /opt/hermes/.venv/bin/python ]]; then
  hermes_python="/opt/hermes/.venv/bin/python"
  hermes_doc_packages=(
    python-docx
    pandas
    openpyxl
    python-pptx
    lxml
    beautifulsoup4
    pypdf
    pdfplumber
    pymupdf
    pyhwp
    olefile
  )
  if command -v uv >/dev/null 2>&1; then
    uv pip install --python "$hermes_python" --no-cache "${hermes_doc_packages[@]}"
  else
    "$hermes_python" -m pip --version >/dev/null 2>&1 \
      || "$hermes_python" -m ensurepip --upgrade
    "$hermes_python" -m pip install --no-cache-dir "${hermes_doc_packages[@]}"
  fi
fi

if grep -q '^# *ko_KR.UTF-8 UTF-8' /etc/locale.gen; then
  sed -i 's/^# *ko_KR.UTF-8 UTF-8/ko_KR.UTF-8 UTF-8/' /etc/locale.gen
elif ! grep -q '^ko_KR.UTF-8 UTF-8' /etc/locale.gen; then
  echo 'ko_KR.UTF-8 UTF-8' >> /etc/locale.gen
fi

locale-gen ko_KR.UTF-8
update-locale LANG=ko_KR.UTF-8 LANGUAGE=ko_KR:ko

for package_name in fonts-noto-cjk-extra fonts-nanum; do
  if apt-cache show "$package_name" >/dev/null 2>&1; then
    apt-get install -y --no-install-recommends "$package_name"
  fi
done

unoconv_candidate="$(apt-cache policy unoconv | awk '/Candidate:/ {print $2; exit}')"
if [[ -n "$unoconv_candidate" && "$unoconv_candidate" != "(none)" ]]; then
  apt-get install -y --no-install-recommends unoconv
fi

fc-cache -f

if apt-cache show 7zip >/dev/null 2>&1; then
  apt-get install -y --no-install-recommends 7zip
else
  apt-get install -y --no-install-recommends p7zip-full p7zip-rar || apt-get install -y --no-install-recommends p7zip-full
fi

if ! command -v 7z >/dev/null 2>&1 && command -v 7zz >/dev/null 2>&1; then
  ln -sf "$(command -v 7zz)" /usr/local/bin/7z
fi
if ! command -v 7zz >/dev/null 2>&1 && command -v 7z >/dev/null 2>&1; then
  ln -sf "$(command -v 7z)" /usr/local/bin/7zz
fi

if command -v npm >/dev/null 2>&1; then
  npm install -g clawhub || true
fi

apt-get clean
rm -rf /var/lib/apt/lists/*

echo "container document baseline install complete"
