#!/usr/bin/env bash
set -e
if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
if [ ! -f .env ]; then
  python setup_env.py
fi
if [ -d "$HOME/_oqs" ]; then
  export OQS_INSTALL_PATH="$HOME/_oqs"
  export DYLD_LIBRARY_PATH="$HOME/_oqs/lib:${DYLD_LIBRARY_PATH:-}"
  export LD_LIBRARY_PATH="$HOME/_oqs/lib:${LD_LIBRARY_PATH:-}"
fi
python app.py
