#!/usr/bin/env bash
# Lanzador de conveniencia: crea venv si no existe, instala deps y ejecuta
# ipmonitor con sudo (la captura de paquetes requiere CAP_NET_RAW).
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

if [ ! -d .venv ]; then
    python3 -m venv .venv
    ./.venv/bin/pip install -U pip wheel
    ./.venv/bin/pip install -r requirements.txt
fi

exec sudo -E "$DIR/.venv/bin/python" -m ipmonitor "$@"
