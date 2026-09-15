#!/bin/sh
set -eu

PLUGIN_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON=${PYTHON:-python3}
PYVER=$($PYTHON -c 'import sys; print(f"{sys.version_info.major}{sys.version_info.minor}")')
VENDOR_DIR="$PLUGIN_DIR/vendor$PYVER"

export PYTHONUNBUFFERED=1
export PYTHONDONTWRITEBYTECODE=1

if [ -d "$VENDOR_DIR" ]; then
    if [ -n "${PYTHONPATH:-}" ]; then
        export PYTHONPATH="$VENDOR_DIR:$PYTHONPATH"
    else
        export PYTHONPATH="$VENDOR_DIR"
    fi
fi

if [ -z "${R2_CONFIG:-}" ]; then
    for candidate in \
        "$PLUGIN_DIR/config.json" \
        "$PLUGIN_DIR/app/config.json" \
        "/storage/plugins/koropwnz-stab-r2d2-plugin/config.json" \
        "/app/config.json"
    do
        if [ -f "$candidate" ]; then
            export R2_CONFIG="$candidate"
            break
        fi
    done
fi

if ! $PYTHON -c 'import aiohttp' >/dev/null 2>&1; then
    echo "ERROR: aiohttp is unavailable for Python $PYVER on this board" >&2
    exit 1
fi

exec $PYTHON "$PLUGIN_DIR/plugin.py"

