#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
python3 -m pytest --noconftest -q tests/stage10
