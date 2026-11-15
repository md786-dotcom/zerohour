#!/bin/sh
# One command for the demo: build, make the lab PCAPs, open the dashboard.
set -e
cd "$(dirname "$0")"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build build -j >/dev/null
cmake --build build --target pcaps >/dev/null
rm -rf .zerohour
[ -z "$NO_OPEN" ] && (sleep 1; open http://127.0.0.1:8765/) &
exec ./build/zerohour serve --port 8765 --state .zerohour
