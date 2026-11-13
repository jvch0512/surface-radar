#!/usr/bin/env bash
# Zero-dependency build and test: javac + java only.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf out && mkdir -p out/main out/test
javac --release 17 -Xlint:all -Werror -d out/main $(find src/main -name '*.java')
if [ "${1:-}" = "test" ]; then
  javac --release 17 -Xlint:all -Werror -cp out/main -d out/test $(find src/test -name '*.java')
  java -ea -cp out/main:out/test dev.jvch.radar.AllTests
fi
