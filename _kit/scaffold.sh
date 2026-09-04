#!/usr/bin/env bash
# Scaffold a new kit-based lab: css (base theme + kit layer), lab_kit.php copy,
# docker-compose.yml, uploads-free skeleton.
#
#   ./_kit/scaffold.sh "JWT Lab" jwt 8093
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="$1"; SLUG="$2"; PORT="$3"

TARGET="$ROOT/$DIR"
mkdir -p "$TARGET/css"

cat "$ROOT/XSS Lab/css/styles.css" "$ROOT/_kit/kit.css" > "$TARGET/css/styles.css"
cp "$ROOT/_kit/lab_kit.php" "$TARGET/lab_kit.php"

cat > "$TARGET/docker-compose.yml" <<YML
services:
  web:
    build: .
    container_name: ${SLUG}_lab
    ports:
      - "${PORT}:80"
    volumes:
      - ./:/var/www/html
    restart: unless-stopped
YML

echo "scaffolded $DIR (slug=$SLUG port=$PORT)"
