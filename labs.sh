#!/usr/bin/env bash
# Bring the whole suite up, down, or report on it.
#
#   ./labs.sh up          # start the portal and every lab
#   ./labs.sh up portal   # just the main menu at http://localhost:8079
#   ./labs.sh up jwt sqli # start only the labs whose directory matches
#   ./labs.sh status      # HTTP check every port
#   ./labs.sh down        # stop everything
#   ./labs.sh test        # run every lab's solve_check.php
#
# Twenty-one containers is a lot of memory. Start a subset if the machine is busy.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# directory | port
LABS=(
  "Portal|8079"
  "SQLi Lab|8080"
  "XSS Lab|8081"
  "Path Traversal Lab|8082"
  "IDOR Lab|8083"
  "OSCommand Injection|8084"
  "SSRF Lab|8085"
  "SSTI Lab|8086"
  "XXE Lab|8087"
  "File Upload Lab|8088"
  "PHP Object Injection|8089"
  "NoSQL Injection Lab|8090"
  "CSRF Lab|8091"
  "Open Redirect Lab|8092"
  "JWT Lab|8093"
  "Race Condition Lab|8094"
  "CORS CSP Lab|8095"
  "Crypto Oracle Lab|8096"
  "Business Logic Lab|8097"
  "GraphQL Lab|8098"
  "Auth Reset Lab|8099"
  "XPath LDAP Lab|8100"
)

matches() {                       # $1 = dir, rest = filters
  local dir="$1"; shift
  [ $# -eq 0 ] && return 0
  local lower; lower=$(printf '%s' "$dir" | tr 'A-Z' 'a-z')
  for f in "$@"; do
    case "$lower" in *"$(printf '%s' "$f" | tr 'A-Z' 'a-z')"*) return 0 ;; esac
  done
  return 1
}

cmd_up() {
  for entry in "${LABS[@]}"; do
    dir="${entry%%|*}"; port="${entry##*|}"
    matches "$dir" "$@" || continue
    printf '%-24s :%s  ' "$dir" "$port"
    if grep -qE '^\s*build:' "$dir/docker-compose.yml"; then
      (cd "$dir" && docker compose up --build -d) >/dev/null 2>&1 && echo "up (built)" || echo "FAILED"
    else
      (cd "$dir" && docker compose up -d) >/dev/null 2>&1 && echo "up" || echo "FAILED"
    fi
  done
  echo
  echo "Some bind-mounted labs compile PHP extensions on first boot and need a"
  echo "minute before they answer. Re-run './labs.sh status' until it is green."
}

cmd_down() {
  for entry in "${LABS[@]}"; do
    dir="${entry%%|*}"
    matches "$dir" "$@" || continue
    printf '%-24s ' "$dir"
    (cd "$dir" && docker compose down) >/dev/null 2>&1 && echo "down" || echo "FAILED"
  done
}

cmd_status() {
  local ok=0 bad=0
  for entry in "${LABS[@]}"; do
    dir="${entry%%|*}"; port="${entry##*|}"
    matches "$dir" "$@" || continue
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 "http://localhost:$port/index.php")
    if [ "$code" = "200" ]; then
      printf '  OK    %-24s http://localhost:%s\n' "$dir" "$port"; ok=$((ok+1))
    else
      printf '  WAIT  %-24s :%s  (http %s)\n' "$dir" "$port" "$code"; bad=$((bad+1))
    fi
  done
  echo
  echo "$ok up, $bad not answering"
}

cmd_test() {
  for entry in "${LABS[@]}"; do
    dir="${entry%%|*}"
    matches "$dir" "$@" || continue
    [ -f "$dir/solve_check.php" ] || continue
    echo "=== $dir ==="
    (cd "$dir" && MSYS_NO_PATHCONV=1 docker compose exec -T web php //var/www/html/solve_check.php 2>&1 | tail -3)
  done
}

case "${1:-status}" in
  up)     shift; cmd_up "$@" ;;
  down)   shift; cmd_down "$@" ;;
  status) shift; cmd_status "$@" ;;
  test)   shift; cmd_test "$@" ;;
  *)      sed -n '2,14p' "$0" ;;
esac
