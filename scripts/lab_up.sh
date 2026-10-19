#!/bin/sh
# Bring up exactly one variant of the lab, tearing down both compose projects
# first. Two compose projects cannot share the same subnets (Docker rejects
# the second one with "Pool overlaps with other one on this address space"),
# so switching variants requires tearing down whichever project is running.
#
# Usage: scripts/lab_up.sh vulnerable|fixed
set -u
cd "$(dirname "$0")/.." || exit 1
V="${1:-}"
case "$V" in
  vulnerable) F=docker-compose.yml ;;
  fixed)      F=docker-compose.fixed.yml ;;
  *) echo "usage: $0 vulnerable|fixed" >&2; exit 1 ;;
esac

docker compose -f docker-compose.yml down -v --remove-orphans > /dev/null 2>&1 || true
docker compose -f docker-compose.fixed.yml down -v --remove-orphans > /dev/null 2>&1 || true

echo "[lab_up] starting the $V lab ($F)"
docker compose -f "$F" up -d --build > /tmp/lab-up.log 2>&1
if [ $? -ne 0 ]; then
  echo "[lab_up] compose up failed:"; tail -20 /tmp/lab-up.log; exit 1
fi

i=0
until curl -s --max-time 4 "http://localhost:8080/?controller=AuthController&action=login" -o /tmp/lab-ready.html 2>/dev/null && grep -q csrf_token /tmp/lab-ready.html; do
  i=$((i+1))
  if [ $i -gt 90 ]; then echo "[lab_up] lab did not become ready"; exit 1; fi
  sleep 2
done
echo "[lab_up] $V lab ready (waited ~$((i*2))s for first HTTP response)"
