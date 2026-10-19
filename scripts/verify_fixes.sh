#!/bin/sh
# Regression suite for the two security fixes.
#
# Rebuilds the patched image, resets the lab to a fresh database, runs both
# PoCs against it and asserts the vulnerable behaviour is gone:
#   poc_xss  -> exit 2  (payload present but HTML-escaped in the <option> node)
#   poc_idor -> exit 2  (cross-user deletion refused, self-removal still works)
# It also verifies byte-for-byte that the container runs the patched files
# from kanboard-patched/files/ (md5 comparison against the repo).
#
# Usage: scripts/verify_fixes.sh
set -u
cd "$(dirname "$0")/.." || exit 1

echo "[1/5] switching to the patched lab (tears down any running variant first)"
scripts/lab_up.sh fixed || exit 1

echo "[2/5] (readiness is handled by lab_up.sh)"

echo "[3/5] XSS PoC against the patched build (expect exit 2)"
POC_TAG=fixed python3 scripts/poc_xss.py
xss_rc=$?

echo "[4/5] IDOR PoC against the patched build (expect exit 2)"
POC_TAG=fixed python3 scripts/poc_idor.py
idor_rc=$?

echo "[5/5] deployed-file integrity (container files vs repo files)"
fail=0
for f in Controller/UserViewController.php Model/RememberMeSessionModel.php Subscriber/AuthSubscriber.php Template/project_view/importTasks.php; do
  img=$(docker exec lab-kanboard sh -c "md5sum /var/www/app/app/$f" | cut -d' ' -f1)
  repo=$(md5 -q "kanboard-patched/files/app/$f" 2>/dev/null || md5sum "kanboard-patched/files/app/$f" | cut -d' ' -f1)
  if [ "$img" = "$repo" ]; then
    echo "  OK   $f"
  else
    echo "  FAIL $f (image=$img repo=$repo)"
    fail=1
  fi
done

echo
echo "poc_xss exit=$xss_rc (want 2)  |  poc_idor exit=$idor_rc (want 2)  |  integrity fail=$fail (want 0)"
if [ "$xss_rc" = "2" ] && [ "$idor_rc" = "2" ] && [ "$fail" = "0" ]; then
  echo "RESULT: ALL FIXES VERIFIED"
  exit 0
fi
echo "RESULT: FIX VERIFICATION FAILED"
exit 1
