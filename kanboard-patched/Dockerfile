# Patched Kanboard v1.2.44 image — security fixes applied as file replacements
# mirroring upstream. (The base image ships no patch(1), so the fixed files are
# baked directly; the upstream diff is preserved in patches/ for provenance.)
#
#   1. CVE-2025-46825 / GHSA-5wj3-c9v4-pj9v — stored XSS in the task-import
#      project picker: escape project names (upstream v1.2.45 fix).
#   2. CVE-2026-56774 / GHSA-vvjm-mjq4-27c8 — IDOR: scope RememberMe session
#      removal to the owning user (upstream commit 928c68a).
#
# The pre-fix originals are kept under vuln-src/ so the exact fix diff is
# reviewable: diff -ru vuln-src/app files/app
FROM kanboard/kanboard:v1.2.44
COPY files/app/Template/project_view/importTasks.php /var/www/app/app/Template/project_view/importTasks.php
COPY files/app/Controller/UserViewController.php /var/www/app/app/Controller/UserViewController.php
COPY files/app/Model/RememberMeSessionModel.php /var/www/app/app/Model/RememberMeSessionModel.php
COPY files/app/Subscriber/AuthSubscriber.php /var/www/app/app/Subscriber/AuthSubscriber.php
RUN echo "[build] security fixes applied: CVE-2025-46825 (output escaping) + CVE-2026-56774 (ownership scoping)"
