#!/usr/bin/env bash
# Turn each sample lockfile directory into a CycloneDX JSON SBOM.
# Re-runnable: the same lockfiles produce the same component set.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CDXGEN_VERSION="12.9.0"
LOCKS="${ROOT}/data/sample/internal/lockfiles"
OUT="${ROOT}/data/sample/sboms"

mkdir -p "${OUT}"

# Registry license lookups are off so reruns do not depend on the network.
export FETCH_LICENSE=false

generate() {
  local service="$1"
  local project_type="$2"
  local src="${LOCKS}/${service}"
  local dest="${OUT}/${service}.cdx.json"
  echo "cdxgen ${CDXGEN_VERSION}: ${service} (${project_type})"
  npx --yes "@cyclonedx/cdxgen@${CDXGEN_VERSION}" \
    --no-install-deps \
    --no-recurse \
    --no-babel \
    --fail-on-error \
    --spec-version 1.6 \
    --json-pretty \
    --author "Sibyl sample workspace" \
    -t "${project_type}" \
    -o "${dest}" \
    "${src}"
}

# cdxgen lists Python components from requirements.txt but leaves the
# dependency graph empty unless it installs the packages. Fill the root
# dependsOn from requirements.in so direct dependencies are in the SBOM.
mark_python_directs() {
  local service="$1"
  python3 - "${LOCKS}/${service}/requirements.in" "${OUT}/${service}.cdx.json" <<'PY'
import json
import re
import sys
from pathlib import Path

req_path, sbom_path = sys.argv[1:]

def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()

directs = []
for raw in Path(req_path).read_text().splitlines():
    line = raw.split("#", 1)[0].strip()
    if not line or line.startswith("-"):
        continue
    name = re.split(r"[<>=!~;\[]", line, maxsplit=1)[0].strip()
    if name:
        directs.append(normalize(name))

document = json.loads(Path(sbom_path).read_text())
by_name = {}
for component in document.get("components") or []:
    purl = component.get("purl") or ""
    if not purl.startswith("pkg:pypi/"):
        continue
    pkg = purl.split("/", 1)[1].split("@", 1)[0]
    by_name[normalize(pkg)] = component["bom-ref"]

missing = [name for name in directs if name not in by_name]
if missing:
    sys.exit(f"direct pins missing from {sbom_path}: {', '.join(missing)}")

root = document["metadata"]["component"]["bom-ref"]
document["dependencies"] = [
    {"ref": root, "dependsOn": [by_name[name] for name in directs]}
]
Path(sbom_path).write_text(json.dumps(document, indent=2) + "\n")
print(f"  {len(directs)} direct dependencies")
PY
}

generate checkout-api python
mark_python_directs checkout-api
generate merchant-portal js
generate reporting-worker python
mark_python_directs reporting-worker
generate internal-admin js

echo "SBOMs written to ${OUT}"
