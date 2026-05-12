#!/usr/bin/env bash
# Deploy Cordon Cloud (dashboard + ingest backend) to a Hugging Face Space.
#
# Mirrors the structure of ``space/deploy.sh`` (the playground deploy):
# clone the empty Space, copy the right files in, push.
#
# Prerequisites:
#   1. Create the Space on the HF web UI:
#        https://huggingface.co/new-space
#      Owner:       <your HF username>
#      Name:        cordon-cloud
#      SDK:         Docker → Blank
#      License:     Apache 2.0
#      Visibility:  Public
#      Leave it empty. This script populates it.
#
#   2. Authenticate to HF over git, either via ``hf auth login`` or by
#      exporting one of HF_TOKEN / HUGGINGFACE_TOKEN / HUGGING_FACE_HUB_TOKEN.
#
# Usage:
#   bash cloud_server/space/deploy.sh <hf-username>
#
# What it does:
#   - Clones the empty HF Space repo into a tmp dir.
#   - Stages cloud_server/__init__.py, app.py, storage.py, templates/,
#     static/, plus the Dockerfile and README from cloud_server/space/.
#   - Commits and pushes. Build is ~60–90 s. Live URL:
#         https://<user>-cordon-cloud.hf.space
#
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <hf-username>" >&2
  exit 64
fi

HF_USER="$1"
SPACE_NAME="${SPACE_NAME:-cordon-cloud}"
SPACE_URL="https://huggingface.co/spaces/${HF_USER}/${SPACE_NAME}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC_DIR="${REPO_ROOT}/cloud_server"
SPACE_TEMPLATE="${REPO_ROOT}/cloud_server/space"
WORK_DIR="$(mktemp -d -t cordon-cloud-space.XXXXXX)"

# ── Resolve an HF write token for the push ────────────────────────
HF_TOKEN="${HF_TOKEN:-${HUGGINGFACE_TOKEN:-${HUGGING_FACE_HUB_TOKEN:-}}}"
if [[ -z "$HF_TOKEN" ]] && [[ -r "$HOME/.cache/huggingface/token" ]]; then
  HF_TOKEN="$(< "$HOME/.cache/huggingface/token" tr -d '[:space:]')"
fi
if [[ -z "$HF_TOKEN" ]]; then
  echo "error: no HF token found." >&2
  echo "  run:  .venv/bin/hf auth login" >&2
  echo "  or:   export HF_TOKEN=hf_xxx" >&2
  exit 65
fi
PUSH_URL="https://${HF_USER}:${HF_TOKEN}@huggingface.co/spaces/${HF_USER}/${SPACE_NAME}"

cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

echo "──────────────────────────────────────────────────────────────"
echo "  Deploying Cordon Cloud to HF Space"
echo "  Target:   $SPACE_URL"
echo "  Workdir:  $WORK_DIR"
echo "──────────────────────────────────────────────────────────────"

git clone "$SPACE_URL" "$WORK_DIR"

# HF Space metadata + image definition.
cp    "$SPACE_TEMPLATE/README.md"   "$WORK_DIR/README.md"
cp    "$SPACE_TEMPLATE/Dockerfile"  "$WORK_DIR/Dockerfile"

# Server module (kept flat at the Space root; the Dockerfile remaps it
# into /home/app/cloud_server/ so the imports line up).
cp    "$SRC_DIR/__init__.py" "$WORK_DIR/__init__.py"
cp    "$SRC_DIR/app.py"      "$WORK_DIR/app.py"
cp    "$SRC_DIR/storage.py"  "$WORK_DIR/storage.py"

rm -rf "$WORK_DIR/templates" "$WORK_DIR/static"
cp -r  "$SRC_DIR/templates"  "$WORK_DIR/templates"
cp -r  "$SRC_DIR/static"     "$WORK_DIR/static"

# .gitattributes: keep small text files out of LFS.
cat > "$WORK_DIR/.gitattributes" <<'EOF'
*.py    text eol=lf
*.md    text eol=lf
*.html  text eol=lf
*.js    text eol=lf
Dockerfile text eol=lf
EOF

cd "$WORK_DIR"
git add -A
if git diff --cached --quiet; then
  echo "nothing to deploy (Space already up to date)."
  exit 0
fi

git -c user.name="Cordon Deploy" \
    -c user.email="deploy@cordon.local" \
    commit -m "deploy: sync cordon-cloud server + dashboard"

git push "$PUSH_URL" main

echo
echo "✓ pushed. Build status:"
echo "    $SPACE_URL"
echo "✓ live URL:"
echo "    https://${HF_USER,,}-${SPACE_NAME,,}.hf.space"
