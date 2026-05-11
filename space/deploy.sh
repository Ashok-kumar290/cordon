#!/usr/bin/env bash
# Deploy the Cordon playground backend to a Hugging Face Space.
#
# Prerequisites:
#   1. Create the Space on the HF web UI:
#        https://huggingface.co/new-space
#      Choose:
#        Owner:   <your HF username>
#        Name:    cordon-playground
#        SDK:     Docker
#        License: Apache 2.0
#        Visibility: Public
#      Leave it empty — this script populates it.
#
#   2. Make sure you can authenticate to HF over git. Either:
#        - run ``huggingface-cli login`` once and use ``hf_…`` tokens, or
#        - configure ``git credential.helper`` with your HF username + a
#          write-scoped access token from
#          https://huggingface.co/settings/tokens
#
# Usage:
#   bash space/deploy.sh <hf-username>
#
# Example:
#   bash space/deploy.sh Ashok-kumar290
#
# What it does:
#   - Clones the empty HF Space repo into a temporary directory.
#   - Stages README.md, Dockerfile and app.py from this repository.
#   - Commits and pushes. The Space builds automatically and is live in
#     ~60 seconds at:
#         https://<user>-cordon-playground.hf.space
#
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <hf-username>" >&2
  exit 64
fi

HF_USER="$1"
SPACE_NAME="${SPACE_NAME:-cordon-playground}"
SPACE_URL="https://huggingface.co/spaces/${HF_USER}/${SPACE_NAME}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="$(mktemp -d -t cordon-space.XXXXXX)"

cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

echo "──────────────────────────────────────────────────────────────"
echo "  Deploying Cordon playground backend to HF Space"
echo "  Target:   $SPACE_URL"
echo "  Workdir:  $WORK_DIR"
echo "──────────────────────────────────────────────────────────────"

git clone "$SPACE_URL" "$WORK_DIR"

# README.md (with HF frontmatter) and Dockerfile both ship from space/.
cp "$REPO_ROOT/space/README.md"   "$WORK_DIR/README.md"
cp "$REPO_ROOT/space/Dockerfile"  "$WORK_DIR/Dockerfile"

# The FastAPI app module is the canonical web/app.py — no fork, no
# duplication. We also ship templates/ and static/ so the same URL
# serves the marketing landing page AND the playground API.
cp    "$REPO_ROOT/web/app.py"    "$WORK_DIR/app.py"
rm -rf "$WORK_DIR/templates" "$WORK_DIR/static"
cp -r "$REPO_ROOT/web/templates" "$WORK_DIR/templates"
cp -r "$REPO_ROOT/web/static"    "$WORK_DIR/static"

# .gitattributes so HF doesn't try to LFS-track our small text files.
cat > "$WORK_DIR/.gitattributes" <<'EOF'
*.py    text eol=lf
*.md    text eol=lf
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
    commit -m "deploy: sync cordon-playground backend"

git push origin main

echo
echo "✓ pushed. Build status:"
echo "    $SPACE_URL"
echo "✓ public API will be live at:"
echo "    https://${HF_USER}-${SPACE_NAME}.hf.space"
