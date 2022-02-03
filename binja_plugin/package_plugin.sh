#!/bin/bash

set -exuo pipefail
shopt -s nullglob

PACKAGE_NAME=${PACKAGE_NAME:-blaze}
OUTPUT_WHEEL_NAME=${OUTPUT_WHEEL_NAME:-blaze-0.1.0-py3-none-any.whl}
BLAZE_WHEEL_SERVER_BASE_URL=${BLAZE_WHEEL_SERVER_BASE_URL:-http://localhost:8000}

DIST_DIR=./dist
PLUGIN_JSON_TEMPLATE=plugin.json.jq

# Update version in pyproject.toml
cp -a pyproject.toml pyproject.toml.bak
function restore_pyproject { mv pyproject.toml.bak pyproject.toml; }
trap restore_pyproject EXIT
base_version=$(toml get --toml-path pyproject.toml tool.poetry.version)
version=${base_version}.${CI_PIPELINE_ID:-dev1}
toml set --toml-path pyproject.toml tool.poetry.version "$version"

# Build the wheel
rm -rf "${DIST_DIR:?}"/*
python3 -m build -o "$DIST_DIR"

# find the wheel that poetry created
wheels=("${DIST_DIR}/${PACKAGE_NAME}"-*.whl)
if [[ ${#wheels[@]} -eq 0 ]]; then
    echo "No matching wheels found" >&2
    exit 1
elif [[ ${#wheels[@]} -ne 1 ]]; then
    echo "Too many matching wheels: ${wheels[*]}" >&2
    exit 1
fi
wheel=${wheels[0]}

packageurl=${BLAZE_WHEEL_SERVER_BASE_URL}/${OUTPUT_WHEEL_NAME}
dependencies=$(pkginfo "$wheel" -f requires_dist --single --sequence-delim=$'\n')

mv "${wheel}" "${DIST_DIR}/${OUTPUT_WHEEL_NAME}"

jq -n -f "${PLUGIN_JSON_TEMPLATE}" \
  --arg timestamp "$(date +%s)" \
  --arg version "${version}" \
  --arg packageurl "${packageurl}" \
  --arg dependencies "${dependencies}" \
  > "${DIST_DIR}/plugin.json"

jq '[.plugin]' \
  < "${DIST_DIR}/plugin.json" \
  > "${DIST_DIR}/plugins.json"
