#!/bin/env bash
# Copyright The Conforma Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# Pushes policy bundles to quay.io, but only if anything changed since
# the last bundle was pushed.
#
# Usage: ./update-bundles.sh [repo-prefix1] [repo-prefix2] ...
# Example: ./update-bundles.sh "quay.io/enterprise-contract/" "quay.io/conforma/"
#
# If no arguments provided, uses REPO_PREFIXES environment variable
# If no arguments and no REPO_PREFIXES environment variable, defaults to "quay.io/conforma/"
# Secrets must be provided via environment variables for security
#
set -o errexit
set -o pipefail
set -o nounset

# Get repository prefixes from arguments or environment variable
if [[ $# -gt 0 ]]; then
  REPO_PREFIXES="$*"
  echo "Using repository prefixes from arguments: $REPO_PREFIXES"
else
  REPO_PREFIXES="${REPO_PREFIXES-quay.io/conforma/}"
  echo "Using repository prefixes from environment: $REPO_PREFIXES"
fi

# Validate repository prefixes
for prefix in $REPO_PREFIXES; do
  if [[ "$prefix" != *"enterprise-contract"* && "$prefix" != *"conforma"* ]]; then
    echo "WARNING: Unknown repository prefix: $prefix" >&2
  fi
done
ROOT_DIR=$( git rev-parse --show-toplevel )
BUNDLES="release pipeline task build_task"
OPA="go run github.com/conforma/cli opa"
ORAS="go run oras.land/oras/cmd/oras"

DRY_RUN=${DRY_RUN:-""}
DRY_RUN_ECHO=""
[ "$DRY_RUN" == "1" ] && DRY_RUN_ECHO="echo #"

# Check required environment variables for multi-org setup
if [[ "$REPO_PREFIXES" == *"enterprise-contract"* ]]; then
  if [[ -z "${EC_REGISTRY_USER:-}" || -z "${EC_REGISTRY_PASS:-}" ]]; then
    echo "ERROR: EC_REGISTRY_USER and EC_REGISTRY_PASS must be set for enterprise-contract repositories" >&2
    exit 1
  fi
fi

if [[ "$REPO_PREFIXES" == *"conforma"* ]]; then
  if [[ -z "${CONFORMA_REGISTRY_USER:-}" || -z "${CONFORMA_REGISTRY_PASS:-}" ]]; then
    echo "ERROR: CONFORMA_REGISTRY_USER and CONFORMA_REGISTRY_PASS must be set for conforma repositories" >&2
    exit 1
  fi
fi

function bundle_src_dirs() {
  echo policy/lib
  echo "policy/$1"
}

function bundle_subdir() {
  echo "policy"
}

function exclusions() {
  echo "artifacthub-pkg.yml"
}

function repo_name() {
  local bundle_name="$1"
  local repo_prefix="$2"
  
  if [[ "$repo_prefix" == *"enterprise-contract"* ]]; then
    echo "ec-$bundle_name-policy"
  else
    echo "${bundle_name//_/-}-policy"
  fi
}

tmp_oci_dirs=()
function cleanup() {
  rm -rf "${tmp_oci_dirs[@]}"
}
trap cleanup EXIT

function ec_registry_login() {
  echo "$EC_REGISTRY_PASS" | docker login quay.io --username "$EC_REGISTRY_USER" --password-stdin
}

function conforma_registry_login() {
  echo "$CONFORMA_REGISTRY_PASS" | docker login quay.io --username "$CONFORMA_REGISTRY_USER" --password-stdin
}

for b in $BUNDLES; do
  # Find the git sha where the source files were last updated
  mapfile -t src_dirs < <(bundle_src_dirs "$b")
  last_update_sha=$(git log -n 1 --pretty=format:%h -- "${src_dirs[@]}")

  tag=git-$last_update_sha

  # Check all repositories to see if any need the bundle
  repos_needing_push=()
  all_repos_have_bundle=true

  for repo_prefix in $REPO_PREFIXES; do
    repo=$(repo_name "$b" "$repo_prefix")
    push_repo="${repo_prefix}$repo"
    
    # Login with correct credentials for tag checking
    if [[ "$push_repo" == *"enterprise-contract"* ]]; then
      ec_registry_login
    elif [[ "$push_repo" == *"conforma"* ]]; then
      conforma_registry_login
    fi
    
    skopeo_args=()
    if [[ $push_repo == *'localhost:'* ]]; then
      skopeo_args+=(--tls-verify=false)
    fi

    tag_found="$(
      {
        skopeo list-tags "${skopeo_args[@]}" "docker://${push_repo}" |
        jq --arg tag "${tag}" -r 'any(.Tags[]; . == $tag)';
      } || echo false
    )"
    
    if [[ "$tag_found" == 'true' ]]; then
      echo "Policy bundle $push_repo:$tag exists already"
    else
      echo "Policy bundle $push_repo:$tag needs to be pushed"
      repos_needing_push+=("$push_repo")
      all_repos_have_bundle=false
    fi
  done

  if [[ "$all_repos_have_bundle" == 'true' ]]; then
    echo "All repositories have bundle for $b:$tag, no push needed"
  else
    echo "Building and pushing policy bundle for $b:$tag to ${#repos_needing_push[@]} repositories"

    # Prepare a temp dir with the bundle's content
    tmp_dir=$(mktemp -d -t "ec-bundle-$b.XXXXXXXXXX")
    tmp_oci_dirs+=("${tmp_dir}")
    content_dir=$tmp_dir/$(bundle_subdir "$b")
    mkdir "${content_dir}"
    for d in "${src_dirs[@]}"; do
      cp -r "$d" "${content_dir}"
    done

    # Remove some files
    exclude_files=$(exclusions "$b")
    for f in $exclude_files; do
      find "${content_dir}" -name "$f" -delete
    done

    # Show the content
    cd "${tmp_dir}" || exit 1
    find . -type f

    # go.mod/go.sum files needs to be copied for go run to function
    cp "${ROOT_DIR}/go.mod" "${ROOT_DIR}/go.sum" "$tmp_dir"

    # Verify the selected sources can be compiled as one unit, e.g. "policy/lib" is included
    ${OPA} build "${src_dirs[@]}" --output /dev/null

    # Push to all repositories that need it
    for push_repo in "${repos_needing_push[@]}"; do
      echo "Pushing to $push_repo:$tag"
      
      # Login with the correct credentials for this repository
      if [[ "$push_repo" == *"enterprise-contract"* ]]; then
        ec_registry_login
      elif [[ "$push_repo" == *"conforma"* ]]; then
        conforma_registry_login
      fi
      
      ${ORAS} push "$push_repo:$tag" "${src_dirs[@]}" \
        --annotation "org.opencontainers.image.revision=${last_update_sha}"

      # Set the 'latest' tag
      skopeo_cp_args=()
      if [[ $push_repo == *'localhost:'* ]]; then
        skopeo_cp_args+=(--dest-tls-verify=false --src-tls-verify=false)
      fi
      $DRY_RUN_ECHO skopeo copy --quiet "docker://$push_repo:$tag" "docker://$push_repo:latest" "${skopeo_cp_args[@]}"
    done

    cd "${ROOT_DIR}"
  fi

done
