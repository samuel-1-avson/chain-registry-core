#!/usr/bin/env bash
# Source sepolia-3node.env, stripping UTF-8 BOM if present (Windows PowerShell utf8).
# Usage: creg_source_sepolia_env "/path/to/sepolia-3node.env"
creg_source_sepolia_env() {
  local env_file="$1"
  if [[ ! -f "$env_file" ]]; then
    echo "Missing $env_file" >&2
    return 1
  fi
  # shellcheck disable=SC1090
  source <(sed '1s/^\xEF\xBB\xBF//' "$env_file")
}
