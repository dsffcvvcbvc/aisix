#!/bin/sh
# Container entrypoint for aisix.
#
# Picks the config file based on CAVORA_CONFIG_PATH (default
# /etc/aisix/config.yaml). Two intended modes:
#
#   Standalone — operator mounts their own config:
#       docker run -v ./config.yaml:/etc/aisix/config.yaml ghcr.io/api7/aisix:dev
#
#   Managed (connected to AISIX Cloud) — use the baked-in template + env vars:
#       docker run \
#         -e CAVORA_CONFIG_PATH=/etc/aisix/config.managed.yaml \
#         -e CAVORA_MANAGED__CP_BASE_URL \
#         -e CAVORA_MANAGED__CP_ETCD_ENDPOINT \
#         -e CAVORA_MANAGED__CP_CERT_PEM \
#         -e CAVORA_MANAGED__CP_KEY_PEM \
#         -e CAVORA_MANAGED__CP_CA_PEM \
#         -v aisix-mtls:/var/lib/aisix \
#         ghcr.io/api7/aisix:dev
# The volume preserves the materialized mTLS bundle and gateway identity across
# container restarts.
#
# The Rust binary's `Config::load_from_path` already layers
# `CAVORA_<UPPER>__<UPPER>` env vars on top of the YAML, so any field
# is reachable without re-templating the file.

set -eu

CONFIG_PATH="${CAVORA_CONFIG_PATH:-/etc/aisix/config.yaml}"

if [ ! -f "$CONFIG_PATH" ]; then
    echo "aisix-entrypoint: config file not found at $CONFIG_PATH" >&2
    echo "aisix-entrypoint: mount one at /etc/aisix/config.yaml or set" >&2
    echo "aisix-entrypoint: CAVORA_CONFIG_PATH=/etc/aisix/config.managed.yaml" >&2
    exit 64
fi

exec /usr/local/bin/cavora --config "$CONFIG_PATH"
