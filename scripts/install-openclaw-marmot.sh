#!/usr/bin/env bash
set -euo pipefail

# Install dm-agent and the OpenClaw Marmot channel plugin from a DM Agent GitHub
# release. OpenClaw itself must already be installed. Mirrors
# scripts/install-hermes-marmot.sh.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace_version_default="$(sed -n 's/^version = "\(.*\)"/\1/p' "$SCRIPT_DIR/../Cargo.toml" 2>/dev/null | head -n 1)"
workspace_version_default="${workspace_version_default:-latest}"

MARMOT_RELEASE_REPO="${MARMOT_RELEASE_REPO:-marmot-protocol/darkmatter}"
DM_AGENT_VERSION_DEFAULT="${DM_AGENT_VERSION_DEFAULT:-$workspace_version_default}"
DM_AGENT_VERSION="${DM_AGENT_VERSION:-$DM_AGENT_VERSION_DEFAULT}"
MARMOT_RELEASE_TAG_DEFAULT="${MARMOT_RELEASE_TAG_DEFAULT:-dm-agent-v${DM_AGENT_VERSION}}"
MARMOT_RELEASE_TAG="${MARMOT_RELEASE_TAG:-$MARMOT_RELEASE_TAG_DEFAULT}"
MARMOT_INSTALL_PREFIX="${MARMOT_INSTALL_PREFIX:-${HOME}/.local}"
MARMOT_HOME="${MARMOT_HOME:-${HOME}/.marmot-agent}"
MARMOT_RELAYS="${MARMOT_RELAYS:-wss://relay.eu.whitenoise.chat,wss://relay.us.whitenoise.chat}"
PLUGIN_PACKAGE="${PLUGIN_PACKAGE:-openclaw-marmot-plugin-${DM_AGENT_VERSION}.tgz}"
INSTALL_BOOTSTRAP=0
DRY_RUN=0

usage() {
    cat <<'USAGE'
Usage: install-openclaw-marmot.sh [options]

Install dm-agent and the OpenClaw Marmot channel plugin from a DM Agent GitHub
release. OpenClaw must already be installed and `openclaw` on PATH.

Options:
  --bootstrap   After install, start dm-agent and run `dm-agent bootstrap --qr`
  --dry-run     Print actions without installing
  -h, --help    Show this help

Environment:
  MARMOT_RELEASE_REPO   GitHub repo (default: marmot-protocol/darkmatter)
  MARMOT_RELEASE_TAG    Release tag (default: dm-agent-v<version>)
  DM_AGENT_VERSION      Asset version suffix
  MARMOT_INSTALL_PREFIX Install root for dm-agent (default: ~/.local)
  MARMOT_HOME           dm-agent home used by bootstrap (default: ~/.marmot-agent)
USAGE
}

log() { printf 'install-openclaw-marmot: %s\n' "$*"; }
run() {
    if [ "$DRY_RUN" -eq 1 ]; then printf '[dry-run] '; printf '%q ' "$@"; printf '\n'; return 0; fi
    "$@"
}
need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }; }

while [ $# -gt 0 ]; do
    case "$1" in
        --bootstrap) INSTALL_BOOTSTRAP=1; shift;;
        --dry-run) DRY_RUN=1; shift;;
        -h|--help) usage; exit 0;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2;;
    esac
done

need_cmd curl
need_cmd openclaw

os="$(uname -s)"; arch="$(uname -m)"
case "$os/$arch" in
    Linux/x86_64) dm_asset="dm-agent-linux-x86_64-${DM_AGENT_VERSION}.tar.gz";;
    Darwin/arm64) dm_asset="dm-agent-darwin-aarch64-${DM_AGENT_VERSION}.tar.gz";;
    *) echo "unsupported platform: $os/$arch" >&2; exit 1;;
esac

base_url="https://github.com/${MARMOT_RELEASE_REPO}/releases/download/${MARMOT_RELEASE_TAG}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# dm-agent ships as a versioned tar.gz bundle (dm-agent-<platform>/dm-agent).
log "downloading dm-agent bundle ($dm_asset)"
run curl -fsSL "$base_url/$dm_asset" -o "$tmp/$dm_asset"
run tar -xzf "$tmp/$dm_asset" -C "$tmp"
run install -d "$MARMOT_INSTALL_PREFIX/bin"
run install -m 0755 "$tmp"/dm-agent-*/dm-agent "$MARMOT_INSTALL_PREFIX/bin/dm-agent"

log "downloading OpenClaw Marmot plugin ($PLUGIN_PACKAGE)"
run curl -fsSL "$base_url/$PLUGIN_PACKAGE" -o "$tmp/$PLUGIN_PACKAGE"

log "installing the plugin into OpenClaw"
run openclaw plugins install "$tmp/$PLUGIN_PACKAGE"
run openclaw plugins enable marmot || log "could not auto-enable; run 'openclaw plugins enable marmot'"

log "installed dm-agent to $MARMOT_INSTALL_PREFIX/bin and the marmot plugin into OpenClaw"

if [ "$INSTALL_BOOTSTRAP" -eq 1 ]; then
    relay_args=()
    IFS=',' read -ra relays <<< "$MARMOT_RELAYS"
    for relay in "${relays[@]}"; do relay_args+=(--relay "$relay"); done
    log "starting dm-agent and bootstrapping the agent account"
    run "$MARMOT_INSTALL_PREFIX/bin/dm-agent" --home "$MARMOT_HOME" "${relay_args[@]}" &
    sleep 2
    run "$MARMOT_INSTALL_PREFIX/bin/dm-agent" bootstrap --home "$MARMOT_HOME" --qr
fi
