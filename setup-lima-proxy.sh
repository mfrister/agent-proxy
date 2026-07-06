#!/usr/bin/env bash
# setup-lima-proxy.sh — Copy the mitmproxy CA into a Lima VM and configure it
# as the system-wide HTTP/HTTPS proxy pointing at the macOS host.
#
# Usage: ./setup-lima-proxy.sh [<vm-name>] [--proxy-port <port>]
#   vm-name     Lima VM name (default: default)
#   --proxy-port  mitmproxy port on the macOS host (default: 8080)

set -euo pipefail

# ── Defaults ────────────────────────────────────────────────────────────────
VM_NAME="default"
PROXY_PORT="8080"
CA_CERT="${HOME}/.mitmproxy/mitmproxy-ca-cert.pem"

# ── Arg parsing ─────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --proxy-port)
      PROXY_PORT="$2"; shift 2 ;;
    --proxy-port=*)
      PROXY_PORT="${1#*=}"; shift ;;
    -*)
      echo "Unknown option: $1" >&2; exit 1 ;;
    *)
      VM_NAME="$1"; shift ;;
  esac
done

# ── Preflight checks ────────────────────────────────────────────────────────
if ! command -v limactl &>/dev/null; then
  echo "Error: limactl not found. Install Lima first: brew install lima" >&2
  exit 1
fi

if [[ ! -f "$CA_CERT" ]]; then
  echo "Error: CA cert not found at $CA_CERT" >&2
  echo "Run mitmproxy at least once to generate the cert:" >&2
  echo "  uv run mitmdump -s addon.py" >&2
  exit 1
fi

if ! limactl list "$VM_NAME" &>/dev/null; then
  echo "Error: Lima VM '$VM_NAME' not found." >&2
  echo "Available VMs:" >&2
  limactl list 2>/dev/null || true
  exit 1
fi

echo "==> Configuring Lima VM '$VM_NAME' to use mitmproxy on host:${PROXY_PORT}"

# ── Step 1: Copy the CA cert into the VM ────────────────────────────────────
echo "--> Copying CA cert into VM..."
limactl copy "$CA_CERT" "${VM_NAME}:/tmp/mitmproxy-ca.pem"

# ── Step 2: Install the cert into the system trust store ────────────────────
echo "--> Installing CA cert in VM trust store..."
limactl shell "$VM_NAME" -- bash -c '
  set -euo pipefail
  SRC=/tmp/mitmproxy-ca.pem

  if command -v update-ca-certificates &>/dev/null && [[ -d /usr/local/share/ca-certificates ]]; then
    # Debian / Ubuntu / Alpine
    sudo cp "$SRC" /usr/local/share/ca-certificates/mitmproxy-ca.crt
    sudo update-ca-certificates
  elif command -v update-ca-trust &>/dev/null; then
    # RHEL / Fedora / CentOS
    sudo cp "$SRC" /etc/pki/ca-trust/source/anchors/mitmproxy-ca.crt
    sudo update-ca-trust extract
  else
    echo "Warning: unknown distro — cert copied to /tmp/mitmproxy-ca.pem but not installed system-wide." >&2
    echo "Install it manually for your distro." >&2
    exit 0
  fi

  rm -f "$SRC"
  echo "CA cert installed."
'

# ── Step 3: Configure system-wide proxy env ─────────────────────────────────
echo "--> Writing /etc/profile.d/proxy.sh inside VM..."
limactl shell "$VM_NAME" -- bash -c "
  sudo tee /etc/profile.d/proxy.sh > /dev/null <<'EOF'
# mitmproxy — set by setup-lima-proxy.sh
export HTTP_PROXY=http://host.lima.internal:${PROXY_PORT}
export HTTPS_PROXY=http://host.lima.internal:${PROXY_PORT}
export http_proxy=http://host.lima.internal:${PROXY_PORT}
export https_proxy=http://host.lima.internal:${PROXY_PORT}
export NO_PROXY=localhost,127.0.0.1,host.lima.internal
export no_proxy=localhost,127.0.0.1,host.lima.internal
export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/mitmproxy-ca.crt
EOF
  sudo chmod 644 /etc/profile.d/proxy.sh
  echo 'Proxy env written to /etc/profile.d/proxy.sh'
"

# ── Step 4: Write proxy guidance into ~/.claude/CLAUDE.md inside the VM ──────
echo "--> Writing proxy guidance into ~/.claude/CLAUDE.md inside VM..."
limactl shell "$VM_NAME" -- bash -c '
  set -euo pipefail
  CLAUDE_MD="${HOME}/.claude/CLAUDE.md"
  MARKER="## Network / Proxy"

  mkdir -p "${HOME}/.claude"
  touch "$CLAUDE_MD"

  if grep -qF "$MARKER" "$CLAUDE_MD"; then
    echo "Proxy guidance already present in $CLAUDE_MD — skipping."
    exit 0
  fi

  # Separate from any existing content with a blank line.
  if [[ -s "$CLAUDE_MD" ]]; then
    printf "\n" >> "$CLAUDE_MD"
  fi

  cat >> "$CLAUDE_MD" <<'"'"'EOF'"'"'
## Network / Proxy

This sandbox sits behind an HTTP(S) proxy that requires manual approval
for each outbound HTTPS request. Expect intermittent 503s while approval
is pending — this is normal, not a failure.

- On a 503 (from WebFetch or from `curl`/`wget`/any HTTP client in shell
  commands), retry automatically every 5-10 seconds for up to 5 minutes
  before giving up and reporting the failure.
- Don'"'"'t treat a single 503 as fatal — it usually just means the proxy
  approval hasn'"'"'t come through yet.
- When constructing shell commands that hit HTTPS endpoints, use the
  system CA store (see below) rather than `-k`/`--insecure`, since the
  proxy performs TLS interception.
EOF

  echo "Proxy guidance written to $CLAUDE_MD"
'

# ── Done ─────────────────────────────────────────────────────────────────────
cat <<EOF

==> Done! Lima VM '$VM_NAME' is configured to proxy through host:${PROXY_PORT}.

To verify inside the VM (open a new shell so /etc/profile.d is sourced):
  limactl shell $VM_NAME

  # Check env
  env | grep -i proxy

  # Test HTTPS trust + routing (requires mitmproxy running on the host)
  curl -sv https://api.anthropic.com 2>&1 | grep -E "SSL|issuer|subject|HTTP/"

  # Or with openssl
  openssl s_client -connect api.anthropic.com:443 2>&1 | grep "Verify return code"
  # Expected: Verify return code: 0 (ok)

Note: /etc/profile.d/proxy.sh is sourced for login/interactive shells.
For systemd services or non-login processes, set the env vars in the unit file or
/etc/environment instead.
EOF
