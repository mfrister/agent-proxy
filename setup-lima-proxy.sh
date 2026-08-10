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
    DEST=/usr/local/share/ca-certificates/mitmproxy-ca.crt
    if [[ -f "$DEST" ]] && cmp -s "$SRC" "$DEST"; then
      echo "CA cert already installed at $DEST — skipping."
    else
      sudo cp "$SRC" "$DEST"
      sudo update-ca-certificates
      echo "CA cert installed at $DEST."
    fi
  elif command -v update-ca-trust &>/dev/null; then
    # RHEL / Fedora / CentOS
    DEST=/etc/pki/ca-trust/source/anchors/mitmproxy-ca.crt
    if [[ -f "$DEST" ]] && cmp -s "$SRC" "$DEST"; then
      echo "CA cert already installed at $DEST — skipping."
    else
      sudo cp "$SRC" "$DEST"
      sudo update-ca-trust extract
      echo "CA cert installed at $DEST."
    fi
  else
    echo "Warning: unknown distro — cert copied to /tmp/mitmproxy-ca.pem but not installed system-wide." >&2
    echo "Install it manually for your distro." >&2
    exit 0
  fi

  rm -f "$SRC"
'

# ── Step 3: Configure system-wide proxy env ─────────────────────────────────
echo "--> Writing /etc/profile.d/proxy.sh inside VM..."
limactl shell "$VM_NAME" -- bash -c "
  set -euo pipefail
  DEST=/etc/profile.d/proxy.sh
  TMP=\$(mktemp)
  cat > \"\$TMP\" <<'EOF'
# mitmproxy — set by setup-lima-proxy.sh
export HTTP_PROXY=http://host.lima.internal:${PROXY_PORT}
export HTTPS_PROXY=http://host.lima.internal:${PROXY_PORT}
export http_proxy=http://host.lima.internal:${PROXY_PORT}
export https_proxy=http://host.lima.internal:${PROXY_PORT}
export NO_PROXY=localhost,127.0.0.1,host.lima.internal
export no_proxy=localhost,127.0.0.1,host.lima.internal
export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/mitmproxy-ca.crt
EOF
  if [[ -f \"\$DEST\" ]] && cmp -s \"\$TMP\" \"\$DEST\"; then
    echo 'Proxy env already up to date at /etc/profile.d/proxy.sh — skipping.'
  else
    sudo cp \"\$TMP\" \"\$DEST\"
    sudo chmod 644 \"\$DEST\"
    echo 'Proxy env written to /etc/profile.d/proxy.sh'
  fi
  rm -f \"\$TMP\"
"

# ── Step 4: Configure system-service proxy env via systemd drop-in ──────────
# /etc/profile.d is only sourced for login/interactive shells; systemd services
# (notably the Docker daemon) do not read it. A DefaultEnvironment drop-in on the
# systemd manager makes every system service inherit the proxy in one place.
echo "--> Writing /etc/systemd/system.conf.d/proxy.conf inside VM..."
limactl shell "$VM_NAME" -- bash -c "
  set -euo pipefail
  DEST=/etc/systemd/system.conf.d/proxy.conf
  TMP=\$(mktemp)
  cat > \"\$TMP\" <<'EOF'
# mitmproxy — set by setup-lima-proxy.sh
[Manager]
DefaultEnvironment=\"HTTP_PROXY=http://host.lima.internal:${PROXY_PORT}\" \"HTTPS_PROXY=http://host.lima.internal:${PROXY_PORT}\" \"http_proxy=http://host.lima.internal:${PROXY_PORT}\" \"https_proxy=http://host.lima.internal:${PROXY_PORT}\" \"NO_PROXY=localhost,127.0.0.1,host.lima.internal\" \"no_proxy=localhost,127.0.0.1,host.lima.internal\"
EOF
  if [[ -f \"\$DEST\" ]] && cmp -s \"\$TMP\" \"\$DEST\"; then
    echo 'systemd proxy env already up to date at /etc/systemd/system.conf.d/proxy.conf — skipping.'
    rm -f \"\$TMP\"
  else
    sudo mkdir -p /etc/systemd/system.conf.d
    sudo cp \"\$TMP\" \"\$DEST\"
    sudo chmod 644 \"\$DEST\"
    rm -f \"\$TMP\"
    echo 'systemd proxy env written to /etc/systemd/system.conf.d/proxy.conf; reloading systemd manager...'
    sudo systemctl daemon-reexec
    # Restart the daemon only if running, so it picks up the new env now.
    # (A stopped/absent docker inherits the env on its next start.)
    if systemctl is-active --quiet docker; then
      echo 'Restarting docker to pick up proxy env...'
      sudo systemctl restart docker
    fi
  fi
"

# ── Step 5: Write proxy guidance into ~/.claude/CLAUDE.md inside the VM ──────
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

  # Confirm system services (e.g. the Docker daemon) inherited the proxy env
  tr '\0' '\n' < /proc/\$(pgrep -x dockerd)/environ | grep -i proxy

Note: proxy env is configured in two complementary places —
  /etc/profile.d/proxy.sh            login/interactive shells
  /etc/systemd/system.conf.d/proxy.conf  all systemd services (incl. dockerd), via DefaultEnvironment
'systemctl show-environment' does not reflect DefaultEnvironment; check a running
service's own environ (as above) to confirm.
EOF
