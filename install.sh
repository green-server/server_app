#!/usr/bin/env bash
# Green Server agent installer.
#
#   curl -fsSL <url>/install.sh | sudo GREENSERVER_TOKEN=<token> bash -s -- \
#     --server wss://host/ws/agent --services nginx,minecraft
#
# The token is read from the environment so it stays out of ps output.
set -euo pipefail

RELEASE_URL="https://github.com/green-server/server_app/releases/latest/download"
ACCOUNT="greenserver"
HOME_DIR="/var/lib/greenserver"
STATE_DIR="$HOME_DIR/state"
BIN="/usr/local/bin/greenserver"
CONF_DIR="/etc/greenserver"
UNIT="/etc/systemd/system/greenserver.service"
ROOT_UNIT="/etc/systemd/system/greenserver-root.service"
SUDOERS="/etc/sudoers.d/greenserver"
TMPFILES="/etc/tmpfiles.d/greenserver-rapl.conf"

die() { echo "greenserver install: $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: GREENSERVER_TOKEN=<token> install.sh --server URL [options]

  --server URL        backend URL, wss://host/ws/agent (required)
  --services a,b      systemd services the AI may stop, start and restart
                      after your approval. Empty means none.
  --idle-watts N      estimated watts at 0% CPU, for hosts without RAPL
  --max-watts N       estimated watts at 100% CPU, for hosts without RAPL
  --binary PATH       install this binary instead of downloading a release
  --grant-key KEY     backend public key; with --server-id, installs the root
                      helper so root commands can be allowed from the browser
  --server-id N       id of this server on the backend
EOF
}

# A service name ends up in a sudoers rule, so only plain names pass, and
# nothing that could lock the owner out or switch off the agent.
valid_service() {
  [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9_.@-]*$ ]] || return 1
  case "${1%.service}" in
    ssh|sshd|openssh*|dropbear|firewalld|ufw|nftables|iptables|ip6tables|fail2ban) return 1 ;;
    greenserver|sudo|networking|NetworkManager|systemd-networkd|systemd-resolved) return 1 ;;
  esac
}

main() {
  local server="" services="" idle_watts="" max_watts="" binary="" grant_key="" server_id=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --server)     server="${2:?}"; shift 2 ;;
      --services)   services="${2:-}"; shift 2 ;;
      --idle-watts) idle_watts="${2:?}"; shift 2 ;;
      --max-watts)  max_watts="${2:?}"; shift 2 ;;
      --binary)     binary="${2:?}"; shift 2 ;;
      --grant-key)  grant_key="${2:?}"; shift 2 ;;
      --server-id)  server_id="${2:?}"; shift 2 ;;
      -h|--help)    usage; exit 0 ;;
      *)            usage >&2; die "unknown option: $1" ;;
    esac
  done

  [[ $(id -u) -eq 0 ]] || die "run as root"
  [[ $(uname -s) == Linux ]] || die "only Linux is supported"
  command -v systemctl >/dev/null || die "systemd is required"
  command -v visudo >/dev/null || die "sudo is required"
  # Only characters with no meaning in a systemd unit, where $ and % expand.
  [[ $server =~ ^wss://[A-Za-z0-9._:/-]+$ ]] || die "--server must be a plain wss:// URL"
  [[ -n ${GREENSERVER_TOKEN:-} ]] || die "set GREENSERVER_TOKEN"
  [[ $GREENSERVER_TOKEN != *$'\n'* ]] || die "invalid GREENSERVER_TOKEN"
  local n
  for n in "$idle_watts" "$max_watts"; do
    [[ -z $n || $n =~ ^[0-9]+(\.[0-9]+)?$ ]] || die "watts must be a number: $n"
  done

  [[ -z $grant_key || $grant_key =~ ^[A-Za-z0-9+/]{43}=$ ]] || die "--grant-key must be a base64 public key"
  [[ -z $server_id || $server_id =~ ^[0-9]+$ ]] || die "--server-id must be a number"
  [[ -z $grant_key && -z $server_id || -n $grant_key && -n $server_id ]] || die "--grant-key and --server-id go together"

  local -a service_list=()
  if [[ -n $services ]]; then
    IFS=',' read -r -a service_list <<<"$services"
  fi
  local s
  for s in "${service_list[@]+"${service_list[@]}"}"; do
    valid_service "$s" || die "refusing service: $s"
  done

  # Everything that can fail on input has now been checked.
  create_account
  install_binary "$binary"
  install_env
  install_rapl_access
  install_sudoers "${service_list[@]+"${service_list[@]}"}"
  install_unit "$server" "$idle_watts" "$max_watts"
  if [[ -n $grant_key ]]; then
    install_root_helper "$grant_key" "$server_id"
  fi

  systemctl daemon-reload
  systemctl enable greenserver.service >/dev/null 2>&1
  systemctl restart greenserver.service
  if [[ -n $grant_key ]]; then
    systemctl enable greenserver-root.service >/dev/null 2>&1
    systemctl restart greenserver-root.service
  fi

  cat <<EOF

greenserver is running. Check it with: systemctl status greenserver

For AI consulting, install Claude Code for the $ACCOUNT account, then pick one:
  subscription: sudo -u $ACCOUNT -H claude /login
  API key:      add ANTHROPIC_API_KEY=... to $CONF_DIR/env and restart

To change which services can be managed, run this installer again.
EOF
}

create_account() {
  if ! id "$ACCOUNT" >/dev/null 2>&1; then
    # A real shell because Claude's Bash tool needs one. The password stays
    # locked, so nobody can log in with it.
    useradd --system --create-home --home-dir "$HOME_DIR" --shell /bin/bash "$ACCOUNT"
  fi
  passwd -l "$ACCOUNT" >/dev/null
  install -d -o "$ACCOUNT" -g "$ACCOUNT" -m 0750 "$HOME_DIR"
  install -d -o "$ACCOUNT" -g "$ACCOUNT" -m 0700 "$STATE_DIR"
}

install_binary() {
  local src="$1" tmp arch
  if [[ -n $src ]]; then
    [[ -f $src ]] || die "no such binary: $src"
    install -o root -g root -m 0755 "$src" "$BIN"
    return
  fi
  case "$(uname -m)" in
    x86_64)  arch=amd64 ;;
    aarch64) arch=arm64 ;;
    *)       die "unsupported architecture: $(uname -m)" ;;
  esac
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064 # expand now: tmp is local and gone by exit time
  trap "rm -rf '$tmp'" EXIT
  curl -fsSL -o "$tmp/greenserver-linux-$arch" "$RELEASE_URL/greenserver-linux-$arch"
  curl -fsSL -o "$tmp/greenserver-linux-$arch.sha256" "$RELEASE_URL/greenserver-linux-$arch.sha256"
  (cd "$tmp" && sha256sum -c --quiet "greenserver-linux-$arch.sha256") || die "checksum mismatch"
  install -o root -g root -m 0755 "$tmp/greenserver-linux-$arch" "$BIN"
}

# Root-owned: systemd reads this file, the greenserver account cannot.
install_env() {
  local previous=""
  install -d -o root -g root -m 0755 "$CONF_DIR"
  if [[ -f $CONF_DIR/env ]]; then
    previous="$(grep -v '^GREENSERVER_TOKEN=' "$CONF_DIR/env" || true)"
  fi
  (
    umask 077
    {
      printf 'GREENSERVER_TOKEN=%s\n' "$GREENSERVER_TOKEN"
      if [[ -n $previous ]]; then
        printf '%s\n' "$previous"
      fi
    } >"$CONF_DIR/env.tmp"
  )
  mv "$CONF_DIR/env.tmp" "$CONF_DIR/env"
}

# The kernel keeps energy_uj root-only (CVE-2020-8694). The agent needs it to
# report measured power, so only its own group gets read access. Without this
# it still runs, but estimates.
install_rapl_access() {
  cat >"$TMPFILES" <<EOF
z /sys/class/powercap/intel-rapl:*/energy_uj 0440 root $ACCOUNT -
z /sys/class/powercap/intel-rapl:*:*/energy_uj 0440 root $ACCOUNT -
EOF
  systemd-tmpfiles --create "$TMPFILES" 2>/dev/null || true
}

# The OS-level limit, so it holds even if every layer above it fails.
#
# Arguments are exact: no wildcards, because in sudoers '*' also matches
# spaces, which would let "stop x ssh" through. Service names come from the
# owner's --services list.
#
# Deliberately not here, because each one is root by another name:
#   crontab  'sudo crontab file' installs root's crontab. The agent uses its
#            own crontab, which needs no sudo.
#   sed, tee, cp, editors  can write any file, including this one. Config
#            edits work only on files the owner made writable for greenserver.
install_sudoers() {
  local tmp systemctl_bin tool s
  tmp="$(mktemp)"
  systemctl_bin="$(command -v systemctl)"
  {
    echo "# Managed by the greenserver installer. Re-run it to change this file."
    echo "Defaults:$ACCOUNT !requiretty"
    for s in "$@"; do
      printf '%s ALL=(root) NOPASSWD: %s stop %s, %s start %s, %s restart %s\n' \
        "$ACCOUNT" "$systemctl_bin" "$s" "$systemctl_bin" "$s" "$systemctl_bin" "$s"
    done
    if tool="$(command -v cpupower)"; then
      for s in powersave schedutil ondemand conservative performance; do
        printf '%s ALL=(root) NOPASSWD: %s frequency-set -g %s\n' "$ACCOUNT" "$tool" "$s"
      done
    fi
    if tool="$(command -v powerprofilesctl)"; then
      for s in power-saver balanced performance; do
        printf '%s ALL=(root) NOPASSWD: %s set %s\n' "$ACCOUNT" "$tool" "$s"
      done
    fi
  } >"$tmp"
  if ! visudo -cf "$tmp" >/dev/null; then
    rm -f "$tmp"
    die "generated sudoers file is invalid, nothing was changed"
  fi
  install -o root -g root -m 0440 "$tmp" "$SUDOERS"
  rm -f "$tmp"
}

install_unit() {
  local server="$1" idle_watts="$2" max_watts="$3"
  local args="run --server $server --state-dir $STATE_DIR"
  if [[ -n $idle_watts ]]; then args+=" --idle-watts $idle_watts"; fi
  if [[ -n $max_watts ]]; then args+=" --max-watts $max_watts"; fi
  cat >"$UNIT" <<EOF
[Unit]
Description=Green Server agent
Wants=network-online.target
After=network-online.target

[Service]
User=$ACCOUNT
Group=$ACCOUNT
EnvironmentFile=$CONF_DIR/env
Environment=PATH=$HOME_DIR/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WorkingDirectory=$HOME_DIR
ExecStart=$BIN $args
Restart=always
RestartSec=5
UMask=0077
# NoNewPrivileges and ProtectSystem stay off on purpose: they would break the
# sudo whitelist and approved config edits for the Claude child process.

[Install]
WantedBy=multi-user.target
EOF
}

# Runs as root, but only accepts commands the backend signed after the owner
# allowed them in the browser, and only from a short list. See internal/priv.
install_root_helper() {
  cat >"$ROOT_UNIT" <<EOF
[Unit]
Description=Green Server root helper
After=network-online.target docker.service

[Service]
ExecStart=$BIN root-helper --public-key $1 --server-id $2
RuntimeDirectory=greenserver-root
RuntimeDirectoryMode=0750
Restart=always
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
}

# Calling main last means a truncated download cannot run half a script.
main "$@"
