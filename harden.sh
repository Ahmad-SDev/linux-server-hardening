#!/usr/bin/env bash
# harden.sh - baseline hardening for a fresh Debian 12 / Ubuntu 22.04+ server.
#
# What it does (each step can be skipped, see --help):
#   1. Installs security updates and turns on unattended upgrades
#   2. Creates a sudo admin user and copies root's SSH keys to it
#   3. Locks SSH down to keys only (refuses if no key is installed)
#   4. Sets a default-deny nftables firewall with the ports you allow
#   5. Adds fail2ban for SSH and safe kernel network settings
#
# Every config file is backed up first and sshd is validated before reload,
# so a typo cannot lock you out.
set -euo pipefail

SSH_PORT="${SSH_PORT:-22}"
ADMIN_USER="${ADMIN_USER:-}"
ALLOW_TCP="${ALLOW_TCP:-}"          # e.g. "80 443"
ALLOW_UDP="${ALLOW_UDP:-}"          # e.g. "51820"
DRY_RUN=0
SKIP=""

usage() {
  cat <<EOF
Usage: sudo ./harden.sh [options]

  --ssh-port N        SSH port to keep open (default: 22)
  --admin-user NAME   create a sudo user and give it root's SSH keys
  --allow-tcp "P ..." extra TCP ports to open (e.g. "80 443")
  --allow-udp "P ..." extra UDP ports to open
  --skip LIST         comma list of steps to skip: updates,user,ssh,firewall,fail2ban,sysctl
  --dry-run           print what would change, change nothing
  -h, --help          this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-port)   SSH_PORT="$2"; shift 2 ;;
    --admin-user) ADMIN_USER="$2"; shift 2 ;;
    --allow-tcp)  ALLOW_TCP="$2"; shift 2 ;;
    --allow-udp)  ALLOW_UDP="$2"; shift 2 ;;
    --skip)       SKIP="$2"; shift 2 ;;
    --dry-run)    DRY_RUN=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

log()  { printf '\e[1;34m[harden]\e[0m %s\n' "$*"; }
warn() { printf '\e[1;33m[warn]\e[0m %s\n' "$*" >&2; }
die()  { printf '\e[1;31m[error]\e[0m %s\n' "$*" >&2; exit 1; }
run()  { if (( DRY_RUN )); then echo "  would run: $*"; else "$@"; fi; }
skipped() { [[ ",$SKIP," == *",$1,"* ]]; }

backup() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  run cp -a "$f" "$f.bak.$(date +%Y%m%d%H%M%S)"
}

write_file() {   # write_file PATH MODE  (content on stdin)
  local path="$1" mode="$2" content
  content="$(cat)"
  if (( DRY_RUN )); then
    echo "  would write $path:"; sed 's/^/    | /' <<<"$content"; return
  fi
  backup "$path"
  install -m "$mode" /dev/null "$path"
  printf '%s\n' "$content" > "$path"
}

[[ $EUID -eq 0 ]] || die "run as root (sudo ./harden.sh)"
[[ -r /etc/os-release ]] && . /etc/os-release
[[ "${ID:-}" == "debian" || "${ID:-}" == "ubuntu" || "${ID_LIKE:-}" == *debian* ]] \
  || die "only Debian/Ubuntu are supported"
[[ "$SSH_PORT" =~ ^[0-9]+$ ]] || die "invalid SSH port: $SSH_PORT"
for p in $ALLOW_TCP $ALLOW_UDP; do [[ "$p" =~ ^[0-9]+$ ]] || die "invalid port: $p"; done

export DEBIAN_FRONTEND=noninteractive

# 1. Updates -----------------------------------------------------------------
if ! skipped updates; then
  log "Installing updates and security packages"
  run apt-get update -q
  run apt-get upgrade -yq
  run apt-get install -yq unattended-upgrades nftables fail2ban
  write_file /etc/apt/apt.conf.d/20auto-upgrades 0644 <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
fi

# 2. Admin user --------------------------------------------------------------
if [[ -n "$ADMIN_USER" ]] && ! skipped user; then
  [[ "$ADMIN_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "invalid user name: $ADMIN_USER"
  if id "$ADMIN_USER" &>/dev/null; then
    log "User $ADMIN_USER already exists"
  else
    log "Creating sudo user $ADMIN_USER"
    run adduser --disabled-password --gecos "" "$ADMIN_USER"
  fi
  run usermod -aG sudo "$ADMIN_USER"
  if [[ -s /root/.ssh/authorized_keys ]]; then
    home="$(getent passwd "$ADMIN_USER" | cut -d: -f6)"
    home="${home:-/home/$ADMIN_USER}"
    run install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" "$home/.ssh"
    run install -m 600 -o "$ADMIN_USER" -g "$ADMIN_USER" /root/.ssh/authorized_keys "$home/.ssh/authorized_keys"
  else
    warn "root has no authorized_keys; add a key for $ADMIN_USER before closing this session"
  fi
fi

# 3. SSH ---------------------------------------------------------------------
if ! skipped ssh; then
  has_key=0
  for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    [[ -s "$f" ]] && has_key=1
  done
  if (( ! has_key )); then
    warn "no SSH keys found on this server; leaving password login ON so you are not locked out"
  else
    log "SSH: keys only, port $SSH_PORT"
    root_login="prohibit-password"
    [[ -n "$ADMIN_USER" ]] && root_login="no"
    write_file /etc/ssh/sshd_config.d/10-hardening.conf 0644 <<EOF
Port $SSH_PORT
PermitRootLogin $root_login
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
    if (( ! DRY_RUN )); then
      sshd -t || die "sshd config test failed; nothing was reloaded"
      systemctl reload ssh 2>/dev/null || systemctl reload sshd
    fi
  fi
fi

# 4. Firewall ----------------------------------------------------------------
if ! skipped firewall; then
  log "Firewall: default deny inbound, allow SSH $SSH_PORT ${ALLOW_TCP:+tcp: $ALLOW_TCP }${ALLOW_UDP:+udp: $ALLOW_UDP}"
  tcp_ports="$(echo "$SSH_PORT $ALLOW_TCP" | xargs | tr ' ' ',')"
  udp_rule=""
  [[ -n "$ALLOW_UDP" ]] && udp_rule="    udp dport { $(echo "$ALLOW_UDP" | xargs | tr ' ' ',') } accept"
  write_file /etc/nftables.conf 0755 <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    ct state invalid drop
    iif "lo" accept
    meta l4proto { icmp, ipv6-icmp } limit rate 20/second accept
    tcp dport { $tcp_ports } ct state new accept
$udp_rule
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
  chain output {
    type filter hook output priority 0; policy accept;
  }
}
EOF
  if (( ! DRY_RUN )); then
    nft -c -f /etc/nftables.conf || die "nftables syntax check failed"
    systemctl enable --now nftables
    nft -f /etc/nftables.conf
  fi
fi

# 5. fail2ban + sysctl -------------------------------------------------------
if ! skipped fail2ban; then
  log "fail2ban: SSH jail"
  write_file /etc/fail2ban/jail.d/sshd.local 0644 <<EOF
[sshd]
enabled  = true
port     = $SSH_PORT
backend  = systemd
maxretry = 5
findtime = 10m
bantime  = 1h
banaction = nftables-multiport
EOF
  run systemctl enable --now fail2ban
  run systemctl restart fail2ban
fi

if ! skipped sysctl; then
  log "Kernel network hardening"
  write_file /etc/sysctl.d/90-hardening.conf 0644 <<'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
EOF
  run sysctl --system -q
fi

log "Done. Open a NEW SSH session on port $SSH_PORT to confirm access before closing this one."
