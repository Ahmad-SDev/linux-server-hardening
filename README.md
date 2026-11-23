# linux-server-hardening

One script that takes a fresh **Debian 12 / Ubuntu 22.04+** server to a sane, secure baseline in about a minute. Written for the servers I hand over to customers, where a lockout is not an option.

## What it does

| Step | Change |
|---|---|
| `updates` | Installs updates, turns on unattended security upgrades |
| `user` | Creates a sudo admin user and copies root's SSH keys to it |
| `ssh` | Keys only, no passwords, short login window, optional custom port |
| `firewall` | nftables, default deny inbound, only the ports you allow |
| `fail2ban` | Bans IPs that keep failing SSH logins (nftables backend) |
| `sysctl` | SYN cookies, no redirects or source routing, logs martians |

## Safety first

- **Will not lock you out.** If no SSH key is installed, password login stays on and you get a warning.
- **Validated before applying.** `sshd -t` and `nft -c` must pass before anything reloads.
- **Backups.** Every file it touches is copied to `*.bak.<timestamp>` first.
- **Dry run.** `--dry-run` prints every command and file without changing anything.

## Usage

```bash
curl -fsSLO https://raw.githubusercontent.com/Ahmad-SDev/linux-server-hardening/main/harden.sh
chmod +x harden.sh

# See what would change
sudo ./harden.sh --dry-run --admin-user deploy --allow-tcp "80 443"

# Apply
sudo ./harden.sh --admin-user deploy --ssh-port 2222 --allow-tcp "80 443"
```

Skip any step with `--skip`, for example `--skip firewall,sysctl` on a host that already has its own firewall.

> After it finishes, open a **new** SSH session to confirm you can still log in before closing the current one.

## License

MIT
