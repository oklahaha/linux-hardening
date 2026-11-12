#!/usr/bin/env bash
# Smart Recon: what runs on this machine and what a hardening fix could break. Read-only: changes nothing.
# Uses sudo -n only where it adds detail (process names, sshd port); works without it.
set -uo pipefail
section() { printf '\n== %s\n' "$1"; }

section "System"
(. /etc/os-release; echo "$PRETTY_NAME (ID=$ID VERSION_ID=${VERSION_ID:-})")
echo "kernel $(uname -r), virtualization: $(systemd-detect-virt 2>/dev/null || echo none)"

section "How the user is connected"
client=${SSH_CONNECTION:-}; client=${client%% *}
# Reported only as a hint: the route back to the client is not proof of the whole management path
# (a VPN can ride on Wi-Fi, routing can be asymmetric), so network changes always need console access.
dev=
if [ -n "$client" ]; then
  echo "SSH from $client"
  dev=$(ip route get "$client" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)
  [ "$dev" = lo ] && { echo "client is local: the session arrives through a local tunnel/proxy (e.g. cloudflared), whose real path is unknown"; dev=; }
else
  echo "no SSH_CONNECTION: the session may be a console, a detached agent, a VPN or a tunnel; the path is unknown"
fi
echo "route-to-client interface: ${dev:-unknown} (a hint, not proof of the full management path)"
case $dev in tun*|tap*|wg*|tailscale*|zt*|ppp*|ipsec*|vti*|gre*|br*|bond*|vlan*|*.*)
  echo "WARNING: $dev is a tunnel/bridge/virtual link; the physical link underneath it is unknown" ;; esac
echo "default route interface: $(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1) (not proof of how the user connects)"
if [ -n "$dev" ] && [ -d "/sys/class/net/$dev/wireless" ]; then
  echo "WARNING: the route to the client is wireless; wireless_* / network interface fixes will cut it"
fi
port=$(sudo -n sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | head -1)
echo "sshd port: ${port:-$(grep -hsiE '^\s*Port\s' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf | awk '{print $2}' | head -1)}${port:+ (from sshd -T)}"

section "Login dependencies (rules that disable these can stop logins)"
grep -hE '^\s*(passwd|group|shadow):' /etc/nsswitch.conf 2>/dev/null
for s in autofs sssd nslcd ypbind winbind nfs-client.target rpcbind; do systemctl is-active --quiet "$s" && echo "$s: active"; done
for d in /home "${HOME:-/root}"; do echo "$d is on: $(findmnt -n -o FSTYPE,SOURCE -T "$d" 2>/dev/null)"; done
awk -F: '$7 !~ /(nologin|false)$/ && $3 >= 1000 {print $6}' /etc/passwd | while read -r h; do
  t=$(findmnt -n -o FSTYPE -T "$h" 2>/dev/null); case $t in nfs*|cifs|autofs|fuse.sshfs) echo "home $h is on $t";; esac
done

section "Listening ports"
sudo -n ss -tulpnH 2>/dev/null || ss -tulnH

section "Running services"
running=$(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}')
echo "$running" | paste -sd' '

section "Firewall"
for s in ufw nftables firewalld; do systemctl is-active --quiet "$s" && echo "$s: active"; done
command -v iptables >/dev/null && echo "iptables: $(iptables -V 2>/dev/null)"

section "Containers"
for c in docker podman; do
  command -v "$c" >/dev/null || continue
  echo "$c installed; running containers:"
  sudo -n "$c" ps --format '  {{.Names}}  {{.Ports}}' 2>/dev/null || echo "  (needs sudo to list)"
done

section "Detected roles (rules that may conflict)"
has() { echo "$running" | grep -qE "^($1)\.service$"; }
has 'nginx|apache2|httpd|caddy|lighttpd'           && echo "web server: firewall rules must keep 80/443 open; Nikto can be offered"
has 'mysql|mysqld|mariadb|postgresql.*|mongod|redis.*' && echo "database: firewall rules must keep its port reachable for its clients"
has 'docker|containerd|podman'                     && echo "containers: keep net.ipv4.ip_forward=1; firewall changes can drop Docker's chains"
has 'kubelet|k3s|rke2-server|rke2-agent'           && echo "kubernetes: ip_forward, br_netfilter and firewall rules are load-bearing"
has 'libvirtd|virtqemud'                           && echo "VM host: bridge/forwarding sysctls are load-bearing"
has 'gdm|gdm3|lightdm|sddm'                        && echo "desktop: workstation profiles fit better than server ones"
has 'tailscaled|cloudflared|wg-quick@.*|openvpn.*|zerotier-one' && echo "VPN/tunnel: the user may reach this box through it; firewall/network rules must keep it working"
has 'NetworkManager'                              && echo "NetworkManager: network_* rules can change how interfaces come up"
exit 0
