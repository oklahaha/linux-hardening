#!/usr/bin/env bash
# Arm an automatic rollback before a guarded fix (sshd, PAM, faillock, sudo, firewall):
#   sudo bash arm-rollback.sh [minutes]               snapshot; restore it in N minutes (default 10) unless cancelled
#   sudo systemctl stop hardening-rollback.timer       cancel, once the fix is verified
#   sudo systemctl start hardening-rollback.service    roll back now
# The snapshot holds /etc, the live firewall rules, and which ssh/firewall services were running.
# Rollback restores changed files, deletes files created since the snapshot (e.g. a new sudoers.d drop-in),
# returns those services to their earlier running state, then reloads the live firewall rules.
set -euo pipefail
export LC_ALL=C   # sort and comm must agree on order
ETC=${HARDENING_ETC:-/etc}                                  # overrides exist for tests only
STATE=${HARDENING_ROLLBACK_DIR:-/root/hardening-rollback}
FIREWALLS="ufw nftables firewalld"
SSH_UNITS="ssh.socket ssh sshd"   # Debian/Ubuntu: ssh (often socket-activated); RHEL/SUSE: sshd
[ -w "$ETC" ] || { echo "run with sudo" >&2; exit 77; }
# Arming and restoring never overlap, so a snapshot is never replaced while it is in use.
exec 9>"$STATE.lock"

# Live rules: nft sees everything nftables-based, iptables-nft included; without nft, use iptables-save per family.
# Legacy xtables live outside nftables, so they are captured as well whenever the legacy tools exist.
fw_backends() {
  if command -v nft >/dev/null; then echo nft
  else for t in iptables ip6tables; do command -v "$t-save" >/dev/null && command -v "$t-restore" >/dev/null && echo "$t"; done; fi
  for t in iptables ip6tables; do
    command -v "$t-legacy-save" >/dev/null && command -v "$t-legacy-restore" >/dev/null && echo "$t-legacy"
  done
  return 0
}
fw_load() {   # fw_load <backend> [--check]; nft applies flush + rules as one transaction
  case $1 in
    nft) { echo "flush ruleset"; cat "$STATE/nft.rules"; } | nft ${2:+-c} -f - ;;
    *) "$1-restore" ${2:+--test} < "$STATE/$1.rules" ;;
  esac
}

if [ "${1:-}" = restore ]; then
  flock 9
  failed=
  find "$ETC" -xdev -print0 | sort -z | comm -z -13 "$STATE/etc.list" - | xargs -0r rm -rf --
  tar -xzf "$STATE/etc.tgz" -C "$(dirname "$ETC")" || failed="$failed /etc"
  systemctl daemon-reload 2>/dev/null || true
  for s in $FIREWALLS; do   # start what ran before, stop what did not; the rules snapshot below then wins
    if grep -qx "$s" "$STATE/active"; then systemctl restart "$s" || failed="$failed $s"
    else systemctl stop "$s" 2>/dev/null || true; fi
  done
  while read -r b; do fw_load "$b" || failed="$failed $b-rules"; done < "$STATE/fw-backends"
  for s in $SSH_UNITS; do   # never stop ssh; only bring back what was running
    if grep -qx "$s" "$STATE/active"; then systemctl reload-or-restart "$s" || failed="$failed $s"; fi
  done
  [ -z "$failed" ] || { echo "ROLLBACK INCOMPLETE, failed:$failed (snapshot in $STATE)" >&2; exit 1; }
  echo "rolled back from $STATE"
  exit 0
fi

minutes=${1:-10}
[[ $minutes =~ ^[1-9][0-9]*$ ]] || { echo "bad minutes: $minutes" >&2; exit 64; }
flock -n 9 || { echo "another arm or restore is running" >&2; exit 75; }
# Never overwrite the snapshot an armed or running rollback depends on.
for u in hardening-rollback.timer hardening-rollback.service; do
  systemctl is-active --quiet "$u" && { echo "$u is active; cancel it or let it finish first" >&2; exit 75; }
done
systemctl reset-failed hardening-rollback.timer hardening-rollback.service 2>/dev/null || true

umask 077
rm -rf "$STATE"; mkdir -p "$STATE"
tar -czf "$STATE/etc.tgz" -C "$(dirname "$ETC")" "$(basename "$ETC")"
find "$ETC" -xdev -print0 | sort -z > "$STATE/etc.list"
for s in $FIREWALLS $SSH_UNITS; do systemctl is-active --quiet "$s" && echo "$s"; done > "$STATE/active" || true
fw_backends > "$STATE/fw-backends"
while read -r b; do
  case $b in nft) nft list ruleset ;; *) "$b-save" ;; esac > "$STATE/$b.rules"
  # Refuse to arm a rollback that could not put these rules back.
  fw_load "$b" --check >/dev/null || { echo "cannot reload the $b snapshot; refusing to arm" >&2; exit 70; }
done < "$STATE/fw-backends"
# Run a root-owned copy, so later edits to this repo cannot change what the timer executes.
install -m 700 "$0" "$STATE/rollback.sh"
systemd-run --unit=hardening-rollback --on-active="${minutes}min" bash "$STATE/rollback.sh" restore
echo "Rollback armed: /etc, firewall rules and ssh/firewall services are restored in $minutes min unless you run: sudo systemctl stop hardening-rollback.timer"
