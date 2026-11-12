#!/usr/bin/env bash
# Arm an automatic rollback before a guarded fix (sshd, PAM, faillock, sudo, firewall):
#   sudo bash arm-rollback.sh [minutes]               snapshot; restore it in N minutes (default 10) unless cancelled
#   sudo systemctl stop hardening-rollback.timer       cancel, once the fix is verified
#   sudo systemctl start hardening-rollback.service    roll back now
# The snapshot holds /etc, the live firewall rules and ipsets, pam_faillock tallies, and which ssh/firewall
# services were running. Rollback restores changed files, moves files created since the snapshot (e.g. a new
# sudoers.d drop-in) aside, resets login-failure tallies, returns those services to their earlier running
# state, then reloads the live firewall rules.
set -euo pipefail
export LC_ALL=C   # sort and comm must agree on order
ETC=${HARDENING_ETC:-/etc}                                  # overrides exist for tests only
STATE=${HARDENING_ROLLBACK_DIR:-/root/hardening-rollback}
FAILLOCK=${HARDENING_FAILLOCK:-/run/faillock}               # pam_faillock tallies live outside /etc
PROC=${HARDENING_PROC:-/proc}
FIREWALLS="ufw nftables firewalld"
SSH_UNITS="ssh.socket ssh sshd"   # Debian/Ubuntu: ssh (often socket-activated); RHEL/SUSE: sshd
PARENT=$(dirname "$ETC") BASE=$(basename "$ETC")
[ -w "$ETC" ] || { echo "run with sudo" >&2; exit 77; }
# Arming and restoring never overlap, so a snapshot is never replaced while it is in use.
exec 9>"$STATE.lock"

etc_list() { (cd "$PARENT" && find "$BASE" -xdev -print0 | sort -z); }   # paths relative to $PARENT

# Live rules: nft sees everything nftables-based, iptables-nft included; without nft, use iptables-save per family.
# Legacy xtables live outside nftables: capture them via the -legacy tools, or a generic iptables that is legacy.
fw_backends() {
  if command -v nft >/dev/null; then echo nft
  else for t in iptables ip6tables; do command -v "$t-save" >/dev/null && command -v "$t-restore" >/dev/null && echo "$t"; done; fi
  for t in iptables ip6tables; do
    if command -v "$t-legacy-save" >/dev/null && command -v "$t-legacy-restore" >/dev/null; then echo "$t-legacy"
    elif command -v nft >/dev/null && command -v "$t-save" >/dev/null && command -v "$t-restore" >/dev/null \
      && "$t" -V 2>/dev/null | grep -q legacy; then echo "$t"; fi
  done
  return 0
}
fw_load() {   # fw_load <backend> [--check]; nft applies flush + rules as one transaction
  local rules
  case $1 in
    nft) rules=$(cat "$STATE/nft.rules") || return 1   # never send "flush ruleset" without the full snapshot
         printf 'flush ruleset\n%s\n' "$rules" | nft ${2:+-c} -f - ;;
    *) "$1-restore" ${2:+--test} < "$STATE/$1.rules" ;;
  esac
}
# Legacy restore rewrites only the tables named in the snapshot; empty any table a fix loaded since.
fw_reset_new_tables() {
  local names=$PROC/net/ip_tables_names t c
  case $1 in ip6*) names=$PROC/net/ip6_tables_names ;; esac
  [ -r "$names" ] && "$1" -V 2>/dev/null | grep -q legacy || return 0
  for t in $(cat "$names"); do
    grep -qx "\*$t" "$STATE/$1.rules" && continue
    for c in $("$1" -t "$t" -S | awk '$1=="-P"{print $2}'); do "$1" -t "$t" -P "$c" ACCEPT; done
    "$1" -t "$t" -F && "$1" -t "$t" -X
  done
}

if [ "${1:-}" = restore ]; then
  flock 9
  umask 077
  # A manual run must not leave the timer to run a second restore over repairs made afterwards.
  systemctl stop hardening-rollback.timer 2>/dev/null || true
  failed=
  # Paths created since arming are moved aside, not deleted (a package may have added them meanwhile).
  # Children first and never recursive, so a filesystem mounted under /etc is left alone: rmdir just fails.
  removed=$STATE.removed-$(date +%Y%m%d-%H%M%S)
  while IFS= read -r -d '' p; do
    if [ -d "$PARENT/$p" ] && [ ! -L "$PARENT/$p" ]; then rmdir -- "$PARENT/$p"
    else mkdir -p "$removed/$(dirname "$p")" && mv -- "$PARENT/$p" "$removed/$p"; fi || failed="$failed $p"
  done < <(etc_list | comm -z -13 "$STATE/etc.list" - | sort -rz)
  tar -xzf "$STATE/etc.tgz" -C "$PARENT" || failed="$failed /etc"
  # Failed logins during the window would keep the admin locked out (faillock deny=, unlock_time=0).
  if [ -d "$FAILLOCK" ]; then
    { find "$FAILLOCK" -mindepth 1 -delete && { [ ! -f "$STATE/faillock.tgz" ] || tar -xzf "$STATE/faillock.tgz" -C "$FAILLOCK"; }; } \
      || failed="$failed faillock"
  fi
  systemctl daemon-reload 2>/dev/null || true
  for s in $FIREWALLS; do   # start what ran before, stop what did not; the rules snapshot below then wins
    if grep -qx "$s" "$STATE/active"; then systemctl restart "$s" || failed="$failed $s"
    else systemctl stop "$s" 2>/dev/null || true; fi
  done
  if [ -f "$STATE/ipset.rules" ]; then   # rules that match an ipset allowlist need its members back first
    { for s in $(ipset list -n); do grep -q "^create $s " "$STATE/ipset.rules" && ipset flush "$s"; done
      ipset restore -exist < "$STATE/ipset.rules"; } || failed="$failed ipset"
  fi
  while read -r b; do
    { [ "$b" = nft ] || fw_reset_new_tables "$b"; } && fw_load "$b" || failed="$failed $b-rules"
  done < "$STATE/fw-backends"
  for s in $SSH_UNITS; do   # never stop ssh; restart, not reload, so restored unit files and arguments apply
    if grep -qx "$s" "$STATE/active"; then systemctl restart "$s" || failed="$failed $s"; fi
  done
  [ -z "$failed" ] || { echo "ROLLBACK INCOMPLETE, failed:$failed (snapshot in $STATE)" >&2; exit 1; }
  echo "rolled back from $STATE${removed:+; files created since arming, if any, are in $removed}"
  exit 0
fi

minutes=${1:-10}
[[ $minutes =~ ^[1-9][0-9]*$ ]] || { echo "bad minutes: $minutes" >&2; exit 64; }
flock -n 9 || { echo "another arm or restore is running" >&2; exit 75; }
# Never overwrite the snapshot an armed or running rollback depends on.
for u in hardening-rollback.timer hardening-rollback.service; do
  systemctl is-active --quiet "$u" && { echo "$u is active; cancel it or let it finish first" >&2; exit 75; }
done
# The rollback restarts sshd from this config, so it must be valid now.
if [ -f "$ETC/ssh/sshd_config" ] && command -v sshd >/dev/null; then
  sshd -t -f "$ETC/ssh/sshd_config" || { echo "sshd -t fails on the current config; fix it first, or the rollback would restore a broken sshd; refusing to arm" >&2; exit 70; }
fi
systemctl reset-failed hardening-rollback.timer hardening-rollback.service 2>/dev/null || true

umask 077
rm -rf "$STATE"; mkdir -p "$STATE"
etc_list > "$STATE/etc.list"
# Archive exactly the listed paths, so the archive and the list describe the same moment.
# Exit 1 means a file changed while being read; it is still archived.
tar -czf "$STATE/etc.tgz" --ignore-failed-read -C "$PARENT" --null --no-recursion -T "$STATE/etc.list" || [ $? -eq 1 ]
if [ -d "$FAILLOCK" ]; then tar -czf "$STATE/faillock.tgz" -C "$FAILLOCK" .; fi
if command -v ipset >/dev/null; then ipset save > "$STATE/ipset.rules"; fi
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
