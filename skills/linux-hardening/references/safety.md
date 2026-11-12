# Safety guarantees and how they are kept

| Guarantee | How |
|---|---|
| Nothing changes without a yes | Scanning and recon are read-only. Every fix is shown first, explained, and needs a confirmation; each RISKY or guarded rule needs its own yes. |
| Never lock out the current SSH session | Guarded rules run only with a root shell open elsewhere, a firewall pre-check, an armed automatic rollback, and a fresh-login test before the rollback is cancelled. |
| Always back up before modifying | A backup of /etc at the start of a fix session, created by root under `/root/hardening-backups/` (never in the caller's report tree); a fresh snapshot right before every guarded rule. |
| Validate before reloading | `sshd -t` before reloading sshd, `visudo -c` after sudo changes, and a dry-run reload of firewall rules before arming. |
| Continue on non-critical failures | A fix that errors or does not pass its re-check is recorded and skipped; the session moves on. A failed lockout check stops the session. |
| Dependencies checked first | Rules that disable services, remove packages or blacklist modules are flagged `CHECK-DEPS` and need recon evidence that nothing uses them; login-carrying services (autofs, NIS, SSSD, LDAP, NFS) are RISKY. |
| Preserve Docker networking | Recon detects Docker/Kubernetes/VM hosts; their forwarding and firewall rules are never treated as quick wins. |
| Untrusted inputs | SCAP content is sha512-verified on each run (or, for distro content, must be root-owned and not writable by others); root writes only into a private temp dir. |

## Rule categories

**Guarded** (rollback + fresh-login test):
- **auth:** sshd, PAM, faillock, password ageing, login.defs, sudo
- **firewall:** ufw, nftables, iptables, firewalld, including `service_*_enabled`

**Out-of-band only.** The rollback cannot undo these: network interfaces, wireless (`wireless_disable_interfaces`), `network_*`, kernel modules for the NIC in use, IPv6 disable. Before one of these:
- Always require the user to confirm working console or out-of-band access (serial/web console, physical keyboard, IPMI) before applying it. No exceptions: recon's "route-to-client interface" is only a hint. A VPN or tunnel can ride on Wi-Fi, and routing can be asymmetric, so it never proves a change will not cut the session.
- Still treat the rule as RISKY and get its own yes.

**Login dependencies.** Some services and packages carry logins or home directories: autofs, NIS/ypbind, SSSD, nslcd/LDAP, winbind, NFS, rpcbind, Kerberos. Rules that disable or remove them are flagged RISKY. Before one:
- Check recon's "Login dependencies" section. If `nsswitch.conf` uses `nis`, `sss`, `ldap` or `winbind`, or any login home is on NFS/autofs/CIFS, the rule would break logins. Record it as an exception.
- Otherwise, follow the guarded procedure, including the fresh-login test.

**CHECK-DEPS rules** (`service_*_disabled`, `package_*_removed`, `kernel_module_*_disabled`) are quick wins only when recon shows the thing is not in use:
- the service is not running
- no listening port belongs to it
- the module is not loaded (`lsmod`)

Package removal is not undone by the rollback. The plan you show must include the reinstall command (for example `sudo apt-get install -y <pkg>`), so the user can recover.

**Ask by name only.** grub passwords, partitioning, `auditd` halt/single actions.

## Guarded fix procedure

1. Get the yes for this rule.
2. Ask the user to keep a root shell (`sudo -i`) open in a separate terminal until the rule is verified. On a cloud VM, also confirm they can reach the serial or web console.
3. Firewall rule: find the SSH port with `sudo sshd -T | awk '$1=="port"{print $2}'`. Confirm the ruleset the fix will load allows it:
   - ufw: `sudo ufw show added`
   - nftables: `/etc/nftables.conf`
   - firewalld: `sudo firewall-cmd --permanent --list-all`

   Also check every port recon showed as needed: web, database, and VPN/tunnel such as tailscale or wireguard. If something needed is not allowed, stop. Add an allow rule first (with the user's OK), or skip the rule.
4. Arm and apply in one line:
   ```bash
   sudo bash scripts/arm-rollback.sh && systemctl is-active --quiet hardening-rollback.timer && sudo timeout 120 bash <fix-file>
   ```
   The fix runs only while the rollback is armed, and is killed if it runs past 2 minutes. If arming prints `refusing to arm`, either the firewall rules could not be saved in a reloadable form, or `sshd -t` fails on the current config (the rollback would restore a broken sshd). Do not apply the rule; fix the cause first.
5. Validate:
   - `sudo visudo -c` if sudo changed.
   - `sudo sshd -t`, then `sudo systemctl reload ssh` (Debian/Ubuntu) or `sshd` (others), if sshd changed.
6. Ask the user to open a **new** SSH session, keeping the others open. Login and `sudo -k && sudo true` must work. For auth rules, `sudo chage -l <user>` must not show an expired or soon-expiring password.
7. All good: `sudo systemctl stop hardening-rollback.timer`. Anything wrong: do not cancel. Run `sudo systemctl start hardening-rollback.service`, from the root shell if sudo is broken, or let the timer fire.

What the rollback (`scripts/arm-rollback.sh`, fires after 10 minutes) restores:
- /etc as it was. Files created since arming are moved to `/root/hardening-rollback.removed-<time>/`, not deleted: a package may have added them during the window. Nothing is removed recursively, so a filesystem mounted under /etc is never touched.
- pam_faillock tallies as they were, so failed logins during the window do not keep anyone locked out
- the ssh and firewall services that were running, restarted even if the fix stopped them (ssh is restarted, not reloaded, so restored unit files apply); the ones that were not running are stopped
- ipset members, then the live firewall rules exactly as they were: nftables, iptables-nft, and legacy iptables v4/v6 (legacy tables loaded since arming are emptied)

It stops its own timer first, so starting it by hand never leads to a second run later.

One failing step does not stop the others. It ends with `ROLLBACK INCOMPLETE, failed: …` if any part fails. Then show the user `sudo journalctl -u hardening-rollback` and fix it from the root shell.

## Recovery

Use this when a fix broke something and no rollback is armed: a non-guarded rule, or the timer was already cancelled.

- Restore only the files the rule touched, from the session backup. The fix block shows which files those are.
  ```bash
  sudo tar -tzf /root/hardening-backups/etc-<time>.tgz | grep <name>          # find the path
  sudo tar -xzf /root/hardening-backups/etc-<time>.tgz -C / etc/ssh/sshd_config
  ```
  Do not restore all of /etc. That also reverts every other change made since the backup, including package updates.
- A file the fix created (for example a new `sysctl.d` or `modprobe.d` drop-in) is not in the backup. Delete it by hand.
- Then reload what uses the file: `sysctl --system`, `sshd -t && systemctl reload <ssh unit>`, `systemctl restart <service>`.
- A removed package: reinstall it with the command from the fix plan.
- Locked out of SSH: use the serial or web console. Restore the file there as shown above, then restart the ssh unit.

## Docker, Kubernetes, VM hosts

When recon reports containers, Kubernetes or a VM host:
- `sysctl_net_ipv4_ip_forward` and other forwarding/bridge sysctls: **not applicable**. Record them as exceptions; never fix them as quick wins.
- Firewall rules: enabling nftables or ufw can flush Docker's chains. If the user still wants one, follow the guarded procedure, then `sudo systemctl restart docker`. Confirm every port recon listed for a container still answers.
- Kernel module blacklists (`overlay`, `br_netfilter`): treat as RISKY on these hosts.

## Lynis findings

Lynis gives suggestions, not fix scripts. To fix one:
- Write the smallest command that does it and show it.
- Explain the impact.
- Get the yes.
- Back up the files it touches (`sudo cp -a <file> <file>.bak-$(date +%s)`).

Lynis tests marked RISKY (AUTH, SSH, FIRE, NETW, BOOT, ACCT) follow the guarded procedure. Verify with `bash scripts/lynis.sh --test <TEST-ID>`: it runs the full audit (tests depend on earlier ones) and prints only that test's remaining findings. It fails (exit 70) if Lynis did not actually run that test, for example because a profile skips it. A missing test is never a pass.

`lynis.sh` runs Lynis from a root-owned empty directory, so a `custom.prf` or `include/` in the caller's directory cannot change or skip tests. Profiles are read only from Lynis's system locations (`/etc/lynis`).
