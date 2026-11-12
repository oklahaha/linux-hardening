---
name: linux-hardening
description: Scan a Linux server against a security standard (CIS Level 1/2, DISA STIG, NIST 800-171, PCI-DSS, HIPAA and others via OpenSCAP, or a Lynis audit), give a scored plain-language report, and fix only the findings the user picks, with confirmation, backups, validation and automatic rollback so SSH access is never lost. Use for "scan this server", "check CIS compliance", "harden this box", "/hardening-scan cis-l1", or follow-ups like "fix the SSH issues" or "fix all high severity". Works on Ubuntu, Debian, RHEL, Rocky, AlmaLinux, CentOS Stream, Oracle Linux, Fedora, Amazon Linux 2023 and SUSE.
---

# Linux hardening

## When to use

- The user wants to know how secure or compliant this Linux machine is: "scan this server", "check CIS compliance", "audit with Lynis", or `/hardening-scan [standard]`.
- The user asks to fix findings from such a scan: "fix the SSH issues", "fix all high severity", "apply the quick wins".

Do not use it for remote machines (this skill scans the machine it runs on), for container images, or for application code.

## Safety rules (always)

1. **Scan first.** Scanning and recon change nothing. Never modify the system unless the user explicitly asks for a fix.
2. **Show, explain, confirm.** Before any change, show the exact commands and what they affect on *this* machine, then wait for a yes. Each RISKY or guarded rule needs its own yes.
3. **Never lock out SSH.** Rules touching SSH, PAM, sudo, passwords or the firewall follow the guarded procedure in `references/safety.md`: a root shell kept open, an automatic rollback armed, validation, and a fresh-login test.
4. **Back up before modifying, validate before reloading.** Run `sshd -t` before reloading sshd, `visudo -c` after sudo changes.
5. **Install nothing without asking.** Only Lynis and OpenSCAP are offered by default. Other tools are offered only when the context calls for them (see `references/distro-mapping.md`).
6. **The scanner decides compliance**, not you. Never edit results to change a score. Never run the whole `fixes.sh`.

Paths below are relative to this file's directory. Talk to the user in their language.

## 1. Detect and check tools

- Read `/etc/os-release`. Look up the package manager, install commands and SSH unit name in `references/distro-mapping.md`.
- `command -v oscap lynis`. If the requested engine is missing, show the install command for this distro and ask before running it. If no engine was requested yet, offer Lynis and OpenSCAP only.

## 2. Smart Recon

```bash
bash scripts/recon.sh
```

It is read-only. It reports:
- how the user is connected: the SSH client, and the interface on the route back to it. That interface is a hint only; network changes always need console access.
- login dependencies: `nsswitch.conf` sources, autofs/SSSD/NIS/LDAP, and where home directories live
- the SSH port, listening ports, running services and the firewall
- containers, and roles detected from the services: web server, database, Docker or Kubernetes, VM host, VPN/tunnel, desktop

Show the user a short **service impact table**:

| Service / port | Why it matters | Rules to be careful with |
|---|---|---|
| sshd :22 | your access | sshd_*, PAM, firewall |
| docker :3000 | published container | ip_forward, firewall |

Then ask: "Is there anything I must not touch, or a port that other machines need that I did not list (backups, monitoring, a cron job that connects in)?" Recon only sees what is running right now. Add the answers to the table.

Keep it for triage and fixes.

## 3. Pick the standard

If the user gave one (as a slash-command argument like `cis-l1`, `cis-l2`, `nist`, `stig`, `lynis`, or in words), map it with `references/standards.md`. For OpenSCAP that means:
- Run `bash scripts/scan.sh` with no profile to list this distro's profiles.
- Match the user's words to a **title**.
- Ask if more than one title matches.

If none was given, recommend one as `standards.md` says and ask.

## 4. Scan

- OpenSCAP: `bash scripts/scan.sh <profile>`
- Lynis: `bash scripts/lynis.sh`

Both need sudo, take a few minutes, and write a private `hardening-reports/<timestamp>-<name>/` in the current directory. Then each prints a summary:

```
Score: 68.4/100                                      (OpenSCAP)
Failed rules (severity | rule | flags | title):
high    | grub2_password | RISKY | Set Boot Loader Password in grub2

Hardening index: 62/100                              (Lynis)
Warnings (test | flags | finding | details):
SSH-7408 | RISKY | Root login is permitted | PermitRootLogin=yes
```

Flags:
- `RISKY`: can lock the user out, cut the network, break services or halt the box.
- `CHECK-DEPS`: disables a service, removes a package or blacklists a module. It is safe only if recon shows nothing uses it (see `references/safety.md`).
- `no-auto-fix`: no upstream fix; explain the manual fix from `report.html`.
- `ERROR`: the check itself failed. Do not count it as non-compliant.

OpenSCAP also writes `report.html` (the full official report) and `fixes.sh` (upstream fixes, one block per rule).

## 5. Report

Do not paste raw output. Give:
1. The score, and the counts by severity.
2. **High-risk failures first.** For each, one line on what it means, plus its impact on this machine from the recon table.
3. The rest grouped as:
   - **Quick wins**: not RISKY, has a fix, and, if flagged `CHECK-DEPS`, recon shows the service, package or module is unused. Examples: banners, file permissions, unused kernel modules, non-network sysctls.
   - **Needs a decision**: RISKY rules, each with what would break here. Examples: `ip_forward` breaks Docker; password max age can expire a key-only user and block SSH; `partition_*` needs repartitioning; `wireless_*` cuts a Wi-Fi link.
   - **Probably not applicable**: rules that conflict with the machine's role. Suggest recording them as exceptions with a reason.
4. A suggested order, quick wins first.

Then stop and wait. Do not fix anything until the user asks.

## 6. Remediate what the user asks for

Selecting:
- "Fix the SSH issues": rules matching `sshd_`/`ssh_` (Lynis: `SSH-`).
- "Fix all high severity": the high rows.
- "Quick wins": that group.

Show the selected list and confirm it. RISKY and guarded rules inside a group still get their own yes.

Once per session, back up /etc. It holds `/etc/shadow` and host keys, so root writes it to a new file in a root-only directory, never into the report tree:

```bash
sudo sh -c 'umask 077 && mkdir -p /root/hardening-backups && f=/root/hardening-backups/etc-$(date +%Y%m%d-%H%M%S).tgz && set -C && tar -czf - /etc > "$f" && echo "$f"'
```

It prints the backup path; tell the user. `set -C` makes the write fail rather than overwrite or follow an existing file.

Then, one rule at a time:

1. **Show** the commands.
   - OpenSCAP: `python3 scripts/summary.py --fix <rule> hardening-reports/<dir>/fixes.sh`
   - Lynis: write the smallest command that fixes the finding.

   Explain in plain words what changes and what it can affect here. Get the yes.
2. **Apply.** Save the commands to a file.
   - Guarded rule (auth or firewall): follow the guarded procedure in `references/safety.md`. It arms the rollback and applies the fix in one line.
   - Network-interface or wireless rule: always needs confirmed console access (`references/safety.md`).
   - Rule that disables or removes a login dependency, or is flagged `CHECK-DEPS`: follow `references/safety.md`. That includes the reinstall command for a package removal.
   - Anything else: `sudo bash <file>`.
3. **Validate and verify.**
   - `sshd -t` / `visudo -c` where relevant.
   - Re-check: `bash scripts/scan.sh <profile> --rule <rule>` must print `Result pass`. For Lynis: `bash scripts/lynis.sh --test <TEST-ID>`.
   - For guarded rules: the fresh-login test, then cancel the rollback.
4. **On failure**, report the error. For a guarded rule, roll it back. Then continue with the next rule. Stop the whole session only if a lockout check fails.

Never batch RISKY rules. Never touch grub passwords, partitions, or `auditd` halt/single actions unless the user names that rule.

## 7. Health check and rescan

Run `bash scripts/recon.sh` again and compare its "Listening ports" and "Running services" with the first run. PIDs change on restart, so match ports and service names, not lines. Anything that was there before and is gone counts as broken by a fix. Report it first, find which rule caused it, and offer to undo that rule (see "Recovery" in `references/safety.md`).

Then run the same scan again. Show:
- the score before and after
- what was fixed
- what is still open and why: exception, needs a decision, no auto-fix, or failed
