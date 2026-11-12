# linux-hardening

An agent skill (SKILL.md standard: Claude Code, Codex CLI, Cursor, Copilot…) that scans a Linux server against a security standard, explains the results in plain language, and fixes only what you pick, without locking you out.

- **Scan first.** Recon and scans are read-only. Nothing changes until you ask for a fix and confirm it.
- **Real scanners decide.** [OpenSCAP](https://www.open-scap.org/) with [SCAP Security Guide](https://github.com/ComplianceAsCode/content) 0.1.82 (pinned, sha512-verified) for CIS, DISA STIG, NIST 800-171, PCI-DSS, HIPAA, ANSSI and more; [Lynis](https://cisofy.com/lynis/) for a general audit. The AI explains and prioritises; it never scores.
- **Smart Recon.** Before any change it maps running services, open ports, containers, VPNs and how you are connected, and shows which rules could break them.
- **Safe fixes.** One rule at a time, each one shown and confirmed. /etc is backed up first. For SSH, PAM, sudo and firewall rules, an automatic 10-minute rollback is armed: it restores /etc, the live firewall rules and the ssh/firewall services. It is cancelled only after a fresh SSH login and sudo both work. Docker/Kubernetes forwarding is left alone.
- **Small footprint.** Only Lynis and OpenSCAP are offered. ssh-audit, nmap, nikto, AIDE and ClamAV are suggested only when relevant, and only installed if you say yes.

Supported: Ubuntu 22.04/24.04/26.04, Debian 11–13, RHEL 8–10, Rocky 8/9 (with the distro's `scap-security-guide` package), AlmaLinux 9, CentOS Stream 9/10, Oracle Linux 7–10, Fedora, Amazon Linux 2023, SLES 12/15/16, openSUSE. Lynis works on all of them.

## Use

```
/hardening-scan            # recommends a standard and asks
/hardening-scan cis-l1     # also: cis-l2, stig, nist, lynis, pci-dss, hipaa
```

Or just say "scan this server" or "check CIS compliance". After the report you can say "fix the SSH issues", "fix all high severity" or "apply the quick wins".

`nist`: SSG has no NIST 800-53 profile for server distros. The skill says so and offers NIST 800-171 (RHEL family) or STIG instead.

Try it on a VM or a box you can reach from a console first.

## Install

Claude Code: `claude --plugin-dir /path/to/linux-hardening`. For other agents, copy `skills/linux-hardening/` into their skills directory.

The skill offers to install the scanners. To do it yourself:
- Debian/Ubuntu: `sudo apt-get install -y openscap-scanner lynis`
- RHEL family: `sudo dnf install -y openscap-scanner`, plus Lynis from EPEL
- SUSE: `sudo zypper install -y openscap-utils lynis`

See `skills/linux-hardening/references/distro-mapping.md`.

## Layout

```
skills/linux-hardening/
├── SKILL.md                  steps + safety rules
├── references/
│   ├── safety.md             guarantees, guarded-fix procedure, rollback, Docker
│   ├── distro-mapping.md     package managers, install commands, SSH unit, content source
│   └── standards.md          cis-l1/cis-l2/stig/nist/lynis -> profile
└── scripts/
    ├── recon.sh              read-only service/port/connection map
    ├── scan.sh               OpenSCAP: list profiles, full scan, re-check one rule
    ├── lynis.sh              Lynis audit / re-run one test
    ├── summary.py            score + failures for OpenSCAP or Lynis; print one rule's fix
    └── arm-rollback.sh       snapshot + timed automatic rollback for guarded fixes
commands/hardening-scan.md    the /hardening-scan slash command (Claude Code)
```

```bash
bash skills/linux-hardening/scripts/recon.sh
bash skills/linux-hardening/scripts/scan.sh                        # list standards for this distro
bash skills/linux-hardening/scripts/scan.sh <profile> [--rule <id>]
bash skills/linux-hardening/scripts/lynis.sh [--test <TEST-ID>]
python3 skills/linux-hardening/scripts/summary.py --fix <rule> fixes.sh
sudo bash skills/linux-hardening/scripts/arm-rollback.sh [minutes]
python3 -m unittest discover tests
```

Not included (later): remote/inventory scanning, scheduled scans, config templates. Fixes come from the upstream SSG remediations, so there are no hand-written templates to drift.
