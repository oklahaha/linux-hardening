# Standards: what the user says → what to run

Two engines:
- **OpenSCAP** (`scripts/scan.sh <profile>`) does formal compliance against a benchmark. It reports a pass/fail score out of 100 and comes with upstream fixes.
- **Lynis** (`scripts/lynis.sh`) is a general hygiene audit. It reports a hardening index out of 100 and suggestions, but no automatic fixes.

The two scores measure different things. Never compare or average them.

OpenSCAP profile ids differ between distros, so never hard-code them. Run `bash scripts/scan.sh` with no profile to list this machine's profiles with titles, then match the user's words to a **title**.

| User says | Engine | Pick |
|---|---|---|
| `cis-l1`, "CIS", "CIS level 1" | OpenSCAP | Title with "CIS" + "Level 1". Choose Server or Workstation from what recon found (desktop service → Workstation). Ubuntu: `cis_level1_server`; RHEL family: `cis_server_l1`. |
| `cis-l2`, "CIS level 2" | OpenSCAP | Title with "Level 2". On the RHEL family, the Level 2 Server profile id is plain `cis`. |
| `stig`, "DISA STIG" | OpenSCAP | `stig`, or `stig_gui` on a machine with a desktop |
| `nist`, "NIST 800-53" | OpenSCAP | **SSG has no NIST 800-53 profile for server distros** (only OpenShift/CoreOS). Say so. The closest options: NIST 800-171 (`cui`) on RHEL 8/9, CentOS Stream 9, Oracle Linux 8/9; or `stig`, whose rules map to 800-53 controls. Let the user choose; never relabel 800-171 as 800-53. |
| `lynis`, "quick audit", "hygiene" | Lynis | `bash scripts/lynis.sh` |
| `pci`, `pci-dss` | OpenSCAP | `pci-dss` (RHEL family) |
| `hipaa`, `anssi`, `e8` / Essential Eight, `ism`, `bsi`, `ccn`, `ospp` | OpenSCAP | Match by title; RHEL family has most of these. |

When the user names no standard: recommend CIS Level 1 (Server or Workstation, from recon) when the distro has it, otherwise Lynis. Ask before running.

When a standard is missing on this distro (Ubuntu has only CIS and STIG), say so and offer what the list does have, plus Lynis.
