# Distro mapping

`/etc/os-release` decides everything. `scan.sh` maps it to SCAP content by itself; this table is for installing tools and for service names.

| Distro (ID) | Packages | Install OpenSCAP | Install Lynis | SCAP content | SSH unit |
|---|---|---|---|---|---|
| Ubuntu 22.04/24.04/26.04 (`ubuntu`), Debian 11–13 (`debian`) | apt | `sudo apt-get install -y openscap-scanner` | `sudo apt-get install -y lynis` | pinned upstream SSG (automatic) | `ssh` (often socket-activated) |
| RHEL 8–10 (`rhel`), AlmaLinux 9 (`almalinux`), CentOS Stream 9/10 (`centos`), Oracle Linux 7–10 (`ol`) | dnf (`yum` on 7) | `sudo dnf install -y openscap-scanner` | from EPEL: `sudo dnf install -y epel-release` (RHEL: the EPEL release RPM), then `sudo dnf install -y lynis` | pinned upstream SSG (automatic) | `sshd` |
| Rocky Linux 8/9 (`rocky`) | dnf | `sudo dnf install -y openscap-scanner` | EPEL, as above | **Rocky's own package:** `sudo dnf install -y scap-security-guide`. Upstream SSG has no Rocky content; `scan.sh` uses `/usr/share/xml/scap/ssg/content/ssg-rl<N>-ds.xml` only if it is root-owned and not group/world-writable. | `sshd` |
| Fedora (`fedora`) | dnf | `sudo dnf install -y openscap-scanner` | `sudo dnf install -y lynis` | pinned upstream SSG | `sshd` |
| Amazon Linux 2023 (`amzn`) | dnf | `sudo dnf install -y openscap-scanner` | not packaged; skip Lynis or use CISOfy's repo if the user asks | pinned upstream SSG | `sshd` |
| SLES 12/15/16 (`sles`), openSUSE (`opensuse-*`) | zypper | `sudo zypper install -y openscap-utils` | `sudo zypper install -y lynis` | pinned upstream SSG | `sshd` |

Not covered: Amazon Linux 2 and anything `scan.sh` refuses. Lynis still works there.

Why pinned upstream SSG instead of the distro package: it is newer, the same version on every distro, and sha512-verified on every run. The distro package is the fallback only where upstream has no content (Rocky).

## Supplementary tools (never install by default)

Offer one only when the context calls for it, and install only after the user says yes.

| Tool | Offer when | apt | dnf (EPEL on RHEL family) |
|---|---|---|---|
| ssh-audit | the user asks about SSH ciphers/kex, or SSH findings dominate | `ssh-audit` | `ssh-audit` (or `pipx install ssh-audit`) |
| nmap | the user wants an outside view of open ports | `nmap` | `nmap` |
| nikto | recon found a web server **and** the user agrees | `nikto` | `nikto` |
| AIDE | a failed rule asks for file integrity monitoring, or the user asks | `aide` | `aide` |
| ClamAV | only if the user asks | `clamav` | `clamav clamav-update` |
