import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills", "linux-hardening", "scripts"))
import summary  # noqa: E402

P = "xccdf_org.ssgproject.content_rule_"
RESULTS = f"""<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="b">
  <Rule id="{P}sshd_use_strong_macs" severity="medium"><title>Use Only Strong MACs</title></Rule>
  <Rule id="{P}grub2_password" severity="high"><title>Set Boot Loader Password</title></Rule>
  <Rule id="{P}banner_etc_issue" severity="low"><title>Banner</title></Rule>
  <TestResult id="t">
    <rule-result idref="{P}banner_etc_issue" severity="low"><result>fail</result></rule-result>
    <rule-result idref="{P}sshd_use_strong_macs" severity="medium"><result>fail</result></rule-result>
    <rule-result idref="{P}grub2_password" severity="high"><result>fail</result></rule-result>
    <rule-result idref="{P}other" severity="low"><result>pass</result></rule-result>
    <score maximum="100">25.0</score>
  </TestResult>
</Benchmark>"""
FIXES = f"""#!/usr/bin/env bash
# BEGIN fix (1 / 2) for '{P}banner_etc_issue'
echo banner
# END fix for '{P}banner_etc_issue'
# BEGIN fix (2 / 2) for '{P}sshd_use_strong_macs'
echo macs
# END fix for '{P}sshd_use_strong_macs'
"""


class SummaryTest(unittest.TestCase):
    def setUp(self):
        f = tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False)
        f.write(RESULTS)
        f.close()
        self.path = f.name

    def tearDown(self):
        os.unlink(self.path)

    def test_summary_sorts_by_severity_and_flags(self):
        lines = summary.summarise(self.path, FIXES).splitlines()
        self.assertEqual(lines[0], "Score: 25.0/100")
        self.assertEqual(lines[1], "Results: fail=3, pass=1")
        rows = lines[4:]
        self.assertEqual([r.split(" | ")[1] for r in rows],
                         ["grub2_password", "sshd_use_strong_macs", "banner_etc_issue"])
        self.assertIn("RISKY,no-auto-fix", rows[0])
        self.assertIn("| RISKY |", rows[1])
        self.assertIn("| - |", rows[2])

    def test_fix_block_per_rule(self):
        blocks = summary.fix_blocks(FIXES)
        self.assertEqual(blocks["sshd_use_strong_macs"].strip(), "echo macs")
        self.assertEqual(set(blocks), {"banner_etc_issue", "sshd_use_strong_macs"})

    def test_network_cutting_rules_are_risky(self):
        for rule in ("wireless_disable_interfaces", "network_nmcli_permissions", "sysctl_net_ipv4_ip_forward"):
            self.assertTrue(summary.risky(rule), rule)
        self.assertFalse(summary.risky("banner_etc_issue"))

    def test_user_and_log_shipping_rules_are_risky(self):
        # Found on Ubuntu 24.04 CIS L1: these had no flag and landed in quick wins.
        for rule in ("file_cron_allow_exists", "file_at_allow_exists",
                     "systemd_journal_upload_url", "systemd_journal_upload_server_tls"):
            self.assertTrue(summary.risky(rule), rule)

    def test_login_dependencies_are_risky_and_removals_need_dep_check(self):
        for rule in ("service_autofs_disabled", "package_nis_removed", "service_sssd_disabled"):
            self.assertTrue(summary.risky(rule), rule)
        for rule in ("service_avahi-daemon_disabled", "package_telnet_removed", "kernel_module_usb-storage_disabled"):
            self.assertTrue(summary.check_deps(rule), rule)
            self.assertFalse(summary.risky(rule), rule)
        self.assertFalse(summary.check_deps("banner_etc_issue"))

    def test_lynis_report(self):
        with tempfile.NamedTemporaryFile("w", suffix=".dat", delete=False) as f:
            f.write("# Lynis Report\nhardening_index=62\nlynis_tests_done=248\n"
                    "warning[]=SSH-7408|Root login is permitted|PermitRootLogin=yes|-|\n"
                    "suggestion[]=PKGS-7370|Install debsums|-|-|\n"
                    "suggestion[]=BOOT-5122|Set a GRUB password|-|-|\n")
        try:
            lines = summary.lynis_summary(f.name).splitlines()
        finally:
            os.unlink(f.name)
        self.assertEqual(lines[:3], ["Hardening index: 62/100", "Tests performed: 248", "Warnings: 1, suggestions: 2"])
        self.assertIn("SSH-7408 | RISKY | Root login is permitted | PermitRootLogin=yes", lines)
        self.assertIn("BOOT-5122 | RISKY | Set a GRUB password", lines)
        self.assertIn("PKGS-7370 | - | Install debsums", lines)


if __name__ == "__main__":
    unittest.main()
