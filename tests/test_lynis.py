import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
LYNIS = os.path.join(HERE, "..", "skills", "linux-hardening", "scripts", "lynis.sh")
RECON = os.path.join(HERE, "..", "skills", "linux-hardening", "scripts", "recon.sh")

# Fake lynis: records its working directory, and "executes" only the tests listed in $RAN.
LYNIS_STUB = r"""#!/bin/sh
pwd > "$D/lynis-cwd"
while [ $# -gt 0 ]; do case $1 in --report-file) r=$2;; --logfile) l=$2;; esac; shift; done
printf 'hardening_index=70\ntests_executed=%s\n' "$RAN" > "$r"; : > "$l"
[ -n "$CRASH" ] && exit 1   # died mid-audit: header written, no finish marker
echo finish=true >> "$r"
"""


class LynisTest(unittest.TestCase):
    def run_lynis(self, d, ran, *args, crash=""):
        bin_dir, caller = os.path.join(d, "bin"), os.path.join(d, "caller")
        os.makedirs(bin_dir)
        os.makedirs(caller)
        with open(os.path.join(caller, "custom.prf"), "w") as f:
            f.write("skip-test=SSH-7408\n")  # planted profile in the caller's directory
        for name, body in (("sudo", '#!/bin/sh\nexec "$@"\n'), ("lynis", LYNIS_STUB)):
            with open(os.path.join(bin_dir, name), "w") as f:
                f.write(body)
            os.chmod(os.path.join(bin_dir, name), 0o755)
        env = dict(os.environ, PATH=bin_dir + ":/usr/bin:/bin", D=d, RAN=ran, CRASH=crash,
                   HARDENING_REPORTS=os.path.join(d, "reports"))
        return subprocess.run(["bash", LYNIS, *args], cwd=caller, env=env, capture_output=True, text=True)

    def test_runs_outside_the_caller_directory(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.run_lynis(d, "SSH-7408|PKGS-7370", "--test", "SSH-7408")
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(os.path.join(d, "lynis-cwd")) as f:
                cwd = f.read().strip()
            self.assertNotEqual(os.path.realpath(cwd), os.path.realpath(os.path.join(d, "caller")))
            self.assertFalse(os.path.exists(os.path.join(cwd, "custom.prf")))

    def test_interrupted_audit_fails_and_keeps_the_partial_report(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.run_lynis(d, "SSH-7408", crash="1")
            self.assertEqual(r.returncode, 70)
            self.assertIn("did not complete (exit 1", r.stderr)
            self.assertNotIn("Hardening index", r.stdout)
            (out,) = os.listdir(os.path.join(d, "reports"))
            self.assertTrue(os.path.getsize(os.path.join(d, "reports", out, "report.dat")) > 0)

    def test_skipped_test_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.run_lynis(d, "PKGS-7370|SSH-74080", "--test", "SSH-7408")
            self.assertEqual(r.returncode, 70)
            self.assertIn("did not run SSH-7408", r.stderr)


class ReconTest(unittest.TestCase):
    def recon(self, ssh_connection=None):
        env = {k: v for k, v in os.environ.items() if k != "SSH_CONNECTION"}
        if ssh_connection:
            env["SSH_CONNECTION"] = ssh_connection
        r = subprocess.run(["bash", RECON], env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_management_path_unknown_without_ssh_client(self):
        self.assertIn("route-to-client interface: unknown", self.recon())

    def test_route_is_reported_as_a_hint_only(self):
        out = self.recon("10.0.0.9 40000 10.0.0.56 22")
        self.assertIn("route-to-client interface:", out)
        self.assertIn("not proof", out)
        self.assertNotIn("management interface:", out)
        self.assertIn("Login dependencies", out)

    def test_management_path_unknown_through_local_tunnel(self):
        out = self.recon("127.0.0.1 40000 127.0.0.1 22")
        self.assertIn("local tunnel", out)
        self.assertIn("route-to-client interface: unknown", out)


if __name__ == "__main__":
    unittest.main()
