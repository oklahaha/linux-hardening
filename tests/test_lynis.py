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
case " $* " in *" --tests "*) echo "--tests used" > "$D/tests-arg";; esac
printf 'hardening_index=70\ntests_executed=%s\n%s' "$RAN" "$FINDINGS" > "$r"; : > "$l"
[ -n "$CRASH" ] && exit 1   # died mid-audit: header written, no finish marker
echo finish=true >> "$r"
"""


class LynisTest(unittest.TestCase):
    def run_lynis(self, d, ran, *args, crash="", findings="", broken_python=False):
        bin_dir, caller = os.path.join(d, "bin"), os.path.join(d, "caller")
        os.makedirs(bin_dir)
        os.makedirs(caller)
        with open(os.path.join(caller, "custom.prf"), "w") as f:
            f.write("skip-test=SSH-7408\n")  # planted profile in the caller's directory
        stubs = [("sudo", '#!/bin/sh\nexec "$@"\n'), ("lynis", LYNIS_STUB)]
        if broken_python:
            stubs.append(("python3", "#!/bin/sh\necho boom >&2; exit 1\n"))
        for name, body in stubs:
            with open(os.path.join(bin_dir, name), "w") as f:
                f.write(body)
            os.chmod(os.path.join(bin_dir, name), 0o755)
        env = dict(os.environ, PATH=bin_dir + ":/usr/bin:/bin", D=d, RAN=ran, CRASH=crash, FINDINGS=findings,
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

    def test_recheck_runs_full_audit_and_shows_only_that_test(self):
        # Found on Ubuntu 24.04: --tests SSH-7408 alone skips it, because its prerequisite SSH-7402 never runs.
        f = ("suggestion[]=SSH-7408|Consider hardening SSH configuration|AllowTcpForwarding (set YES to NO)|-|\n"
             "suggestion[]=PKGS-7370|Install debsums|-|-|\n")
        with tempfile.TemporaryDirectory() as d:
            r = self.run_lynis(d, "SSH-7402|SSH-7408|PKGS-7370", "--test", "SSH-7408", findings=f)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse(os.path.exists(os.path.join(d, "tests-arg")))
            self.assertIn("SSH-7408 | RISKY | Consider hardening SSH configuration | AllowTcpForwarding", r.stdout)
            self.assertNotIn("PKGS-7370", r.stdout)
        with tempfile.TemporaryDirectory() as d:
            r = self.run_lynis(d, "SSH-7408", "--test", "SSH-7408")
            self.assertIn("SSH-7408: ran, no warnings or suggestions left", r.stdout)

    def test_recheck_fails_closed_when_summary_fails(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.run_lynis(d, "SSH-7408", "--test", "SSH-7408", broken_python=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertNotIn("no warnings or suggestions left", r.stdout)


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
