import os
import shutil
import subprocess
import tempfile
import unittest

SCAN = os.path.join(os.path.dirname(__file__), "..", "skills", "linux-hardening", "scripts", "scan.sh")


class TamperedCacheTest(unittest.TestCase):
    def test_tampered_cached_zip_is_rejected_before_any_scan(self):
        with tempfile.TemporaryDirectory() as d:
            cache = os.path.join(d, "cache", "linux-hardening")
            os.makedirs(cache)
            zip_path = os.path.join(cache, "ssg-0.1.82.zip")
            with open(zip_path, "w") as f:
                f.write("tampered")
            bin_dir = os.path.join(d, "bin")
            os.mkdir(bin_dir)
            marker = os.path.join(d, "oscap-called")
            for name in ("oscap", "sudo", "curl"):
                stub = os.path.join(bin_dir, name)
                with open(stub, "w") as f:
                    f.write(f"#!/bin/sh\ntouch {marker}\nexit 1\n")
                os.chmod(stub, 0o755)
            env = dict(os.environ, PATH=bin_dir + ":/usr/bin:/bin", XDG_CACHE_HOME=os.path.join(d, "cache"),
                       HARDENING_REPORTS=os.path.join(d, "reports"))
            r = subprocess.run(["bash", SCAN], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 65, r.stderr)
            self.assertFalse(os.path.exists(zip_path))
            self.assertFalse(os.path.exists(marker))


CACHED_ZIP = os.path.expanduser("~/.cache/linux-hardening/ssg-0.1.82.zip")
OSCAP_STUB = r"""#!/bin/sh
case "$1 $2" in
  "info --profiles") echo "xccdf_org.ssgproject.content_profile_cis_level1_server: CIS" ;;
  "xccdf eval")
    while [ $# -gt 0 ]; do
      case $1 in --results) res=$2 ;; --report) rep=$2 ;; esac; shift
    done
    echo "$res" > "$LOG"
    printf '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"><TestResult id="t"><score>50</score></TestResult></Benchmark>' > "$res"
    echo report > "$rep"; exit 2 ;;
  "xccdf generate") while [ $# -gt 1 ]; do [ "$1" = --output ] && : > "$2"; shift; done ;;
esac
"""


@unittest.skipUnless(os.path.exists(CACHED_ZIP), "needs the cached SSG 0.1.82 zip")
class PrivilegedOutputTest(unittest.TestCase):
    def test_root_never_writes_into_the_caller_report_dir(self):
        with tempfile.TemporaryDirectory() as d:
            cache = os.path.join(d, "cache", "linux-hardening")
            os.makedirs(cache)
            os.symlink(CACHED_ZIP, os.path.join(cache, "ssg-0.1.82.zip"))
            bin_dir, reports, log = os.path.join(d, "bin"), os.path.join(d, "reports"), os.path.join(d, "eval-path")
            os.mkdir(bin_dir)
            for name, body in (("oscap", OSCAP_STUB), ("sudo", '#!/bin/sh\nexec "$@"\n')):
                with open(os.path.join(bin_dir, name), "w") as f:
                    f.write(body)
                os.chmod(os.path.join(bin_dir, name), 0o755)
            env = dict(os.environ, PATH=bin_dir + ":/usr/bin:/bin", XDG_CACHE_HOME=os.path.join(d, "cache"),
                       HARDENING_REPORTS=reports, LOG=log)
            r = subprocess.run(["bash", SCAN, "cis_level1_server"], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(log) as f:
                written = os.path.realpath(f.read().strip())
            self.assertFalse(written.startswith(os.path.realpath(reports)), written)
            (out,) = os.listdir(reports)
            self.assertEqual(os.stat(os.path.join(reports, out)).st_mode & 0o777, 0o700)
            self.assertTrue(os.path.getsize(os.path.join(reports, out, "results.xml")) > 0)
            self.assertFalse(os.path.exists(os.path.dirname(written)), "privileged temp dir not cleaned up")


@unittest.skipUnless(os.path.exists(CACHED_ZIP) and shutil.which("oscap"), "needs the cached SSG zip and oscap")
class DistroDetectionTest(unittest.TestCase):
    def list_standards(self, os_release, **extra_env):
        with tempfile.TemporaryDirectory() as d:
            cache = os.path.join(d, "cache", "linux-hardening")
            os.makedirs(cache)
            os.symlink(CACHED_ZIP, os.path.join(cache, "ssg-0.1.82.zip"))
            with open(os.path.join(d, "os-release"), "w") as f:
                f.write(os_release)
            env = dict(os.environ, XDG_CACHE_HOME=os.path.join(d, "cache"), HARDENING_OS_RELEASE=os.path.join(d, "os-release"), **extra_env)
            return subprocess.run(["bash", SCAN], env=env, capture_output=True, text=True)

    def test_maps_os_release_to_ssg_product(self):
        cases = {
            'ID=ubuntu\nVERSION_ID="24.04"': ("ubuntu2404", "cis_level1_server"),
            'ID=debian\nVERSION_ID="12"': ("debian12", "cis_level1_server"),
            'ID="rhel"\nVERSION_ID="9.4"': ("rhel9", "pci-dss"),
            'ID="almalinux"\nVERSION_ID="9.5"': ("almalinux9", "cis"),
            'ID="centos"\nVERSION_ID="9"': ("cs9", "stig"),
            'ID="amzn"\nVERSION_ID="2023"': ("al2023", "cis"),
            'ID="sles"\nVERSION_ID="15.6"': ("sle15", "stig"),
            'ID="opensuse-leap"\nVERSION_ID="15.6"': ("opensuse", "standard"),
            'ID=fedora\nVERSION_ID=41': ("fedora", "ospp"),
        }
        for os_release, (product, profile) in cases.items():
            with self.subTest(product=product):
                r = self.list_standards(os_release + "\n")
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn(f"Standards available for {product} ", r.stdout)
                self.assertIn(f"  {profile}: ", r.stdout)

    def test_unsupported_distro_is_refused_with_the_list(self):
        r = self.list_standards('ID=slackware\nVERSION_ID="15.0"\n')
        self.assertEqual(r.returncode, 69)
        self.assertIn("tried: slackware150 slackware15 slackware", r.stderr)
        self.assertIn("rhel9", r.stderr)

    def test_distro_content_not_owned_by_root_is_ignored(self):
        with tempfile.TemporaryDirectory() as sys_content:
            with open(os.path.join(sys_content, "ssg-rl9-ds.xml"), "w") as f:
                f.write("<planted/>")  # owned by the test user, so it must not be trusted
            r = self.list_standards('ID="rocky"\nVERSION_ID="9.4"\n', HARDENING_SYS_CONTENT=sys_content)
        self.assertEqual(r.returncode, 69, r.stdout)
        self.assertIn("tried: rl94 rl9 rl", r.stderr)
        self.assertIn("dnf install -y scap-security-guide", r.stderr)


if __name__ == "__main__":
    unittest.main()
