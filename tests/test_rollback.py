import fcntl
import os
import subprocess
import tempfile
import unittest

ARM = os.path.join(os.path.dirname(__file__), "..", "skills", "linux-hardening", "scripts", "arm-rollback.sh")
RUNTIME_RULE = "table inet runtime_ssh { chain input { tcp dport 2222 accept } }"
NFT_OK = f"""case "$*" in
  "list ruleset") echo '{RUNTIME_RULE}' ;;
  "-c -f -") cat > /dev/null ;;
  "-f -") cat > "$D/nft-loaded" ;;
esac"""


def active(*units):
    """systemctl stub: the given units are active, everything else succeeds except is-active."""
    pats = "|".join(f'"is-active --quiet {u}"' for u in units) or '"never"'
    return f'case "$*" in {pats}) exit 0;; "is-active --quiet "*) exit 1;; esac; exit 0'


class RollbackTest(unittest.TestCase):
    def _env(self, d, systemctl, nft=NFT_OK):
        etc, bin_dir = os.path.join(d, "etc"), os.path.join(d, "bin")
        os.makedirs(etc)
        os.mkdir(bin_dir)
        for name, body in (("systemctl", systemctl), ("systemd-run", "exit 0"), ("nft", nft)):
            with open(os.path.join(bin_dir, name), "w") as f:
                f.write(f'#!/bin/sh\necho "{name} $*" >> "$D/calls"\n{body}\n')
            os.chmod(os.path.join(bin_dir, name), 0o755)
        return dict(os.environ, PATH=bin_dir + ":/usr/bin:/bin", HARDENING_ETC=etc,
                    HARDENING_ROLLBACK_DIR=os.path.join(d, "state"), D=d)

    def _arm_then_restore(self, d, env):
        arm = subprocess.run(["bash", ARM, "5"], env=env, capture_output=True, text=True)
        self.assertEqual(arm.returncode, 0, arm.stderr)
        self.assertIn("Rollback armed", arm.stdout)
        open(os.path.join(d, "calls"), "w").close()
        return lambda: subprocess.run(["bash", os.path.join(d, "state", "rollback.sh"), "restore"],
                                      env=env, capture_output=True, text=True)

    def _calls(self, d):
        with open(os.path.join(d, "calls")) as f:
            return f.read().splitlines()

    def test_restore_reverts_changed_and_deletes_created_files(self):
        with tempfile.TemporaryDirectory() as d:
            env = self._env(d, active())
            etc = env["HARDENING_ETC"]
            os.makedirs(os.path.join(etc, "sudoers.d"))
            with open(os.path.join(etc, "sudoers"), "w") as f:
                f.write("good\n")
            restore = self._arm_then_restore(d, env)
            self.assertEqual(os.stat(os.path.join(d, "state", "etc.tgz")).st_mode & 0o077, 0)

            # Simulate a bad auth fix: edit a file and add a new drop-in with spaces in its name.
            with open(os.path.join(etc, "sudoers"), "w") as f:
                f.write("broken\n")
            os.makedirs(os.path.join(etc, "new dir"))
            with open(os.path.join(etc, "sudoers.d", "99 lockout"), "w") as f:
                f.write("deny\n")

            r = restore()
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(os.path.join(etc, "sudoers")) as f:
                self.assertEqual(f.read(), "good\n")
            self.assertFalse(os.path.exists(os.path.join(etc, "sudoers.d", "99 lockout")))
            # Moved aside, not deleted: a package may have created it during the window.
            (kept,) = [n for n in os.listdir(d) if n.startswith("state.removed-")]
            self.assertTrue(os.path.isfile(os.path.join(d, kept, "etc", "sudoers.d", "99 lockout")))
            self.assertFalse(os.path.exists(os.path.join(etc, "new dir")))
            self.assertTrue(os.path.isdir(os.path.join(etc, "sudoers.d")))

    def test_refuses_to_arm_while_lock_held_or_rollback_active(self):
        with tempfile.TemporaryDirectory() as d:
            env = self._env(d, active())
            with open(os.path.join(d, "state.lock"), "w") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                r = subprocess.run(["bash", ARM], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 75, r.stderr)
        with tempfile.TemporaryDirectory() as d:
            env = self._env(d, active("hardening-rollback.service"))
            r = subprocess.run(["bash", ARM], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 75, r.stderr)
            self.assertIn("service is active", r.stderr)

    def test_refuses_to_arm_when_firewall_snapshot_cannot_be_reloaded(self):
        with tempfile.TemporaryDirectory() as d:
            env = self._env(d, active(), nft='case "$*" in "-c -f -") exit 1;; esac')
            r = subprocess.run(["bash", ARM], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 70, r.stderr)
            self.assertNotIn("systemd-run", "".join(self._calls(d)))

    def test_restore_restarts_services_a_fix_stopped_then_reloads_live_rules(self):
        with tempfile.TemporaryDirectory() as d:
            # nftables and sshd ran at arming time; the fix (e.g. service_nftables_disabled) stopped them.
            env = self._env(d, active("nftables", "sshd"))
            restore = self._arm_then_restore(d, env)
            r = restore()
            self.assertEqual(r.returncode, 0, r.stderr)
            calls = self._calls(d)
            for c in ("systemctl restart nftables", "systemctl stop ufw", "systemctl stop firewalld",
                      "systemctl restart sshd"):
                self.assertIn(c, calls)
            self.assertFalse([c for c in calls if c.startswith("systemctl stop ssh")], calls)
            # The live snapshot (incl. a runtime-only SSH allow) is loaded after the service restarts, in one flush+load.
            self.assertLess(calls.index("systemctl restart nftables"), calls.index("nft -f -"))
            self.assertLess(calls.index("nft -f -"), calls.index("systemctl restart sshd"))
            with open(os.path.join(d, "nft-loaded")) as f:
                self.assertEqual(f.read().splitlines(), ["flush ruleset", RUNTIME_RULE])

    def test_legacy_iptables_is_captured_alongside_nft(self):
        with tempfile.TemporaryDirectory() as d:
            env = self._env(d, active())
            bin_dir = os.path.join(d, "bin")
            for t in ("iptables", "ip6tables"):
                for verb, body in (("save", f"echo '*filter -A INPUT -j DROP # {t}'"), ("restore", 'cat >> "$D/legacy-loaded"')):
                    path = os.path.join(bin_dir, f"{t}-legacy-{verb}")
                    with open(path, "w") as f:
                        f.write(f'#!/bin/sh\necho "{t}-legacy-{verb} $*" >> "$D/calls"\n{body}\n')
                    os.chmod(path, 0o755)
            restore = self._arm_then_restore(d, env)
            with open(os.path.join(d, "state", "fw-backends")) as f:
                self.assertEqual(f.read().split(), ["nft", "iptables-legacy", "ip6tables-legacy"])
            open(os.path.join(d, "legacy-loaded"), "w").close()  # drop the --test loads done while arming
            r = restore()
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(os.path.join(d, "legacy-loaded")) as f:
                self.assertEqual(f.read().splitlines(), ["*filter -A INPUT -j DROP # iptables", "*filter -A INPUT -j DROP # ip6tables"])

    def test_restore_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            env = self._env(d, active("firewalld"))
            restore = self._arm_then_restore(d, env)
            with open(os.path.join(d, "bin", "systemctl"), "w") as f:  # now every restart fails
                f.write('#!/bin/sh\necho "systemctl $*" >> "$D/calls"\ncase "$1" in restart) exit 1;; esac\n')
            r = restore()
            self.assertEqual(r.returncode, 1)
            self.assertIn("ROLLBACK INCOMPLETE, failed: firewalld", r.stderr)
            self.assertIn("nft -f -", self._calls(d))  # still restores the rules after a service fails

    # Findings from the Codex adversarial review of this script.

    def _tool(self, d, name, body):
        path = os.path.join(d, "bin", name)
        with open(path, "w") as f:
            f.write(f'#!/bin/sh\necho "{name} $*" >> "$D/calls"\n{body}\n')
        os.chmod(path, 0o755)

    def test_stuck_new_path_does_not_abort_recovery_and_is_never_deleted_recursively(self):
        with tempfile.TemporaryDirectory() as d:
            env = self._env(d, active("sshd"))
            etc = env["HARDENING_ETC"]
            with open(os.path.join(etc, "sudoers"), "w") as f:
                f.write("good\n")
            restore = self._arm_then_restore(d, env)
            with open(os.path.join(etc, "sudoers"), "w") as f:
                f.write("broken\n")
            locked = os.path.join(etc, "locked")  # stands in for an immutable file or a mountpoint
            os.mkdir(locked)
            with open(os.path.join(locked, "data"), "w") as f:
                f.write("keep\n")
            os.chmod(locked, 0o555)
            try:
                r = restore()
            finally:
                os.chmod(locked, 0o755)
            self.assertEqual(r.returncode, 1)
            self.assertIn("ROLLBACK INCOMPLETE", r.stderr)
            self.assertIn("etc/locked", r.stderr)
            self.assertTrue(os.path.exists(os.path.join(locked, "data")))  # no rm -rf
            with open(os.path.join(etc, "sudoers")) as f:
                self.assertEqual(f.read(), "good\n")  # the rest still ran
            calls = self._calls(d)
            self.assertIn("nft -f -", calls)
            self.assertIn("systemctl restart sshd", calls)

    def test_restore_stops_the_timer_first(self):
        with tempfile.TemporaryDirectory() as d:
            env = self._env(d, active())
            r = self._arm_then_restore(d, env)()
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(self._calls(d)[0], "systemctl stop hardening-rollback.timer")

    def test_missing_nft_snapshot_never_flushes(self):
        with tempfile.TemporaryDirectory() as d:
            env = self._env(d, active())
            restore = self._arm_then_restore(d, env)
            os.remove(os.path.join(d, "state", "nft.rules"))
            r = restore()
            self.assertEqual(r.returncode, 1)
            self.assertIn("nft-rules", r.stderr)
            self.assertNotIn("nft -f -", self._calls(d))

    def test_refuses_to_arm_on_invalid_sshd_config(self):
        with tempfile.TemporaryDirectory() as d:
            env = self._env(d, active())
            os.makedirs(os.path.join(env["HARDENING_ETC"], "ssh"))
            open(os.path.join(env["HARDENING_ETC"], "ssh", "sshd_config"), "w").close()
            self._tool(d, "sshd", "exit 1")
            r = subprocess.run(["bash", ARM], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 70)
            self.assertIn("sshd -t fails", r.stderr)
            self.assertNotIn("systemd-run", "".join(self._calls(d)))

    def test_faillock_tallies_return_to_arming_state(self):
        with tempfile.TemporaryDirectory() as d:
            env = self._env(d, active())
            fl = os.path.join(d, "faillock")
            os.mkdir(fl)
            with open(os.path.join(fl, "admin"), "w") as f:
                f.write("old\n")
            env["HARDENING_FAILLOCK"] = fl
            restore = self._arm_then_restore(d, env)
            with open(os.path.join(fl, "admin"), "w") as f:
                f.write("locked\n")
            open(os.path.join(fl, "other"), "w").close()
            r = restore()
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(sorted(os.listdir(fl)), ["admin"])
            with open(os.path.join(fl, "admin")) as f:
                self.assertEqual(f.read(), "old\n")

    def test_ipset_members_restored_before_rules(self):
        with tempfile.TemporaryDirectory() as d:
            env = self._env(d, active())
            self._tool(d, "ipset", 'case "$1" in save) printf "create allow hash:ip\\nadd allow 10.0.0.1\\n";; '
                                   'list) echo allow; echo newset;; restore) cat > "$D/ipset-loaded";; esac')
            restore = self._arm_then_restore(d, env)
            r = restore()
            self.assertEqual(r.returncode, 0, r.stderr)
            calls = self._calls(d)
            self.assertIn("ipset flush allow", calls)
            self.assertNotIn("ipset flush newset", calls)  # not in the snapshot
            self.assertLess(calls.index("ipset restore -exist"), calls.index("nft -f -"))
            with open(os.path.join(d, "ipset-loaded")) as f:
                self.assertIn("add allow 10.0.0.1", f.read())

    def test_generic_legacy_iptables_is_captured_and_new_legacy_tables_are_emptied(self):
        with tempfile.TemporaryDirectory() as d:
            env = self._env(d, active())
            self._tool(d, "iptables", 'case "$*" in -V) echo "iptables v1.8.10 (legacy)";; '
                                      '"-t raw -S") echo "-P PREROUTING DROP";; esac')
            self._tool(d, "iptables-save", "echo '*filter'; echo COMMIT")
            self._tool(d, "iptables-restore", "cat > /dev/null")
            proc = os.path.join(d, "proc", "net")
            os.makedirs(proc)
            with open(os.path.join(proc, "ip_tables_names"), "w") as f:
                f.write("filter\nraw\n")  # raw was loaded by the fix
            env["HARDENING_PROC"] = os.path.join(d, "proc")
            restore = self._arm_then_restore(d, env)
            with open(os.path.join(d, "state", "fw-backends")) as f:
                self.assertEqual(f.read().split(), ["nft", "iptables"])
            r = restore()
            self.assertEqual(r.returncode, 0, r.stderr)
            calls = self._calls(d)
            for c in ("iptables -t raw -P PREROUTING ACCEPT", "iptables -t raw -F", "iptables -t raw -X"):
                self.assertIn(c, calls)
            self.assertFalse([c for c in calls if c.startswith("iptables -t filter")], calls)
            self.assertLess(calls.index("iptables -t raw -X"), calls.index("iptables-restore "))


if __name__ == "__main__":
    unittest.main()
