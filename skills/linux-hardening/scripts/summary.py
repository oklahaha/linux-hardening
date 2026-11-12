#!/usr/bin/env python3
"""Summarise an OpenSCAP results file or a Lynis report, or print one OpenSCAP rule's fix.

  summary.py results.xml [fixes.sh]          OpenSCAP: score, counts, failed rules by severity
  summary.py --fix <rule> fixes.sh           OpenSCAP: the bash fix block for one rule
  summary.py --lynis report.dat              Lynis: hardening index, warnings, suggestions
"""
import re
import sys
import xml.etree.ElementTree as ET

NS = {"x": "http://checklists.nist.gov/xccdf/1.2"}
PREFIX = "xccdf_org.ssgproject.content_rule_"
SEVERITY = {"high": 0, "medium": 1, "low": 2}
# Rule ids containing these can lock you out, stop services or halt the box.
RISKY = ("sshd", "pam", "faillock", "account", "password", "firewall", "ufw",
         "nftables", "iptables", "sudo", "grub", "mount", "partition",
         "auditd", "sysctl_net", "apparmor", "wireless", "network",
         # identity and home-directory services: disabling or removing them can stop logins
         "autofs", "nis", "ypbind", "sssd", "nslcd", "ldap", "nfs", "rpcbind", "krb5", "kerberos", "winbind", "samba",
         # cron/at allow-lists shut non-root users out; journal upload ships logs off the box
         "cron_allow", "at_allow", "journal_upload")
# Disabling a service, removing a package or blacklisting a module is safe only if nothing here uses it.
CHECK_DEPS = (("service_", "_disabled"), ("package_", "_removed"), ("kernel_module_", "_disabled"))
# Lynis test groups that touch logins, SSH, firewall, networking, boot or accounts.
LYNIS_RISKY = ("AUTH-", "SSH-", "FIRE-", "NETW-", "BOOT-", "ACCT-")


def short(rule_id):
    return rule_id.removeprefix(PREFIX)


def risky(rule):
    return any(k in rule for k in RISKY)


def check_deps(rule):
    return any(rule.startswith(a) and rule.endswith(b) for a, b in CHECK_DEPS)


def fix_blocks(fixes_text):
    pat = re.compile(r"# BEGIN fix \(\d+ / \d+\) for '([^']+)'\n(.*?)# END fix for '\1'", re.S)
    return {short(m[1]): m[2] for m in pat.finditer(fixes_text)}


def summarise(results_xml, fixes_text=""):
    root = ET.parse(results_xml).getroot()
    titles = {short(r.get("id")): r.findtext("x:title", "", NS).strip()
              for r in root.iter(f"{{{NS['x']}}}Rule")}
    test = root.find(".//x:TestResult", NS)
    if test is None:
        raise SystemExit("no TestResult in file; is this an oscap --results file?")
    score = float(test.findtext("x:score", "nan", NS))
    counts, failed = {}, []
    for rr in test.findall("x:rule-result", NS):
        res = rr.findtext("x:result", "", NS)
        counts[res] = counts.get(res, 0) + 1
        if res in ("fail", "error"):
            rule = short(rr.get("idref"))
            failed.append((res, rr.get("severity", "unknown"), rule))
    failed.sort(key=lambda f: (SEVERITY.get(f[1], 3), f[2]))
    fixes = fix_blocks(fixes_text)

    lines = [f"Score: {score:.1f}/100",
             "Results: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())),
             "",
             "Failed rules (severity | rule | flags | title):"]
    for res, sev, rule in failed:
        flags = ",".join(f for f, on in (("RISKY", risky(rule)), ("CHECK-DEPS", check_deps(rule)),
                                         ("no-auto-fix", rule not in fixes),
                                         ("ERROR", res == "error")) if on) or "-"
        lines.append(f"{sev:7} | {rule} | {flags} | {titles.get(rule, '')}")
    return "\n".join(lines)


def lynis_summary(report_dat):
    vals, findings = {}, {"warning[]": [], "suggestion[]": []}
    with open(report_dat, errors="replace") as f:
        for line in f:
            key, sep, val = line.rstrip("\n").partition("=")
            if not sep or key.startswith("#"):
                continue
            if key in findings:  # TEST-ID|finding|details|solution|
                findings[key].append((val.split("|") + ["", "", ""])[:3])
            else:
                vals[key] = val
    lines = [f"Hardening index: {vals.get('hardening_index', '?')}/100",
             f"Tests performed: {vals.get('lynis_tests_done', '?')}",
             f"Warnings: {len(findings['warning[]'])}, suggestions: {len(findings['suggestion[]'])}"]
    for key, label in (("warning[]", "Warnings"), ("suggestion[]", "Suggestions")):
        lines += ["", f"{label} (test | flags | finding | details):"]
        for test, text, details in sorted(findings[key]):
            flags = "RISKY" if test.startswith(LYNIS_RISKY) else "-"
            lines.append(f"{test} | {flags} | {text} | {details if details != '-' else ''}".rstrip(" |"))
    return "\n".join(lines)


def main(argv):
    if len(argv) == 2 and argv[0] == "--lynis":
        print(lynis_summary(argv[1]))
    elif len(argv) == 3 and argv[0] == "--fix":
        block = fix_blocks(open(argv[2]).read()).get(argv[1].removeprefix(PREFIX))
        if block is None:
            raise SystemExit(f"no automatic fix for {argv[1]}; fix it by hand from report.html")
        print(block)
    elif len(argv) in (1, 2):
        print(summarise(argv[0], open(argv[1]).read() if len(argv) == 2 else ""))
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
