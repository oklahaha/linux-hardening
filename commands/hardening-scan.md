---
description: Scan this server against a security standard (cis-l1, cis-l2, stig, nist, lynis, pci-dss, hipaa...) and report what fails. Changes nothing.
argument-hint: "[cis-l1 | cis-l2 | stig | nist | lynis | pci-dss | hipaa]"
---

Use the linux-hardening skill and follow it from step 1. It scans first and changes nothing without the user's yes.

Standard the user asked for: $ARGUMENTS

If that is empty, recommend one as the skill's references/standards.md says and ask. Otherwise map it with references/standards.md, and ask only if it matches more than one profile.
