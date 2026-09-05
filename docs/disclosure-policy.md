# Coordinated disclosure policy

How findings from mcp-scan's ecosystem scan campaign get reported, not how
to report a bug in mcp-scan itself (see the repo's issue tracker for that).

## Steps

1. **Private report first.** Contact the maintainer directly, not a public
   issue or forum post. Prefer a security contact listed in the package's
   README, `SECURITY.md`, or npm/PyPI maintainer email. If none exists, use
   GitHub Security Advisories' private "Report a vulnerability" form on the
   package's repo, or npm/PyPI's own abuse contact as a last resort.
2. **Give the details needed to reproduce and fix.** Package name, affected
   version range, the finding (data exfiltration, credential relay,
   malicious dependency, etc.), severity, and a suggested fix where one
   exists. No public disclosure, no proof-of-concept posted anywhere else,
   until the maintainer has had a chance to respond.
3. **90-day window.** Clock starts the day the maintainer confirms receipt,
   or 7 days after the report if they never respond. A fix, a mitigation,
   or an agreed extension all count as progress; silence does not. After
   90 days with no fix and no response, disclosure can proceed publicly.
4. **Request a CVE once the issue is confirmed.** File through GitHub
   Security Advisories if the package has a GitHub repo (it can mint the
   CVE directly), otherwise request one from MITRE
   (https://cveform.mitre.org/). Do this before public disclosure, not
   after, so the advisory ships with a CVE ID attached.
5. **Publish only after one of:** the fix ships, the 90 days elapse, or the
   maintainer agrees to earlier disclosure. The advisory states the
   affected versions, the fixed version, and the finding in plain terms.
6. **Credit line.** Every advisory and CVE request credits the finder as:
   `Abanoub Rodolf Boctor, ThynkQ`.

## What this is not

No maintainer contact, no public issue, and no CVE request happens as part
of the scan itself. The scan only produces findings; every step above is a
separate, deliberate action taken after review.
