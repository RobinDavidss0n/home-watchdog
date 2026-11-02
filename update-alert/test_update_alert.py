import unittest
from datetime import date

from update_alert import (advisory_is_open, find_problems, format_message, is_new_release,
                          parse_debian_advisories, parse_proxmox_advisories, parse_report,
                          pending_debian_advisories, to_tell, wanted_scores, why_serious)

REPORT = """RELEASE trixie
KERNEL 7.0.14-26-pve
INSTALLED pve-manager 9.2.24
INSTALLED libnss3 2:3.110-1+deb13u4
INSTALLED qemu-server 9.2.2
PENDING libnss3 2:3.110-1+deb13u4 2:3.110-1+deb13u5 nss
PENDING vim-tiny 2:9.1.1230-2 2:9.1.1230-2+deb13u1 vim
PENDING vim-common 2:9.1.1230-2 2:9.1.1230-2+deb13u1 vim
PENDING openssh-server 1:10.0p1-7 1:10.0p1-7+deb13u1 openssh
"""

DSA_LIST = """[01 Nov 2026] DSA-6600-1 vim - security update
\t{CVE-2026-1111 CVE-2026-2222}
\t[trixie] - vim 2:9.1.1230-2+deb13u1
[31 Oct 2026] DSA-6599-1 nss - security update
\t[trixie] - nss 2:3.110-1+deb13u5
[30 Oct 2026] DSA-6598-1 nss - security update
\t{CVE-2026-3333}
\t[trixie] - nss 2:3.110-1+deb13u3
[29 Oct 2026] DSA-6597-1 openssh - security update
\t{CVE-2026-4444}
\t[trixie] - openssh 1:10.0p1-7+deb13u1
[28 Oct 2026] DSA-6596-1 bookworm-only - security update
\t{CVE-2026-5555}
\t[bookworm] - bookworm-only 1.0
"""

PAGE = """
<article><div class="bbWrapper"><b>Subject</b>: PSA-2026-00080-1: kernel TCP Use-After-Free (CVE-2026-98432)&#8203;<br />
<b>Advisory date</b>: 2026-10-31<br />
<b>Fixed in</b>: proxmox-kernel-7.0.14-25-pve(-signed)<br />
<br />
<b>References</b>: CVE-2026-98432</div></article>
<article><div class="bbWrapper"><b>Subject</b>: PSA-2026-00079-1: Missing shell quoting<br />
<b>Details</b>: a crafted URL.<br />
<b>Fixed in</b>:<br />
- pve-manager &gt;= 9.2.24</div></article>
<article><div class="bbWrapper"><b>Subject</b>: PSA-2026-00081-1: Auth problem<br />
<b>Details</b>: allowed an unauthenticated attacker in.<br />
<b>Fixed in</b>:<br />
- qemu-server &gt;= 9.2.3<br />
- libpve-access-control &gt;= 9.0.1</div></article>
<article><div class="bbWrapper">Thanks for the fix!</div></article>
"""


def host():
    return parse_report(REPORT)


def debian():
    return pending_debian_advisories(parse_debian_advisories(DSA_LIST, "trixie"), host())


class ParseTests(unittest.TestCase):

    def test_report(self):
        parsed = host()

        self.assertEqual(parsed["release"], "trixie")
        self.assertEqual(parsed["kernel"], "7.0.14-26-pve")
        self.assertEqual(parsed["pending"]["libnss3"]["source"], "nss")
        self.assertEqual(parsed["pending"]["libnss3"]["new"], "2:3.110-1+deb13u5")

    def test_debian_advisories_for_this_release_only(self):
        advisories = parse_debian_advisories(DSA_LIST, "trixie")

        self.assertEqual([a["id"] for a in advisories], ["DSA-6600-1", "DSA-6599-1", "DSA-6598-1", "DSA-6597-1"])
        self.assertEqual(advisories[0]["cves"], ["CVE-2026-1111", "CVE-2026-2222"])
        self.assertEqual(advisories[1]["cves"], [])

    def test_pending_advisories_skip_what_is_installed_and_repeat_no_source(self):
        self.assertEqual(sorted(a["id"] for a in debian()), ["DSA-6597-1", "DSA-6599-1", "DSA-6600-1"])

    def test_proxmox_advisories_skip_replies(self):
        self.assertEqual([a["id"] for a in parse_proxmox_advisories(PAGE)],
                         ["PSA-2026-00080-1", "PSA-2026-00079-1", "PSA-2026-00081-1"])

    def test_proxmox_advisory_fields(self):
        kernel, shell, auth = parse_proxmox_advisories(PAGE)

        self.assertEqual(kernel["cves"], ["CVE-2026-98432"])
        self.assertEqual(kernel["kernels"], ["7.0.14-25"])
        self.assertEqual(kernel["title"], "kernel TCP Use-After-Free (CVE-2026-98432)")
        self.assertEqual(shell["fixed"], [("pve-manager", "9.2.24")])
        self.assertFalse(shell["no_login"])
        self.assertTrue(auth["no_login"])


class OpenTests(unittest.TestCase):

    def setUp(self):
        self.host = host()
        self.kernel, self.shell, self.auth = parse_proxmox_advisories(PAGE)

    def test_kernel_already_newer_is_closed(self):
        self.assertFalse(advisory_is_open(self.kernel, self.host))

    def test_kernel_older_is_open(self):
        self.host["kernel"] = "7.0.14-5-pve"
        self.assertTrue(advisory_is_open(self.kernel, self.host))

    def test_kernel_of_another_branch_is_ignored(self):
        self.assertFalse(advisory_is_open({**self.kernel, "kernels": ["6.8.12-41"]}, self.host))

    def test_package_at_the_fixed_version_is_closed(self):
        self.assertFalse(advisory_is_open(self.shell, self.host))

    def test_package_below_the_fixed_version_is_open(self):
        self.assertTrue(advisory_is_open(self.auth, self.host))

    def test_advisory_without_readable_fix_counts_as_open(self):
        self.assertTrue(advisory_is_open({**self.shell, "fixed": [], "kernels": []}, self.host))

    def test_package_not_installed_is_closed(self):
        self.assertFalse(advisory_is_open({**self.shell, "fixed": [("proxmox-backup-server", "9.0")]}, self.host))


class FilterTests(unittest.TestCase):

    CRITICAL = {"score": 9.8, "vector": "NETWORK"}

    def test_severity_rule(self):
        scores = {"CVE-1": self.CRITICAL,
                  "CVE-2": {"score": 9.8, "vector": "LOCAL"},
                  "CVE-3": {"score": 8.9, "vector": "NETWORK"}}

        self.assertIn("CVSS 9.8", why_serious(["CVE-1"], set(), scores))
        self.assertIsNone(why_serious(["CVE-2", "CVE-3", "CVE-4"], set(), scores))
        self.assertIn("exploited", why_serious(["CVE-2"], {"CVE-2"}, scores))

    def test_ordinary_updates_stay_silent(self):
        self.assertEqual(find_problems(host(), debian(), [], set(), {}), {})

    def test_a_critical_score_is_not_enough_for_an_ordinary_package(self):
        self.assertEqual(find_problems(host(), debian(), [], set(), {"CVE-2026-1111": self.CRITICAL}), {})

    def test_a_critical_score_counts_for_a_network_facing_package(self):
        problems = find_problems(host(), debian(), [], set(), {"CVE-2026-4444": self.CRITICAL})

        self.assertIn("openssh", problems["DSA-6597-1"])

    def test_an_exploited_cve_counts_for_any_package(self):
        problems = find_problems(host(), debian(), [], {"CVE-2026-2222"}, {})

        self.assertIn("vim: CVE-2026-2222 is actively exploited", problems["DSA-6600-1"])

    def test_open_advisory_needing_no_login_is_told(self):
        _, _, auth = parse_proxmox_advisories(PAGE)

        self.assertIn("PSA-2026-00081-1", find_problems(host(), [], [auth], set(), {}))

    def test_release_jump(self):
        self.assertTrue(is_new_release("9.2.24", "9.3.1"))
        self.assertTrue(is_new_release("9.2.24", "10.0.1"))
        self.assertFalse(is_new_release("9.2.24", "9.2.25"))

        report = host()
        report["pending"]["pve-manager"] = {"old": "9.2.24", "new": "9.3.1", "source": "pve-manager"}
        self.assertIn("release-9.3.1", find_problems(report, [], [], set(), {}))

    def test_only_cves_that_can_matter_cost_a_request(self):
        kernel, _, _ = parse_proxmox_advisories(PAGE)

        self.assertEqual(wanted_scores(debian(), [kernel], {}, set()), ["CVE-2026-4444", "CVE-2026-98432"])
        self.assertEqual(wanted_scores(debian(), [kernel], {"CVE-2026-4444": {}}, {"CVE-2026-98432"}), [])


class TellTests(unittest.TestCase):

    def test_new_then_quiet_then_reminder(self):
        problems = {"CVE-1": "message"}

        self.assertEqual(to_tell(problems, {}, date(2026, 11, 2)), [("CVE-1", "message")])
        self.assertEqual(to_tell(problems, {"CVE-1": "2026-11-02"}, date(2026, 11, 8)), [])
        self.assertEqual(to_tell(problems, {"CVE-1": "2026-11-02"}, date(2026, 11, 9)), [("CVE-1", "message")])

    def test_long_lists_are_cut(self):
        message = format_message([(str(i), f"line {i}") for i in range(8)])

        self.assertEqual(len(message.splitlines()), 6)
        self.assertTrue(message.endswith("and 3 more"))


if __name__ == "__main__":
    unittest.main()
