import json
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch

from update_alert import (DSA_URL, KEV_URL, MAX_LINES, PSA_URL, advisory_is_open, check, find_problems,
                          format_message, is_new_release, latest_proxmox_advisories, load_state, main,
                          parse_debian_advisories, parse_proxmox_advisories, parse_report,
                          pending_debian_advisories, read_env, save_state, to_tell, wanted_scores,
                          why_serious)

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

KEV_LIST = json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-2222"}]})
TODAY = date(2026, 11, 2)


def host():
    return parse_report(REPORT)


def debian():
    return pending_debian_advisories(parse_debian_advisories(DSA_LIST, "trixie"), host())


def post(text):
    return f'<article><div class="bbWrapper">{text}</div></article>'


def advisory_post(number):
    return post(f"<b>Subject</b>: PSA-2026-{number:05}-1: Something")


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

    def test_proxmox_advisory_fix_written_in_words(self):
        page = ('<article><div class="bbWrapper"><b>Subject</b>: PSA-2026-00043-1: Authentication bypass<br />'
                '<b>Fixed in</b>: libpve-access-control 8.0.4 (released 2023-07-20) and all later versions. '
                'No supported Proxmox VE release is affected.<br /><b>Details</b>: pam 2 retries.</div></article>')
        advisory = parse_proxmox_advisories(page)[0]
        report = host()
        report["installed"]["libpve-access-control"] = "9.0.1"

        self.assertEqual(advisory["fixed"], [("libpve-access-control", "8.0.4")])
        self.assertFalse(advisory_is_open(advisory, report))

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


class EnvTests(unittest.TestCase):

    def test_read_env_handles_quotes_comments_and_equals_signs(self):
        env = read_env('# a comment\nHA_TOKEN="abc=def"\nPROXMOX_TOKEN=\'x\'\n\nPLAIN=y\n')

        self.assertEqual(env, {"HA_TOKEN": "abc=def", "PROXMOX_TOKEN": "x", "PLAIN": "y"})


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


class SourceTests(unittest.TestCase):

    def advisories(self, pages):
        with patch("update_alert.fetch", side_effect=pages.__getitem__) as fetch:
            ids = [advisory["id"] for advisory in latest_proxmox_advisories()]

        self.fetched = [call.args[0] for call in fetch.call_args_list]
        return ids

    def test_one_page_is_read_once(self):
        self.assertEqual(self.advisories({PSA_URL: advisory_post(1)}), ["PSA-2026-00001-1"])
        self.assertEqual(self.fetched, [PSA_URL])

    def test_two_pages_are_both_read(self):
        pages = {PSA_URL: '<a href="page-2">2</a>' + advisory_post(1), f"{PSA_URL}page-2": advisory_post(2)}

        self.assertEqual(self.advisories(pages), ["PSA-2026-00001-1", "PSA-2026-00002-1"])
        self.assertEqual(self.fetched, [PSA_URL, f"{PSA_URL}page-2"])

    def test_only_the_last_two_of_many_pages_are_read(self):
        pages = {PSA_URL: '<a href="page-2">2</a><a href="page-3">3</a>' + advisory_post(1),
                 f"{PSA_URL}page-2": advisory_post(2),
                 f"{PSA_URL}page-3": advisory_post(3)}

        self.assertEqual(self.advisories(pages), ["PSA-2026-00002-1", "PSA-2026-00003-1"])

    def test_a_page_without_posts_raises(self):
        with self.assertRaises(RuntimeError):
            self.advisories({PSA_URL: "<html>Oops, something went wrong</html>"})

        with self.assertRaises(RuntimeError):
            self.advisories({PSA_URL: '<a href="page-2">2</a>' + advisory_post(1), f"{PSA_URL}page-2": "<html></html>"})

    def test_a_last_page_of_replies_only_does_not_raise(self):
        pages = {PSA_URL: '<a href="page-2">2</a>' + advisory_post(1), f"{PSA_URL}page-2": post("Thanks!")}

        self.assertEqual(self.advisories(pages), ["PSA-2026-00001-1"])

    def test_a_debian_list_with_nothing_for_the_release_raises(self):
        with self.assertRaises(RuntimeError):
            parse_debian_advisories(DSA_LIST, "forky")


class OfflineTests(unittest.TestCase):
    """A temporary state file, with the host, the web and the phone replaced."""

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        self.state_file = self.folder / "state.json"
        self.pages = {KEV_URL: KEV_LIST, DSA_URL: DSA_LIST, PSA_URL: PAGE}
        self.down = set()

        self.replace("update_alert.STATE", new=self.state_file)
        self.replace("update_alert.fetch", side_effect=self.fetch)
        self.read_host = self.replace("update_alert.read_host", return_value=host())
        self.lookup = self.replace("update_alert.lookup_cvss", return_value=None)
        self.notify = self.replace("update_alert.notify")
        self.replace("builtins.print")

    def replace(self, target, **kwargs):
        patcher = patch(target, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def fetch(self, url):
        if url in self.down:
            raise OSError(f"{url} is down")

        return self.pages[url]

    def saved(self):
        return json.loads(self.state_file.read_text())


class CheckTests(OfflineTests):

    def test_all_sources_read_tells_and_prunes(self):
        state = {**load_state(), "told": {"DSA-1-1": "2026-11-01"}}

        check(state, TODAY)

        self.assertEqual(state["told"], {"DSA-6600-1": "2026-11-02", "PSA-2026-00081-1": "2026-11-02"})

    def test_a_failed_forum_still_tells_then_raises_without_pruning(self):
        self.down.add(PSA_URL)
        state = {**load_state(), "told": {"PSA-2026-00081-1": "2026-11-01"}}

        with self.assertRaisesRegex(RuntimeError, "forum"):
            check(state, TODAY)

        self.notify.assert_called_once()
        self.assertIn("CVE-2026-2222", self.notify.call_args.args[0])
        self.assertEqual(state["told"], {"PSA-2026-00081-1": "2026-11-01", "DSA-6600-1": "2026-11-02"})

    def test_the_exploited_list_and_the_debian_list_fail_on_their_own(self):
        for url, name in ((KEV_URL, "exploited"), (DSA_URL, "Debian")):
            with self.subTest(name):
                self.down = {url}
                state = load_state()

                with self.assertRaisesRegex(RuntimeError, name):
                    check(state, TODAY)

                self.assertEqual(list(state["told"]), ["PSA-2026-00081-1"])

    def test_nvd_failing_for_one_cve_stops_neither_the_next_cve_nor_the_alert(self):
        def lookup(cve):
            if cve == "CVE-2026-0001":
                raise OSError("NVD is down")

            return {"score": 5.0, "vector": "LOCAL"}

        self.lookup.side_effect = lookup
        self.pages[PSA_URL] = post("<b>Subject</b>: PSA-2026-00082-1: Something (CVE-2026-0001)")
        state = load_state()

        with self.assertRaisesRegex(RuntimeError, "CVE-2026-0001"):
            check(state, TODAY)

        self.assertIn("CVE-2026-2222", self.notify.call_args.args[0])
        self.assertIn("DSA-6600-1", state["told"])
        self.assertEqual(list(state["scores"]), ["CVE-2026-4444"])

    def test_only_what_the_message_shows_is_marked_told(self):
        problems = {f"key-{i}": f"line {i}" for i in range(MAX_LINES + 2)}
        state = load_state()

        with patch("update_alert.find_problems", return_value=problems):
            check(state, TODAY)
            self.assertEqual(sorted(state["told"]), [f"key-{i}" for i in range(MAX_LINES)])

            check(state, TODAY + timedelta(days=1))

        self.assertIn(f"line {MAX_LINES}", self.notify.call_args.args[0])
        self.assertEqual(len(state["told"]), MAX_LINES + 2)


class MainTests(OfflineTests):
    """Day 0 is the first failure; a day's number is how many days the check has failed for."""

    def setUp(self):
        super().setUp()
        self.read_host.side_effect = OSError("no route to host")

    def run_on_day(self, day):
        return main(TODAY + timedelta(days=day))

    def test_quiet_until_day_3_then_tells_once(self):
        for day in range(3):
            self.assertEqual(self.run_on_day(day), 1)

        self.notify.assert_not_called()

        self.run_on_day(3)
        self.run_on_day(4)

        self.notify.assert_called_once()
        self.assertIn("3 days: no route to host", self.notify.call_args.args[0])
        self.assertEqual(self.saved()["failed_since"], "2026-11-02")

    def test_a_gap_over_day_3_still_tells(self):
        self.run_on_day(0)
        self.run_on_day(2)
        self.notify.assert_not_called()

        self.run_on_day(4)

        self.notify.assert_called_once()
        self.assertIn("4 days", self.notify.call_args.args[0])

    def test_a_failing_notify_keeps_state_and_retries(self):
        self.run_on_day(0)
        self.notify.side_effect = OSError("Home Assistant is down")

        self.assertEqual(self.run_on_day(3), 1)
        self.assertEqual(self.saved()["failed_since"], "2026-11-02")
        self.assertFalse(self.saved()["failure_told"])

        self.notify.side_effect = None
        self.run_on_day(4)
        self.assertTrue(self.saved()["failure_told"])
        self.assertEqual(self.notify.call_count, 2)

        self.run_on_day(5)
        self.assertEqual(self.notify.call_count, 2)

    def test_success_clears_the_failure(self):
        self.run_on_day(0)
        self.run_on_day(3)
        self.assertTrue(self.saved()["failure_told"])

        self.read_host.side_effect = None

        self.assertEqual(self.run_on_day(4), 0)
        self.assertIsNone(self.saved()["failed_since"])
        self.assertFalse(self.saved()["failure_told"])

    def test_a_partly_failed_run_counts_as_failed_and_keeps_what_it_told(self):
        self.read_host.side_effect = None
        self.down.add(PSA_URL)

        self.assertEqual(self.run_on_day(0), 1)
        self.assertEqual(self.saved()["failed_since"], "2026-11-02")
        self.assertIn("DSA-6600-1", self.saved()["told"])


class StateTests(OfflineTests):

    DEFAULTS = {"told": {}, "scores": {}, "failed_since": None, "failure_told": False}

    def test_no_file_gives_defaults(self):
        self.assertEqual(load_state(), self.DEFAULTS)

    def test_a_bad_file_gives_defaults(self):
        for text in ('{"told": {"DS', "", "[]", "null"):
            with self.subTest(text):
                self.state_file.write_text(text)
                self.assertEqual(load_state(), self.DEFAULTS)

    def test_a_file_from_before_failure_told_gets_the_default(self):
        self.state_file.write_text('{"told": {"DSA-1-1": "2026-11-01"}}')
        state = load_state()

        self.assertEqual(state["told"], {"DSA-1-1": "2026-11-01"})
        self.assertFalse(state["failure_told"])

    def test_a_bad_file_does_not_stop_a_run(self):
        self.state_file.write_text('{"told": {"DS')
        self.read_host.side_effect = None

        self.assertEqual(main(TODAY), 0)
        self.assertIn("DSA-6600-1", self.saved()["told"])

    def test_saving_replaces_the_file_and_leaves_no_temporary_one(self):
        self.state_file.write_text("old")

        save_state({"told": {"DSA-1-1": "2026-11-01"}})

        self.assertEqual(self.saved(), {"told": {"DSA-1-1": "2026-11-01"}})
        self.assertEqual(list(self.folder.iterdir()), [self.state_file])


if __name__ == "__main__":
    unittest.main()
