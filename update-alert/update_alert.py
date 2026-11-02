#!/usr/bin/env python3
"""Tells the phone when the Proxmox host has an update worth the time, and only then.

Runs daily from cron on VM 101. Worth the time means one of:
  - a pending Debian update whose advisory fixes a CVE on CISA's list of exploited ones;
  - the same for a network-facing package with a CVSS >= 9.0 network CVE;
  - a Proxmox advisory with such a CVE, or that needs no login, for a version newer
    than what's installed;
  - a new Proxmox release (9.2 -> 9.3 or higher).
CVSS alone isn't used for other Debian packages: replayed on this host's real
upgrades it flagged ~90 CVEs per upgrade, in perl, samba clients and so on, while
the exploited list flagged 3 of the year's 68 advisories.
Each finding goes out once, then again after 7 days if it's still open.
"""
import html
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import date, timedelta
from pathlib import Path

STATE = Path(os.environ.get("UPDATE_ALERT_STATE", Path.home() / ".update-alert.json"))
ENV_FILE = Path(os.environ.get("UPDATE_ALERT_ENV", Path.home() / "main/homeassistant-watchdog/.env"))
REPORT_COMMAND = ["ssh", "-T", "-i", str(Path.home() / ".ssh/update-alert"), "-o", "BatchMode=yes", "root@192.168.1.2"]

KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
DSA_URL = "https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DSA/list"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
NVD_PAUSE_SECONDS = 7  # NVD allows 5 requests per 30 s without an API key
PSA_URL = "https://forum.proxmox.com/threads/proxmox-virtual-environment-security-advisories.149331/"

CRITICAL_CVSS = 9.0
NETWORK_FACING = {"openssh", "openssl"}
REMIND_DAYS = 7
MAX_LINES = 5
FAILED_DAYS_BEFORE_TELLING = 3
NO_LOGIN_WORDS = ("unauthenticated", "without authentication", "authentication bypass", "without logging in")


def fetch(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "update-alert (home server)"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8")


def parse_report(report: str) -> dict:
    parsed = {"release": "", "kernel": "", "installed": {}, "pending": {}}

    for line in report.splitlines():
        kind, _, rest = line.partition(" ")
        fields = rest.split()

        if kind == "RELEASE":
            parsed["release"] = rest.strip()
        elif kind == "KERNEL":
            parsed["kernel"] = rest.strip()
        elif kind == "INSTALLED" and len(fields) == 2:
            parsed["installed"][fields[0]] = fields[1]
        elif kind == "PENDING" and len(fields) == 4:
            parsed["pending"][fields[0]] = {"old": fields[1], "new": fields[2], "source": fields[3]}

    return parsed


def parse_debian_advisories(text: str, release: str) -> list:
    """Debian's advisory list: blocks of a date line, {CVEs} and one [release] line each."""
    advisories = []
    current = None

    for line in text.splitlines():
        heading = re.match(r"\[[^]]+\] (DSA-\S+) ", line)

        if heading:
            current = {"id": heading.group(1), "cves": []}
            continue

        if current is None:
            continue

        if line.strip().startswith("{"):
            current["cves"] += re.findall(r"CVE-\d{4}-\d+", line)

        fix = re.match(r"\s+\[(\S+)\] - (\S+) (\S+)", line)

        if fix and fix.group(1) == release:
            advisories.append({**current, "source": fix.group(2), "version": fix.group(3)})

    if not advisories:
        raise RuntimeError(f"Debian's advisory list has nothing for {release}")

    return advisories


def pending_debian_advisories(advisories: list, host: dict) -> list:
    """The advisories that a pending update would bring in."""
    pending = {}

    for update in host["pending"].values():
        for advisory in advisories:
            if (advisory["source"] == update["source"]
                    and version_older(update["old"], advisory["version"])
                    and not version_older(update["new"], advisory["version"])):
                pending[advisory["id"]] = advisory

    return list(pending.values())


def parse_proxmox_advisories(page: str) -> list:
    """The advisories in one page of Proxmox's thread."""
    advisories = []

    for post in re.findall(r'<div class="bbWrapper">(.*?)</article>', page, re.S):
        text = html.unescape(re.sub(r"<[^>]+>", "", re.sub(r"<br\s*/?>", "\n", post)))
        subject = re.search(r"Subject:\s*(PSA-[\d-]+):\s*([^\n]*)", text)

        if not subject:
            continue

        fixed_part = text.split("Fixed in:", 1)[-1] if "Fixed in:" in text else ""
        fixed_part = fixed_part.split("References:", 1)[0]

        advisories.append({
            "id": subject.group(1),
            "title": subject.group(2).replace("​", "").strip(),
            "cves": sorted(set(re.findall(r"CVE-\d{4}-\d+", text))),
            "no_login": any(word in text.lower() for word in NO_LOGIN_WORDS),
            "fixed": re.findall(r"([a-z0-9][a-z0-9.+-]*?)(?:\(-signed\))?\s*>=\s*([\w.:+~-]+)", fixed_part),
            "kernels": re.findall(r"proxmox-kernel-(\d[\w.]*-\d+)-pve", fixed_part),
        })

    return advisories


def version_older(version: str, than: str) -> bool:
    return subprocess.run(["dpkg", "--compare-versions", version, "lt", than]).returncode == 0


def kernel_key(version: str) -> list:
    return [int(number) for number in re.findall(r"\d+", version)]


def advisory_is_open(advisory: dict, host: dict) -> bool:
    """False when the host already has every fix the advisory names."""
    # An advisory that can't be read counts as open: better one alert too many
    if not advisory["kernels"] and not advisory["fixed"]:
        return True

    running = re.sub(r"-pve$", "", host["kernel"])
    branch = kernel_key(running)[:2]

    # An advisory lists a kernel per release; only this kernel's branch counts
    for fixed in advisory["kernels"]:
        if kernel_key(fixed)[:2] == branch and kernel_key(running) < kernel_key(fixed):
            return True

    for package, fixed in advisory["fixed"]:
        installed = host["installed"].get(package)

        if installed and version_older(installed, fixed):
            return True

    return False


def lookup_cvss(cve: str) -> dict | None:
    """Score and attack vector, or None while NVD hasn't scored it yet."""
    data = json.loads(fetch(NVD_URL + urllib.parse.quote(cve)))
    time.sleep(NVD_PAUSE_SECONDS)

    for item in data.get("vulnerabilities", []):
        metrics = item["cve"].get("metrics", {})

        for version in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            if metrics.get(version):
                cvss = metrics[version][0]["cvssData"]
                return {"score": cvss["baseScore"], "vector": cvss.get("attackVector", "")}

    return None


def why_serious(cves: list, exploited: set, scores: dict, use_scores: bool = True) -> str | None:
    for cve in cves:
        if cve in exploited:
            return f"{cve} is actively exploited"

    for cve in cves if use_scores else []:
        cvss = scores.get(cve)

        if cvss and cvss["score"] >= CRITICAL_CVSS and cvss["vector"] == "NETWORK":
            return f"{cve}, CVSS {cvss['score']} over the network"

    return None


def is_new_release(old: str, new: str) -> bool:
    return kernel_key(new)[:2] > kernel_key(old)[:2]


def find_problems(host: dict, debian: list, proxmox: list, exploited: set, scores: dict) -> dict:
    """What's worth telling, as {stable key: message}. Both lists hold only open advisories."""
    problems = {}

    for advisory in debian:
        why = why_serious(advisory["cves"], exploited, scores, advisory["source"] in NETWORK_FACING)

        if why:
            problems[advisory["id"]] = f"{advisory['source']}: {why} ({advisory['id']})"

    for advisory in proxmox:
        why = why_serious(advisory["cves"], exploited, scores)

        if advisory["no_login"]:
            why = why or "needs no login"

        if why:
            problems[advisory["id"]] = f"{advisory['title']}: {why} ({advisory['id']})"

    manager = host["pending"].get("pve-manager")

    if manager and is_new_release(manager["old"], manager["new"]):
        problems[f"release-{manager['new']}"] = f"New Proxmox release: {manager['old']} -> {manager['new']}"

    return problems


def to_tell(problems: dict, told: dict, today: date) -> list:
    """Messages that are new, or due for their reminder."""
    due = []

    for key, message in problems.items():
        last = told.get(key)

        if last is None or today - date.fromisoformat(last) >= timedelta(days=REMIND_DAYS):
            due.append((key, message))

    return due


def format_message(due: list) -> str:
    lines = [message for _, message in due]

    if len(lines) > MAX_LINES:
        return "\n".join(lines[:MAX_LINES] + [f"and {len(lines) - MAX_LINES} more"])

    return "\n".join(lines)


def wanted_scores(debian: list, proxmox: list, known: dict, exploited: set) -> list:
    """CVEs worth an NVD request: not scored yet, not on the exploited list, and able to matter."""
    cves = {cve for advisory in proxmox for cve in advisory["cves"]}

    for advisory in debian:
        if advisory["source"] in NETWORK_FACING:
            cves.update(advisory["cves"])

    return sorted(cve for cve in cves if cve not in known and cve not in exploited)


def read_env(text: str) -> dict:
    """The watchdog's .env, read as compose reads it: values may be quoted."""
    env = {}

    for line in text.splitlines():
        name, separator, value = line.strip().partition("=")

        if separator and not name.startswith("#"):
            env[name.strip()] = value.strip().strip("\"'")

    return env


def notify(message: str) -> None:
    env = read_env(ENV_FILE.read_text())
    service = env.get("HA_NOTIFY_SERVICE", "mobile_app_robins_oneplus_13")
    base = env.get("HA_BASE_URL", "http://192.168.1.10:8123")

    request = urllib.request.Request(
        f"{base}/api/services/notify/{service}",
        data=json.dumps({"title": "Proxmox update", "message": message}).encode(),
        headers={"Authorization": f"Bearer {env['HA_TOKEN']}", "Content-Type": "application/json"},
    )
    urllib.request.urlopen(request, timeout=30).close()


def load_state() -> dict:
    defaults = {"told": {}, "scores": {}, "failed_since": None, "failure_told": False}

    try:
        state = json.loads(STATE.read_text()) if STATE.exists() else {}
        return {**defaults, **state}

    except (ValueError, TypeError) as error:
        print(f"update-alert: ignoring a bad state file: {error}", file=sys.stderr)
        return defaults


def save_state(state: dict) -> None:
    temporary = STATE.with_name(STATE.name + ".tmp")
    temporary.write_text(json.dumps(state, indent=1))
    os.replace(temporary, STATE)


def latest_proxmox_advisories() -> list:
    """The thread's last two pages, so a page rollover doesn't drop an advisory still open.

    Not all pages: an old post that can't be parsed would count as open.
    """
    first = fetch(PSA_URL)
    last = max((int(number) for number in re.findall(r"page-(\d+)", first)), default=1)
    advisories = []

    for number in range(max(last - 1, 1), last + 1):
        page = first if number == 1 else fetch(f"{PSA_URL}page-{number}")

        # No PSA is fine, a last page may hold only replies; no posts at all is an error page
        if 'class="bbWrapper"' not in page:
            raise RuntimeError(f"page {number} of Proxmox's advisory thread has no posts")

        advisories += parse_proxmox_advisories(page)

    return advisories


def read_host() -> dict:
    report = subprocess.run(REPORT_COMMAND, capture_output=True, text=True, timeout=600, check=True).stdout
    host = parse_report(report)

    if not host["installed"] or not host["release"]:
        raise RuntimeError("the host's report is empty")

    return host


def read_source(name: str, fallback, failed: list, read):
    """What read() returns; if it fails, the fallback, with the name added to failed."""
    try:
        return read()

    except Exception as error:
        print(f"update-alert: {name} failed: {error}", file=sys.stderr)
        failed.append(name)
        return fallback


def check(state: dict, today: date) -> None:
    host = read_host()
    failed = []

    exploited = read_source("CISA's exploited list", set(), failed,
                            lambda: {item["cveID"] for item in json.loads(fetch(KEV_URL))["vulnerabilities"]})
    debian = read_source("Debian's advisories", [], failed,
                         lambda: pending_debian_advisories(parse_debian_advisories(fetch(DSA_URL), host["release"]), host))
    proxmox = read_source("Proxmox's forum", [], failed,
                          lambda: [advisory for advisory in latest_proxmox_advisories() if advisory_is_open(advisory, host)])

    # Not given up after one failure: CVEs go in sorted order, so one bad CVE would block those after it for good
    for cve in wanted_scores(debian, proxmox, state["scores"], exploited):
        cvss = read_source(f"NVD for {cve}", None, failed, lambda: lookup_cvss(cve))

        if cvss:
            state["scores"][cve] = cvss

    problems = find_problems(host, debian, proxmox, exploited, state["scores"])
    due = to_tell(problems, state["told"], today)

    print(f"{today}: {len(host['pending'])} pending, {len(debian)} Debian and {len(proxmox)} Proxmox "
          f"advisories open, {len(problems)} worth telling, {min(len(due), MAX_LINES)} told now")

    if due:
        notify(format_message(due))

    # After a failed source problems is incomplete: pruning would lose reminders and cause repeats
    if not failed:
        state["told"] = {key: seen for key, seen in state["told"].items() if key in problems}

    # Only what the message showed; the rest come up the next day
    state["told"].update({key: today.isoformat() for key, _ in due[:MAX_LINES]})

    if failed:
        raise RuntimeError(f"could not read {', '.join(failed)}")


def main(today: date | None = None) -> int:
    state = load_state()
    today = today or date.today()

    try:
        check(state, today)
        state["failed_since"] = None
        state["failure_told"] = False
        result = 0

    except Exception as error:
        print(f"update-alert failed: {error}", file=sys.stderr)
        state["failed_since"] = state["failed_since"] or today.isoformat()
        failed_days = (today - date.fromisoformat(state["failed_since"])).days

        if failed_days >= FAILED_DAYS_BEFORE_TELLING and not state["failure_told"]:
            try:
                notify(f"The update check has failed for {failed_days} days: {error}")
                state["failure_told"] = True

            except Exception as notify_error:
                print(f"update-alert could not tell: {notify_error}", file=sys.stderr)

        result = 1

    save_state(state)
    return result


if __name__ == "__main__":
    sys.exit(main())
