"""The Slack bot token is only ever sent to Slack's own file hosts. An external or remote
file's url_private is whatever its creator set, so it must never get the Authorization
header."""
from __future__ import annotations

import pytest

from app import saas_connectors as sc

GOOD = "https://files.slack.com/files-pri/T1-F1/download/report.txt"


@pytest.mark.parametrize("f", [
    {"url_private": GOOD},
    {"url_private_download": GOOD, "url_private": "https://host.example/x"},
    {"url_private": "https://files.slack-gov.com/files-pri/T1-F1/report.txt"},
])
def test_slack_hosted_files_are_fetched(f):
    assert sc._slack_file_url(f)


@pytest.mark.parametrize("f", [
    {"url_private": "https://host.example/files-pri/report.txt"},
    {"url_private": "http://files.slack.com/files-pri/report.txt"},
    {"url_private": "https://files.slack.com.host.example/report.txt"},
    {"url_private": "https://files.slack.com:8443/report.txt"},
    {"url_private": "https://u@files.slack.com/report.txt"},
    {"url_private": GOOD, "is_external": True},
    {"url_private": GOOD, "mode": "external"},
    {"url_private": ""},
    {},
])
def test_other_hosts_and_external_files_are_skipped(f):
    assert sc._slack_file_url(f) == ""


def test_skipped_file_never_reaches_the_network(monkeypatch):
    calls = []
    monkeypatch.setattr(sc, "_http_fetch_capped", lambda *a: calls.append(a) or b"")
    out = sc._slack_file_text({"url_private": "https://host.example/a.txt", "name": "a.txt"},
                              {"Authorization": "Bearer placeholder"})
    assert out == ("", "", False) and calls == []
