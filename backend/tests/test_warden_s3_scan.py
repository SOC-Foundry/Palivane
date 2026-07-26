"""S3 at-rest scanner (cli/warden-s3-scan): public-exposure detection, object filtering,
payload shape, and dry-run. boto3 isn't required — the S3 client is a fake injected into the
boto3-touching functions, and urlopen is monkeypatched to capture the POST body."""

from __future__ import annotations

import importlib.util
import io
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path

# The script has no .py extension, so the source loader is named explicitly.
_path = Path(__file__).resolve().parents[2] / "cli" / "warden-s3-scan"
_spec = importlib.util.spec_from_loader("warden_s3_scan", SourceFileLoader("warden_s3_scan", str(_path)))
s3s = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(s3s)


class FakeS3:
    """A minimal boto3-S3 stand-in. Each hook can be a value to return or an Exception to
    raise, mirroring AccessDenied / missing-config behavior."""

    def __init__(self, *, pab=None, policy_status=None, acl=None, listings=None, objects=None):
        self._pab = pab
        self._policy_status = policy_status
        self._acl = acl if acl is not None else {"Grants": []}
        self._listings = listings or [{"Contents": [], "IsTruncated": False}]
        self._objects = objects or {}
        self._list_calls = 0

    def _resolve(self, val):
        if isinstance(val, Exception):
            raise val
        return val

    def get_public_access_block(self, Bucket):
        if self._pab is None:
            raise RuntimeError("NoSuchPublicAccessBlockConfiguration")
        return self._resolve(self._pab)

    def get_bucket_policy_status(self, Bucket):
        if self._policy_status is None:
            return {"PolicyStatus": {"IsPublic": False}}
        return self._resolve(self._policy_status)

    def get_bucket_acl(self, Bucket):
        return self._resolve(self._acl)

    def list_objects_v2(self, **kw):
        page = self._listings[min(self._list_calls, len(self._listings) - 1)]
        self._list_calls += 1
        return page

    def get_object(self, Bucket, Key):
        val = self._objects[Key]
        if isinstance(val, Exception):
            raise val
        return {"Body": io.BytesIO(val)}


_BLOCKED_PAB = {"PublicAccessBlockConfiguration": {
    "BlockPublicAcls": True, "IgnorePublicAcls": True,
    "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}
_ALLUSERS_GRANT = {"Grants": [
    {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}]}


# --- Public-exposure detection --------------------------------------------------------

def test_public_when_acl_grants_allusers():
    # An AllUsers ACL grant with no full Block-Public-Access => actually public.
    s3 = FakeS3(pab=None, acl=_ALLUSERS_GRANT)
    assert s3s.is_public(s3, "b") is True


def test_public_when_policy_status_ispublic():
    # AWS's own policy evaluation says IsPublic, and BPA isn't fully on => public.
    s3 = FakeS3(pab=None, policy_status={"PolicyStatus": {"IsPublic": True}})
    assert s3s.is_public(s3, "b") is True


def test_full_bpa_overrides_public_grant():
    # A public ACL grant is neutralized by a fully-enabled Block Public Access => not public.
    s3 = FakeS3(pab=_BLOCKED_PAB, acl=_ALLUSERS_GRANT)
    assert s3s.is_public(s3, "b") is False


def test_missing_block_config_alone_is_not_public():
    # No bucket-level block config but NO public grant either — most private buckets look like
    # this; treating it as public would flag everything.
    s3 = FakeS3(pab=None, acl={"Grants": []})
    assert s3s.is_public(s3, "b") is False


def test_not_public_with_block_and_no_public_policy():
    # All block flags true, no public policy, no public ACL grant => not public.
    s3 = FakeS3(pab=_BLOCKED_PAB, policy_status={"PolicyStatus": {"IsPublic": False}},
                acl={"Grants": []})
    assert s3s.is_public(s3, "b") is False


def test_is_public_survives_access_denied():
    # AccessDenied on every call must not crash; with no positive signal => not public.
    err = RuntimeError("AccessDenied")
    s3 = FakeS3(pab=err, policy_status=err, acl=err)
    assert s3s.is_public(s3, "b") is False


# --- Object listing + read (filtering happens in main) --------------------------------

def test_read_object_skips_binary():
    s3 = FakeS3(objects={"k": b"\xff\xfe\x00\x01binary"})
    assert s3s.read_object(s3, "b", "k") is None


def test_read_object_decodes_and_truncates():
    s3 = FakeS3(objects={"k": ("A" * (s3s.MAX_CONTENT + 50)).encode()})
    out = s3s.read_object(s3, "b", "k")
    assert len(out) == s3s.MAX_CONTENT


def test_list_objects_caps_at_max():
    contents = [{"Key": f"k{i}", "Size": 10} for i in range(5)]
    s3 = FakeS3(listings=[{"Contents": contents, "IsTruncated": False}])
    got = s3s.list_objects(s3, "b", "", max_objects=3)
    assert len(got) == 3


# --- End-to-end via main(): filtering, payload shape, dry-run -------------------------

def _run_main(monkeypatch, s3, argv, *, url="https://w.example.com", token="ak_test",
              urlopen=None):
    monkeypatch.setattr(s3s, "_s3_client", lambda region: s3)
    if url is not None:
        monkeypatch.setenv("WARDEN_URL", url)
    else:
        monkeypatch.delenv("WARDEN_URL", raising=False)
    if token is not None:
        monkeypatch.setenv("WARDEN_TOKEN", token)
    else:
        monkeypatch.delenv("WARDEN_TOKEN", raising=False)
    monkeypatch.setattr(s3s.sys, "argv", ["warden-s3-scan", *argv])
    if urlopen is not None:
        monkeypatch.setattr(s3s.urllib.request, "urlopen", urlopen)
    return s3s.main()


def _capturing_urlopen(captured, response):
    class _Resp:
        def __init__(self, body):
            self._body = body
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self):
            return json.dumps(response).encode()

    def _urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        captured["body"] = json.loads(req.data.decode())
        return _Resp(response)

    return _urlopen


def test_payload_shape_and_filtering(monkeypatch):
    # small.txt (ok), big.txt (over size cap -> skipped), bin (binary -> skipped).
    listings = [{"Contents": [
        {"Key": "small.txt", "Size": 10},
        {"Key": "big.txt", "Size": 5_000_000},
        {"Key": "bin", "Size": 20},
    ], "IsTruncated": False}]
    objects = {"small.txt": b"TOKEN=ghp_x", "bin": b"\xff\xfe\x00binary"}
    s3 = FakeS3(pab=None, acl=_ALLUSERS_GRANT, listings=listings, objects=objects)

    captured = {}
    resp = {"action": "block", "scanned": 1, "bucket": "b", "public": True, "objects": []}
    rc = _run_main(monkeypatch, s3, ["b", "--max-object-bytes", "1000000"],
                   urlopen=_capturing_urlopen(captured, resp))

    body = captured["body"]
    assert captured["url"].endswith("/api/scan/s3")
    assert captured["headers"].get("X-warden-token") == "ak_test"
    assert body["bucket"] == "b"
    assert body["public"] is True                      # AllUsers ACL grant detected
    # Only the small text object survives filtering; big + binary are dropped.
    assert body["objects"] == [{"key": "small.txt", "content": "TOKEN=ghp_x"}]
    assert rc == 0   # backend returned no flagged objects -> nothing blocking


def test_block_finding_exits_1(monkeypatch):
    listings = [{"Contents": [{"Key": "a.env", "Size": 10}], "IsTruncated": False}]
    s3 = FakeS3(pab=_BLOCKED_PAB, listings=listings, objects={"a.env": b"AKIA..."})
    resp = {"action": "block", "scanned": 1, "bucket": "b", "public": False,
            "objects": [{"key": "a.env", "action": "block", "severity": "high",
                         "signals": [{"category": "secret_leak", "evidence": "AKIA…"}]}]}
    rc = _run_main(monkeypatch, s3, ["b"], urlopen=_capturing_urlopen({}, resp))
    assert rc == 1


def test_dry_run_sends_nothing(monkeypatch):
    listings = [{"Contents": [{"Key": "a.txt", "Size": 10}], "IsTruncated": False}]
    s3 = FakeS3(pab=_BLOCKED_PAB, listings=listings, objects={"a.txt": b"hello"})

    def _boom(req, timeout=None):
        raise AssertionError("--dry-run must not make an HTTP request")

    rc = _run_main(monkeypatch, s3, ["b", "--dry-run"], token=None, urlopen=_boom)
    assert rc == 0   # dry-run works even without a token, and sends nothing
