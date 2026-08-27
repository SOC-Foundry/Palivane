"""palivane-s3-scan against a real S3 API, not a hand-written fake.

Every other test for this scanner injects a FakeS3, which means the parts that talk to the
service have never actually run: pagination, the binary and size skips, and the bucket
exposure calls. This exercises them against MinIO, which speaks the S3 API and supports
GetBucketPolicyStatus and GetBucketAcl, two of the three inputs to is_public().

What MinIO cannot show is a bucket it considers PUBLIC: it returns NotImplemented for
PutBucketAcl with public-read, and reports IsPublic false even for a Principal:"*"
GetObject policy. So the positive exposure paths, and "a fully-enabled Block Public Access
overrides a public grant", still need real AWS; the FakeS3 tests cover that logic and this
file does not pretend otherwise.

What IS covered is the direction that misfires more often: a private bucket, or one with an
ordinary policy, must not read as public. A false positive there flags every bucket a
customer owns.

Skipped unless MinIO is reachable. To run it:

    docker run -d --name pv-minio -p 9100:9000 \\
      -e MINIO_ROOT_USER=palivanetest -e MINIO_ROOT_PASSWORD=palivanetest123 \\
      minio/minio:latest server /data
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import urllib.error

import pytest

ENDPOINT = "http://localhost:9100"
KEY, SECRET = "palivanetest", "palivanetest123"

boto3 = pytest.importorskip("boto3", reason="boto3 not installed")


def _minio_up() -> bool:
    import urllib.request
    try:
        with urllib.request.urlopen(f"{ENDPOINT}/minio/health/live", timeout=2) as r:
            return r.status == 200
    except Exception:                                             # noqa: BLE001
        return False


pytestmark = pytest.mark.skipif(not _minio_up(), reason="MinIO not running on :9100")


def _load_cli():
    """palivane-s3-scan has no .py suffix, so import it by path."""
    path = pathlib.Path(__file__).resolve().parents[2] / "cli" / "palivane-s3-scan"
    spec = importlib.util.spec_from_loader(
        "palivane_s3_scan", importlib.machinery.SourceFileLoader("palivane_s3_scan", str(path)))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def cli():
    return _load_cli()


@pytest.fixture(scope="module")
def s3():
    return boto3.client("s3", endpoint_url=ENDPOINT, aws_access_key_id=KEY,
                        aws_secret_access_key=SECRET, region_name="us-east-1")


@pytest.fixture
def bucket(s3, request):
    name = f"pv-{request.node.name.replace('_', '-')[:50]}"
    try:
        s3.create_bucket(Bucket=name)
    except s3.exceptions.BucketAlreadyOwnedByYou:
        pass
    yield name
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
        for o in page.get("Contents", []):
            s3.delete_object(Bucket=name, Key=o["Key"])
    s3.delete_bucket(Bucket=name)


def test_listing_pages_past_the_1000_key_response_limit(cli, s3, bucket):
    """S3 returns at most 1000 keys per call. The fake never made the scanner page."""
    for i in range(1005):
        s3.put_object(Bucket=bucket, Key=f"k/{i:05d}.txt", Body=b"x")
    got = cli.list_objects(s3, bucket, "", max_objects=5000)
    assert len(got) == 1005, "pagination dropped keys"


def test_max_objects_caps_the_listing(cli, s3, bucket):
    for i in range(30):
        s3.put_object(Bucket=bucket, Key=f"{i:03d}.txt", Body=b"x")
    assert len(cli.list_objects(s3, bucket, "", max_objects=10)) == 10


def test_prefix_filters_the_listing(cli, s3, bucket):
    s3.put_object(Bucket=bucket, Key="logs/a.txt", Body=b"x")
    s3.put_object(Bucket=bucket, Key="other/b.txt", Body=b"x")
    keys = [o["key"] for o in cli.list_objects(s3, bucket, "logs/", max_objects=100)]
    assert keys == ["logs/a.txt"]


def test_binary_objects_read_as_none_and_text_decodes(cli, s3, bucket):
    s3.put_object(Bucket=bucket, Key="t.txt", Body="hello world".encode())
    s3.put_object(Bucket=bucket, Key="b.bin", Body=b"\xff\xfe\x00\x01binary")
    assert cli.read_object(s3, bucket, "t.txt") == "hello world"
    assert cli.read_object(s3, bucket, "b.bin") is None


def test_a_private_bucket_is_not_reported_public(cli, s3, bucket):
    """The failure mode that matters most: a false 'private' hides the crown-jewel case,
    but a false 'public' flags every bucket a customer owns. MinIO implements no
    PublicAccessBlock, which is exactly the 'no block config' shape this must tolerate."""
    assert cli.is_public(s3, bucket) is False


def test_a_bucket_policy_alone_does_not_make_it_public(cli, s3, bucket):
    """The verdict comes from the service's own IsPublic evaluation, never from the mere
    presence of a bucket policy. Most buckets have one; reading that as public would flag
    almost everything a customer owns.

    MinIO happens to report IsPublic false even for a Principal:"*" GetObject policy, which
    is not how AWS evaluates it. That divergence is the reason the POSITIVE exposure paths
    cannot be verified here (see the module docstring) but it makes this bucket a clean
    example of a policy that the service does not consider public."""
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                       "Resource": f"arn:aws:s3:::{bucket}/*"}]}))
    assert s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"]["IsPublic"] is False
    assert cli.is_public(s3, bucket) is False


def test_exposure_check_survives_a_bucket_it_cannot_read(cli, s3):
    """Every call in is_public is guarded; AccessDenied must not abort a scan."""
    assert cli.is_public(s3, "definitely-not-a-bucket-owned-here") is False


def test_end_to_end_secret_is_found_locally_and_no_bytes_are_sent(cli, s3, bucket, monkeypatch):
    """The whole point of the change, against a real object store: the scanner reads the
    object, detects in-process, and the request carries findings but none of the content."""
    secret = "AKIAIOSFODNN7EXAMPLE"
    s3.put_object(Bucket=bucket, Key="exports/.env", Body=f"AWS_ACCESS_KEY_ID={secret}\n".encode())
    s3.put_object(Bucket=bucket, Key="notes.txt", Body=b"nothing sensitive here")

    sent = {}

    def fake_urlopen(req, timeout=None):
        sent["body"] = json.loads(req.data.decode())

        class R:
            status = 200
            def read(self_inner): return json.dumps(
                {"action": "block", "scanned": 2, "bucket": bucket, "public": False,
                 "objects": [{"key": "exports/.env", "action": "block"}]}).encode()
            def __enter__(self_inner): return self_inner
            def __exit__(self_inner, *a): return False
        return R()

    monkeypatch.setattr(cli.urllib.request, "urlopen", fake_urlopen)
    objs = []
    for o in cli.list_objects(s3, bucket, "", max_objects=100):
        content = cli.read_object(s3, bucket, o["key"])
        if content is None:
            continue
        found = cli.detect.scan_all(content)
        if found:
            objs.append({"key": o["key"], "findings": [
                {"category": c, "label": l, "line": n, "masked": m} for c, l, n, m in found]})
    cli.post_batch({"url": "http://backend", "token": "ak_x"}, bucket, "us-east-1", False,
                   objs, record=False)

    body = sent["body"]
    assert [o["key"] for o in body["objects"]] == ["exports/.env"], "clean object should not be sent"
    assert body["objects"][0]["findings"][0]["category"] == "secret_leak"
    assert secret not in json.dumps(body), "the raw secret must never leave the account"
    assert "content" not in body["objects"][0]
