"""SPA static-file catch-all must not serve files outside the static root (path traversal)."""

from __future__ import annotations

import os

from app.main import _safe_static_file


def test_safe_static_file_blocks_traversal(tmp_path):
    root = os.path.realpath(tmp_path)
    (tmp_path / "index.html").write_text("<html>")
    (tmp_path / "logo.png").write_text("png")
    secret = tmp_path.parent / "secret.txt"
    secret.write_text("TOPSECRET")

    assert _safe_static_file(root, "logo.png") == os.path.join(root, "logo.png")   # real file inside
    assert _safe_static_file(root, "") is None                                     # SPA root
    assert _safe_static_file(root, "nope.js") is None                              # missing -> SPA
    # Traversal (raw and the shapes percent-decoding produces) must NOT escape root:
    for evil in ("../secret.txt", "../../secret.txt", "..%2f..%2fsecret.txt".replace("%2f", "/"),
                 "foo/../../secret.txt", "/etc/passwd"):
        assert _safe_static_file(root, evil) is None, evil
