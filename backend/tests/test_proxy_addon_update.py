"""Proxy addon updates reach the RUNNING proxy (palivane-desktop `update-addon`).

The addon used to change only on disk, and only when palivane-posture ran (a Claude Code
session start) or someone re-ran `palivane connect`. update-addon fetches a verified build,
swaps it in only when its hash differs, confirms the running proxy loaded it (mitmproxy
reloads a replaced -s script; the addon's running() writes proxy-loaded.json), restarts the
service once only if it did not, and puts the old file back if even that fails.

These run the real bash against a file:// release with systemctl/launchctl stubbed. The
mitmproxy reload is simulated by a watcher that does what mitmdump does: notice the file's
mtime moved and load it, i.e. write the marker for the bytes now on disk."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import threading
import time
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_DESKTOP = _ROOT / "cli" / "palivane-desktop"

pytestmark = pytest.mark.skipif(
    not (shutil.which("openssl") and shutil.which("python3") and shutil.which("curl")),
    reason="needs openssl + python3 + curl")

OLD = b"# addon 1.4.0\n"
NEW = b"# addon 1.4.1\n"


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _marker(home: Path, body: bytes) -> None:
    st = home / ".palivane"
    (st / "proxy-loaded.json").write_text(json.dumps({"version": "x", "sha256": _sha(body)}))


@pytest.fixture
def listener():
    """Something listening where the proxy would be, so the updater sees it running."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(16)
    yield s.getsockname()[1]
    s.close()


class Reloader:
    """mitmdump's script watcher, reduced to what the updater observes: when the addon's
    mtime moves forward, 'load' it, i.e. write the marker for the bytes on disk."""

    def __init__(self, home: Path):
        self.addon = home / ".palivane" / "palivane_addon.py"
        self.home = home
        self.stop = threading.Event()
        self.loads = 0
        self.t = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        last = self.addon.stat().st_mtime
        while not self.stop.wait(0.05):
            try:
                m = self.addon.stat().st_mtime
                if m > last:
                    last = m
                    _marker(self.home, self.addon.read_bytes())
                    self.loads += 1
            except OSError:
                pass

    def __enter__(self):
        self.t.start()
        return self

    def __exit__(self, *a):
        self.stop.set()
        self.t.join(5)


def _setup(tmp_path, signed_release, served: bytes = NEW, manifest_body: bytes | None = None,
           sig: bool = True, restart: str = "loads"):
    """HOME with an installed OLD addon; a file:// release serving `served` (the manifest
    signs `manifest_body`, default `served`); systemctl/launchctl stubs that log every call.
    restart="loads": a restart loads the file on disk (writes the marker); "noop": restarts
    but nothing loads; "fails": the restart command fails."""
    home = tmp_path / "home"
    (home / ".palivane").mkdir(parents=True)
    addon = home / ".palivane" / "palivane_addon.py"
    addon.write_bytes(OLD)
    os.utime(addon, (time.time() - 3600, time.time() - 3600))
    srv = tmp_path / "srv" / "cli"
    srv.mkdir(parents=True)
    manifest, good_sig = signed_release({"palivane_addon.py": manifest_body or served})
    (srv / "manifest.json").write_bytes(manifest)
    if sig:
        (srv / "manifest.sig").write_bytes(good_sig)
    (srv / "palivane_addon.py").write_bytes(served)

    stub = tmp_path / "stub"
    stub.mkdir()
    log = tmp_path / "calls.log"
    load = (f'python3 -c "import hashlib,json,sys; '
            f"open(sys.argv[2],'w').write(json.dumps({{'sha256': hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest()}}))\" "
            f'"{addon}" "{home}/.palivane/proxy-loaded.json"')
    on_restart = {"loads": load, "noop": "true", "fails": "exit 1"}[restart]
    for tool in ("systemctl", "launchctl"):
        (stub / tool).write_text(
            "#!/bin/sh\n"
            f'echo "{tool} $*" >> "{log}"\n'
            'case "$*" in *restart*|*kickstart*) ' f"{on_restart} ;; esac\n"
            "exit 0\n")
        os.chmod(stub / tool, 0o755)
    env = {"HOME": str(home), "PALIVANE_STATE_DIR": str(home / ".palivane"),
           "PALIVANE_URL": f"file://{tmp_path / 'srv'}",
           "PATH": f"{stub}{os.pathsep}{os.environ['PATH']}", "PALIVANE_UPDATE_WAIT": "2"}
    return home, addon, log, env


def _run(env: dict, port: int, body: str = "cmd_update_addon", argv0: str | None = None,
         os_name: str | None = None) -> subprocess.CompletedProcess:
    pre = f'OS="{os_name}"\n' if os_name else ""
    script = f'set -euo pipefail\nsource "{_DESKTOP}"\n{pre}{body}\n'
    cmd = ["bash", "-c", script] + ([argv0] if argv0 else [])
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                          env={**os.environ, **env, "PALIVANE_PROXY_PORT": str(port)})


def _calls(log: Path) -> list[str]:
    return log.read_text().splitlines() if log.exists() else []


def _ledger(home: Path) -> dict:
    p = home / ".palivane" / "scan-failed-proxy.json"
    return json.loads(p.read_text()) if p.exists() else {}


def test_the_script_parses():
    assert subprocess.run(["bash", "-n", str(_DESKTOP)]).returncode == 0


def test_new_addon_is_reloaded_in_place_without_a_restart(tmp_path, signed_release, listener):
    home, addon, log, env = _setup(tmp_path, signed_release)
    with Reloader(home) as r:
        out = _run(env, listener)
    assert out.returncode == 0, out.stdout + out.stderr
    assert addon.read_bytes() == NEW
    assert r.loads == 1                                  # exactly one reload
    assert not any("restart" in c for c in _calls(log))  # and no restart
    assert "reloaded it in place" in out.stdout
    assert not (home / ".palivane" / "palivane_addon.py.prev").exists()
    assert not list((home / ".palivane").glob("*.palivane-new*"))
    assert not (home / ".palivane" / "update-addon.lock").exists()     # released
    assert _ledger(home) == {}


def _hold_lock(home: Path, pid: int, age_s: float = 0) -> Path:
    lock = home / ".palivane" / "update-addon.lock"
    lock.mkdir()
    (lock / "pid").write_text(f"{pid}\n")
    if age_s:
        t = time.time() - age_s
        os.utime(lock, (t, t))
    return lock


def test_a_second_update_leaves_it_to_the_one_running(tmp_path, signed_release, listener):
    # Two writers sharing one temp name was the "could not write" failure; two runs also
    # interleaved the backup, the marker wait, the restart and the rollback.
    home, addon, log, env = _setup(tmp_path, signed_release)
    lock = _hold_lock(home, os.getpid())                 # a live owner
    out = _run(env, listener)
    assert out.returncode == 0, out.stdout + out.stderr  # not a failure: the other run has it
    assert "already running" in out.stdout
    assert addon.read_bytes() == OLD and _calls(log) == [] and lock.exists()


@pytest.mark.parametrize("why", ["dead owner", "too old"])
def test_a_stale_lock_is_taken_over(tmp_path, signed_release, listener, why):
    home, addon, log, env = _setup(tmp_path, signed_release)
    dead = subprocess.Popen(["true"])
    dead.wait()
    if why == "dead owner":
        _hold_lock(home, dead.pid)
    else:
        _hold_lock(home, os.getpid(), age_s=3600)
    with Reloader(home):
        out = _run(env, listener)
    assert out.returncode == 0, out.stdout + out.stderr
    assert addon.read_bytes() == NEW
    assert not (home / ".palivane" / "update-addon.lock").exists()


def test_two_updates_at_once_end_with_one_clean_update(tmp_path, signed_release, listener):
    home, addon, log, env = _setup(tmp_path, signed_release)
    # A slow download, so both runs are mid-update at once (the timer firing while a session
    # start hands posture's update over). Without it they simply run one after the other.
    slow = tmp_path / "slow"
    slow.mkdir()
    (slow / "curl").write_text(f'#!/bin/sh\nsleep 1\nexec "{shutil.which("curl")}" "$@"\n')
    os.chmod(slow / "curl", 0o755)
    env["PATH"] = f"{slow}{os.pathsep}{env['PATH']}"
    script = f'set -euo pipefail\nsource "{_DESKTOP}"\ncmd_update_addon\n'
    full = {**os.environ, **env, "PALIVANE_PROXY_PORT": str(listener)}
    with Reloader(home) as r:
        procs = [subprocess.Popen(["bash", "-c", script], env=full, text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT) for _ in range(2)]
        outs = [p.communicate(timeout=120)[0] for p in procs]
    assert [p.returncode for p in procs] == [0, 0], outs
    # Exactly one run does the update; without the lock both did all of it (seen with the
    # old script under this same overlap): two swaps, two marker waits, two chances to restart.
    assert sum("addon updated" in o for o in outs) == 1, outs
    assert sum("already running" in o for o in outs) == 1, outs
    assert addon.read_bytes() == NEW
    assert r.loads == 1                                  # swapped in once
    assert not any("restart" in c for c in _calls(log))  # nobody restarted the proxy
    assert _ledger(home) == {}                            # and nobody rolled back
    assert not list((home / ".palivane").glob("*.palivane-new*"))
    assert not (home / ".palivane" / "palivane_addon.py.prev").exists()


def test_a_proxy_that_does_not_reload_is_restarted_exactly_once(tmp_path, signed_release, listener):
    home, addon, log, env = _setup(tmp_path, signed_release, restart="loads")
    out = _run(env, listener)                            # no Reloader: nothing reloads
    assert out.returncode == 0, out.stdout + out.stderr
    assert addon.read_bytes() == NEW
    assert [c for c in _calls(log) if "restart" in c] == [
        "systemctl --user restart palivane-proxy.service"]
    assert "restarted to load it" in out.stdout
    assert _ledger(home) == {}


def test_macos_restarts_the_launchd_job(tmp_path, signed_release, listener):
    home, addon, log, env = _setup(tmp_path, signed_release, restart="loads")
    out = _run(env, listener, os_name="Darwin")
    assert out.returncode == 0, out.stdout + out.stderr
    kicks = [c for c in _calls(log) if "kickstart" in c]
    assert kicks == [f"launchctl kickstart -k gui/{os.getuid()}/io.palivane.proxy"]
    assert addon.read_bytes() == NEW


def test_unchanged_addon_touches_nothing(tmp_path, signed_release, listener):
    home, addon, log, env = _setup(tmp_path, signed_release, served=OLD)
    before = addon.stat().st_mtime
    with Reloader(home) as r:
        out = _run(env, listener)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "current" in out.stdout
    assert addon.read_bytes() == OLD and addon.stat().st_mtime == before
    assert r.loads == 0 and _calls(log) == []


@pytest.mark.parametrize("case", ["tampered", "unsigned", "forged"])
def test_unverified_addon_keeps_the_installed_copy(tmp_path, signed_release, listener, case):
    if case == "tampered":      # served bytes differ from what the signed manifest says
        home, addon, log, env = _setup(tmp_path, signed_release, served=b"# evil\n",
                                       manifest_body=NEW)
    elif case == "unsigned":
        home, addon, log, env = _setup(tmp_path, signed_release, sig=False)
    else:                       # a manifest that matches the evil file, with a bad signature
        home, addon, log, env = _setup(tmp_path, signed_release, served=b"# evil\n")
        (tmp_path / "srv" / "cli" / "manifest.sig").write_bytes(b"AAAA")
    before = addon.stat().st_mtime
    with Reloader(home) as r:
        out = _run(env, listener)
    assert out.returncode != 0
    assert "kept the installed copy" in out.stdout
    assert addon.read_bytes() == OLD and addon.stat().st_mtime == before
    assert r.loads == 0 and _calls(log) == []


@pytest.mark.parametrize("restart", ["fails", "noop"])
def test_a_build_that_will_not_load_is_rolled_back(tmp_path, signed_release, listener, restart):
    """Neither the reload nor a restart loads the new build: the previous file goes back,
    the proxy is restarted on it, and the failure is counted in the proxy's ledger."""
    home, addon, log, env = _setup(tmp_path, signed_release, restart=restart)
    out = _run(env, listener)
    assert out.returncode != 0
    assert addon.read_bytes() == OLD
    assert "restoring the previous one" in out.stdout
    restarts = [c for c in _calls(log) if "restart" in c]
    assert len(restarts) == 2                  # the attempt, then back on the old file
    led = _ledger(home)
    assert led["reasons"] == {"update-failed": 1} and led["count"] == 1
    assert led["first"] <= led["last"]
    # A second failure adds to it, keeping what the proxy had already counted.
    led["reasons"]["timeout"] = 2
    (home / ".palivane" / "scan-failed-proxy.json").write_text(json.dumps(led))
    _run(env, listener)
    assert _ledger(home)["reasons"] == {"timeout": 2, "update-failed": 2}


def test_rollback_ledger_is_one_the_proxy_reports(tmp_path, signed_release, listener):
    """What the updater writes survives the addon's own sanitizer, so it is delivered."""
    home, _, _, env = _setup(tmp_path, signed_release, restart="fails")
    _run(env, listener)
    spec = importlib.util.spec_from_loader(
        "pv_addon_upd", SourceFileLoader("pv_addon_upd", str(_ROOT / "proxy" / "palivane_addon.py")))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    raw = _ledger(home)
    assert mod._failopen_clean(raw)["reasons"] == {"update-failed": 1}


def test_proxy_not_running_just_swaps_the_file(tmp_path, signed_release):
    home, addon, log, env = _setup(tmp_path, signed_release)
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    free = s.getsockname()[1]
    s.close()                                  # nothing listens there
    out = _run(env, free)
    assert out.returncode == 0, out.stdout + out.stderr
    assert addon.read_bytes() == NEW
    assert _calls(log) == []
    assert "not running" in out.stdout


def test_update_timer_is_armed_once_and_only_for_the_installed_copy(tmp_path, signed_release,
                                                                     listener):
    home, _, log, env = _setup(tmp_path, signed_release)
    bin_dir = home / ".palivane" / "bin"
    bin_dir.mkdir()
    installed = bin_dir / "palivane-desktop"
    shutil.copy(_DESKTOP, installed)
    unit_dir = home / ".config" / "systemd" / "user"

    out = _run(env, listener, body="ensure_update_timer", argv0=str(installed), os_name="Linux")
    assert out.returncode == 0, out.stdout + out.stderr
    svc = (unit_dir / "palivane-proxy-update.service").read_text()
    assert f"ExecStart={installed} update-addon" in svc
    assert f"Environment=PALIVANE_URL={env['PALIVANE_URL']}" in svc
    assert "OnUnitActiveSec=6h" in (unit_dir / "palivane-proxy-update.timer").read_text()
    assert "systemctl --user enable --now palivane-proxy-update.timer" in _calls(log)

    n = len(_calls(log))                       # idempotent: nothing rewritten or reloaded
    _run(env, listener, body="ensure_update_timer", argv0=str(installed), os_name="Linux")
    assert len(_calls(log)) == n

    # Run from anywhere else (a checkout, a temp download): no timer pointing at it.
    shutil.rmtree(unit_dir)
    _run(env, listener, body="ensure_update_timer", argv0=str(_DESKTOP), os_name="Linux")
    assert not unit_dir.exists()


def test_dispatch_knows_update_addon():
    src = _DESKTOP.read_text()
    assert "update-addon)  cmd_update_addon" in src


# --- the addon announces the build it loaded -----------------------------------------------

def _addon(name="pv_addon_marker"):
    spec = importlib.util.spec_from_loader(
        name, SourceFileLoader(name, str(_ROOT / "proxy" / "palivane_addon.py")))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_running_writes_the_loaded_marker(tmp_path, monkeypatch):
    monkeypatch.setenv("PALIVANE_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("PALIVANE_PROXY_INTERCEPT_ALL", "true")   # no mitmproxy ctx needed
    mod = _addon()
    mod.PalivaneGuard().running()
    m = json.loads((tmp_path / "proxy-loaded.json").read_text())
    src = (_ROOT / "proxy" / "palivane_addon.py").read_bytes()
    assert m["sha256"] == _sha(src) and m["version"] == mod.VERSION and m["pid"] == os.getpid()
    assert not list(tmp_path.glob(".proxy-loaded.*"))


def test_loaded_marker_never_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("PALIVANE_STATE_DIR", str(tmp_path / "f"))
    (tmp_path / "f").write_text("a file where the directory should be")
    _addon("pv_addon_marker2").write_loaded_marker()


# --- posture and connect hand the addon to palivane-desktop --------------------------------

def _load_cli(name, mod):
    spec = importlib.util.spec_from_loader(mod, SourceFileLoader(mod, str(_ROOT / "cli" / name)))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _fake_desktop(home: Path, body: bytes, log: Path) -> None:
    """An installed palivane-desktop whose update-addon installs `body` and logs the call."""
    d = home / ".palivane" / "bin"
    d.mkdir(parents=True, exist_ok=True)
    p = d / "palivane-desktop"
    p.write_text(
        "#!/bin/sh\n# update-addon\n"
        f'echo "$1 $PALIVANE_URL" >> "{log}"\n'
        f"printf '%s' '{body.decode()}' > \"{home}/.palivane/palivane_addon.py\"\n")
    os.chmod(p, 0o755)


def test_posture_hands_the_addon_to_palivane_desktop(tmp_path, monkeypatch, signed_release):
    wp = _load_cli("palivane-posture", "pv_posture_upd")
    home = tmp_path / "home"
    (home / ".palivane").mkdir(parents=True)
    addon = home / ".palivane" / "palivane_addon.py"
    addon.write_bytes(OLD)
    monkeypatch.setenv("HOME", str(home))
    log = tmp_path / "desktop.log"
    _fake_desktop(home, NEW, log)
    manifest, sig = signed_release({"palivane_addon.py": NEW})
    fetched = []

    def fetch(url, token, timeout=20.0):
        name = url.rsplit("/cli/", 1)[-1]
        fetched.append(name)
        return {"manifest.json": manifest, "manifest.sig": sig}.get(name, NEW)
    monkeypatch.setattr(wp, "_fetch", fetch)
    monkeypatch.setattr(wp, "_UPDATE_DIRS", (str(home / ".palivane"),))
    n = wp.self_update({"url": "https://pv.example", "token": "t"}, {}, say=lambda *a: None)
    assert n == 1 and addon.read_bytes() == NEW
    assert log.read_text().split() == ["update-addon", "https://pv.example"]
    assert "palivane_addon.py" not in fetched          # posture did not swap it itself


def test_posture_swaps_it_itself_for_an_older_palivane_desktop(tmp_path, monkeypatch,
                                                                signed_release):
    wp = _load_cli("palivane-posture", "pv_posture_upd2")
    home = tmp_path / "home"
    (home / ".palivane" / "bin").mkdir(parents=True)
    (home / ".palivane" / "bin" / "palivane-desktop").write_text("#!/bin/sh\nexit 1\n")
    addon = home / ".palivane" / "palivane_addon.py"
    addon.write_bytes(OLD)
    monkeypatch.setenv("HOME", str(home))
    manifest, sig = signed_release({"palivane_addon.py": NEW})
    monkeypatch.setattr(wp, "_fetch", lambda url, token, timeout=20.0: {
        "manifest.json": manifest, "manifest.sig": sig}.get(url.rsplit("/cli/", 1)[-1], NEW))
    monkeypatch.setattr(wp, "_UPDATE_DIRS", (str(home / ".palivane"),))
    assert wp.self_update({"url": "https://pv.example", "token": "t"}, {},
                          say=lambda *a: None) == 1
    assert addon.read_bytes() == NEW


def test_connect_hands_the_addon_to_palivane_desktop(tmp_path, monkeypatch, signed_release):
    wc = _load_cli("palivane-connect", "pv_connect_upd")
    home = tmp_path / "home"
    (home / ".palivane").mkdir(parents=True)
    addon = home / ".palivane" / "palivane_addon.py"
    addon.write_bytes(OLD)
    monkeypatch.setenv("HOME", str(home))
    log = tmp_path / "desktop.log"
    _fake_desktop(home, NEW, log)
    manifest, sig = signed_release({"palivane_addon.py": NEW,
                                    **{n: b"# v2\n" for n in wc._PLANE_SCRIPTS}})
    monkeypatch.setattr(wc, "_http_get", lambda url: {
        "manifest.json": manifest, "manifest.sig": sig}.get(url.rsplit("/", 1)[-1], b"# v2\n"))
    monkeypatch.setattr(wc, "_MANAGED_BIN", str(tmp_path / "bin"))
    monkeypatch.setattr(wc, "_in_repo_checkout", lambda: False)
    monkeypatch.setattr(wc.sys, "argv", ["palivane-connect"])
    msgs = wc._refresh_planes("https://pv.example")
    assert addon.read_bytes() == NEW
    assert log.read_text().split() == ["update-addon", "https://pv.example"]
    assert not any("palivane_addon.py" in m for m in msgs if "could not" in m)


# --- Windows: same steps in palivane-desktop.ps1 (no PowerShell here, so checked as text) --

def test_windows_port_has_the_same_update_path():
    ps = (_ROOT / "cli" / "palivane-desktop.ps1").read_text()
    assert '"update-addon")]' in ps and '"update-addon" { exit (Invoke-UpdateAddon) }' in ps
    body = ps.split("function Invoke-UpdateAddonLocked", 1)[1].split("\nfunction ", 1)[0]
    # Verified first, unchanged hash is a no-op, then reload -> one restart -> rollback.
    order = ["Get-VerifiedManifest", "-eq $want", "Save-VerifiedFile", "Wait-Loaded $want",
             "Restart-Proxy", "Set-FileInPlace $prev $Addon", "Add-UpdateFailure"]
    pos = [body.index(s) for s in order]
    assert pos == sorted(pos)
    assert "Start-ScheduledTask -TaskName $TaskName" in ps.split("function Restart-Proxy", 1)[1]
    assert "Install-UpdateTask $palivaneUrl" in ps and "Remove-UpdateTask" in ps
    assert '"update-failed"' in ps
    # One update at a time, and no shared temp name.
    wrapper = ps.split("function Invoke-UpdateAddon {", 1)[1].split("\nfunction ", 1)[0]
    assert "System.Threading.Mutex" in wrapper and "WaitOne(0)" in wrapper
    assert "AbandonedMutexException" in wrapper and "ReleaseMutex()" in wrapper
    assert "Invoke-UpdateAddonLocked" in wrapper and "already running" in wrapper
    assert '.palivane-new"' not in ps                    # every temp name is per-run
