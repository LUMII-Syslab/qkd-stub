"""Helpers shared by the process-level tests."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("QKD_STUB_BIN", ROOT / ("target/debug/qkd-stub.exe" if os.name == "nt" else "target/debug/qkd-stub")))
PROCESS_FLAGS = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0


def script(name):
    return str(ROOT / 'scripts' / (name + ('.bat' if os.name == 'nt' else '.sh')))


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def write_config(path, port, pki, mapping, psk):
    """Write a saved configuration. Absolute paths are used as-is."""
    values = {
        'listen': f'127.0.0.1:{port}', 'kme_id': 'KME-A', 'peer_kme_id': 'KME-B',
        'tls_cert': (pki / 'server.crt').as_posix(), 'tls_key': (pki / 'server.key').as_posix(),
        'tls_client_ca': (pki / 'ca.crt').as_posix(), 'psk_file': Path(psk).as_posix(),
        'sae_map': Path(mapping).as_posix(),
    }
    path.write_text(''.join(f'{key} = {json.dumps(value)}\n' for key, value in values.items()))
    return path


def serve(config, log=None, **kwargs):
    return subprocess.Popen([str(BINARY), '--config', str(config), 'serve'], stdout=log, stderr=log,
                            creationflags=PROCESS_FLAGS, **kwargs)


def start(port, pki, mapping, log, ctx, psk, fetch):
    """Start `serve` and wait until `fetch(port, 'B/status', ctx)` succeeds."""
    config = write_config(Path(psk).parent / f'config-{port}.toml', port, pki, mapping, psk)
    proc = serve(config, log)
    for _ in range(100):
        if proc.poll() is not None:
            raise AssertionError(f'Server exited: {proc.returncode}')
        try:
            assert fetch(port, 'B/status', ctx)[0] == 200
            return proc
        except (OSError, urllib.error.URLError):
            time.sleep(.05)
    stop(proc)
    raise AssertionError('Server failed to start')


def stop(proc):
    if proc.poll() is None:
        if os.name == 'nt':
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            proc.terminate()
        try:
            proc.wait(timeout=7)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise AssertionError("Server did not shut down gracefully")
    assert proc.returncode == 0, proc.returncode
