"""Run inside the built image with its default coder user."""
import json
import os
from pathlib import Path
import signal
import http.client
import subprocess
import time


def gateway_pids():
    result = []
    for proc in Path('/proc').glob('[0-9]*'):
        try:
            args = (proc / 'cmdline').read_bytes().split(b'\0')
            if args[:2] == [b'python', b'/opt/wanderlog-mcp/mcp/server.py']:
                result.append(int(proc.name))
        except (FileNotFoundError, ProcessLookupError):
            pass
    return result


def wait_ready(exclude=None):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        pids = gateway_pids()
        if len(pids) == 1 and pids[0] != exclude:
            try:
                connection = http.client.HTTPConnection('127.0.0.1', 8080, timeout=1)
                connection.request('GET', '/healthz', headers={'Host': 'smoke-test.example.invalid'})
                response = connection.getresponse()
                response.read()
                connection.close()
                if response.status == 200:
                    return pids[0]
            except OSError:
                pass
        time.sleep(0.2)
    log = Path(os.environ['STATE_DIR']) / 'gateway.log'
    raise AssertionError(log.read_text() if log.exists() else 'Gateway did not start')


assert subprocess.check_output(['id', '-un'], text=True).strip() == 'coder'
subprocess.run(['sudo', '-n', 'true'], check=True)
subprocess.run(['git', '--version'], check=True)
subprocess.run(['wanderlog', '--help'], check=True, stdout=subprocess.DEVNULL)
assert Path('/mcp/requirements.txt').is_file()
assert not any(Path(os.environ['STATE_DIR']).iterdir()), 'Image must ship no state'
os.environ.pop('PUBLIC_URL', None)
unconfigured = subprocess.run(['/usr/local/bin/start-gateway'], check=True, capture_output=True, text=True)
assert unconfigured.stderr.count('Gateway not started:') == 1
time.sleep(3)
assert not gateway_pids()
assert not (Path(os.environ['STATE_DIR']) / 'gateway.log').exists()
config = Path(os.environ['STATE_DIR']) / 'runtime.json'
config.write_text(json.dumps({'PUBLIC_URL': 'https://smoke-test.example.invalid'}))
config.chmod(0o600)
subprocess.run(['/usr/local/bin/start-gateway'], check=True)
first = wait_ready()
for _ in range(4):
    subprocess.run(['/usr/local/bin/start-gateway'], check=True)
time.sleep(1)
assert gateway_pids() == [first], 'Repeated startup must not duplicate gateway'
os.kill(first, signal.SIGKILL)
second = wait_ready(exclude=first)
assert second != first, 'Supervisor must restart a crashed gateway'
subprocess.run(['/usr/local/bin/start-gateway', '--restart'], check=True)
third = wait_ready(exclude=second)
assert third != second
config.chmod(0o644)
invalid = subprocess.run(['/usr/local/bin/start-gateway'], check=True, capture_output=True, text=True)
assert 'mode 0600' in invalid.stderr
config.chmod(0o600)
print(json.dumps({'user': 'coder', 'idempotent_start': True, 'crash_restart': True}))
