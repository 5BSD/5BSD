"""Record QMP lifecycle events without requesting guest shutdown.

QEMU's SHUTDOWN guest/reason fields distinguish guest power-off from a host
termination. ARM PSCI power-off need not print the x86 ACPI console message.
Reference: https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html
"""
import json
import socket
import threading
import time


class ShutdownEvidence:
    def __init__(self, directory):
        self.socket_path = directory / 'qmp.sock'
        self.log_path = directory / 'qmp-events.jsonl'
        assert not self.socket_path.exists() and not self.log_path.exists()
        self.events = []
        self.error = None
        self.thread = None

    @property
    def arguments(self):
        return ['-qmp', f'unix:{self.socket_path},server=on,wait=off']

    def start(self, process):
        self.thread = threading.Thread(target=self._collect, args=(process,), daemon=True)
        self.thread.start()

    def _collect(self, process):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                deadline = time.monotonic() + 30
                while True:
                    try:
                        connection.connect(str(self.socket_path))
                        break
                    except (FileNotFoundError, ConnectionRefusedError):
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError('QMP connection unavailable')
                        time.sleep(0.1)
                connection.settimeout(0.5)
                pending = b''
                with self.log_path.open('x') as output:
                    while True:
                        try:
                            data = connection.recv(65536)
                        except socket.timeout:
                            if process.poll() is not None:
                                break
                            continue
                        if not data:
                            break
                        pending += data
                        while b'\n' in pending:
                            line, pending = pending.split(b'\n', 1)
                            if not line.strip():
                                continue
                            message = json.loads(line)
                            output.write(json.dumps(message) + '\n')
                            output.flush()
                            if 'QMP' in message:
                                connection.sendall(b'{"execute":"qmp_capabilities"}\r\n')
                            if 'event' in message:
                                self.events.append(message)
        except Exception as error:
            self.error = str(error)

    def finish(self):
        self.thread.join(timeout=3)
        if self.thread.is_alive():
            self.error = 'QMP collector did not finish'
        shutdown = [event for event in self.events if event.get('event') == 'SHUTDOWN']
        return {
            'guest_poweroff': self.error is None and any(
                event.get('data', {}).get('guest') is True
                and event.get('data', {}).get('reason') == 'guest-shutdown'
                for event in shutdown),
            'shutdown_events': shutdown,
            'error': self.error,
            'event_log': str(self.log_path),
        }
