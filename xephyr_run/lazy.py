"""A Xephyr that is only started when a client first connects to its display.

The display's listening socket is opened here, before any client exists. A client that connects
simply waits in the socket's queue. When the socket becomes readable we start Xephyr and hand it
the open socket, so it accepts the waiting connection itself: no proxying, so shared memory and
descriptor passing work as usual. A client that never uses X never costs a Xephyr or a window.

The socket is handed over with the LISTEN_FDS convention: the listening socket is descriptor 3 of
the new process, and the environment variables LISTEN_FDS=1 and LISTEN_PID=<its pid> say so. The
X server code that Xephyr shares with Xorg understands this. It began with systemd, but nothing
here runs or needs systemd; it is only environment variables. (Xephyr has no -listenfd option,
which only Xwayland has.) It needs a Xephyr built with that support, which Ubuntu's is.
"""
import os
import select
import socket
import subprocess
import tempfile
import time
from pathlib import Path

SOCKETS = Path('/tmp/.X11-unix')


def free_display(sockets=SOCKETS, first=90):
    number = first
    while (sockets/f'X{number}').exists():
        number += 1
    return number


class LazyXephyr:
    """The display :NUMBER, served at SOCKETS/X<NUMBER> by a Xephyr started on first connection."""

    def __init__(self, number, size, title, sockets=SOCKETS):
        self.number = number
        self.size = size
        self.title = title
        self.sockets = Path(sockets)
        self.path = self.sockets/f'X{number}'
        self.listener = None
        self.server = None
        self.log = None

    @property
    def display(self):
        return f':{self.number}'

    def open(self):
        """Create the listening socket. Connections made from now on wait for the Xephyr."""
        self.sockets.mkdir(parents=True, exist_ok=True)
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(self.path))
        os.chmod(self.path, 0o600)
        self.listener.listen(64)

    def connection_waiting(self, timeout):
        """Whether a client has connected and is waiting, without accepting it."""
        ready, _, _ = select.select([self.listener], [], [], timeout)
        return bool(ready)

    def start(self):
        """Start Xephyr on the open socket. It picks up the waiting connection."""
        # Xephyr also wants a display number of its own; it is never used by clients.
        hidden = free_display(self.sockets, first=self.number + 100)
        self.log = tempfile.TemporaryFile()
        fd = self.listener.fileno()
        # The shell puts the socket on descriptor 3 and sets LISTEN_PID to its own pid, which exec keeps.
        script = 'exec 3<&"$1"; shift; export LISTEN_FDS=1 LISTEN_PID=$$; exec "$@"'
        self.server = subprocess.Popen(
            ['sh', '-c', script, 'sh', str(fd), 'Xephyr', f':{hidden}', '-screen', self.size,
             '-title', self.title, '-resizeable', '-no-host-grab',
             # Without this the server resets when its last client disconnects, which closes the
             # inherited listening socket and leaves later connections waiting for ever.
             '-noreset'],
            pass_fds=[fd], stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log)
        time.sleep(0.3)
        if self.server.poll() is not None:
            self.log.seek(0)
            raise RuntimeError('Xephyr exited as it started:\n'
                               + self.log.read().decode(errors='replace').strip()[-500:])

    def close(self):
        if self.server and self.server.poll() is None:
            self.server.terminate()
            try:
                self.server.wait(5)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait()
        if self.listener:
            self.listener.close()
        self.path.unlink(missing_ok=True)
        if self.log:
            self.log.close()
