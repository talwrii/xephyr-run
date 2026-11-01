import os
import shutil
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path

from xephyr_run import lazy


class Waiting(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.directory, True)
        self.display = lazy.LazyXephyr(7, '300x200', 'test', sockets=Path(self.directory))
        self.display.open()
        self.addCleanup(self.display.close)

    def test_nothing_happens_until_a_client_connects(self):
        self.assertFalse(self.display.connection_waiting(0.05))
        self.assertIsNone(self.display.server)

    def test_a_connecting_client_is_noticed_without_being_accepted(self):
        client = socket.socket(socket.AF_UNIX)
        self.addCleanup(client.close)
        client.connect(str(self.display.path))
        self.assertTrue(self.display.connection_waiting(0.5))
        self.assertTrue(self.display.connection_waiting(0.05))   # still waiting: nobody accepted it

    def test_the_socket_is_private_and_removed_on_close(self):
        self.assertEqual(os.stat(self.display.path).st_mode & 0o777, 0o600)
        self.display.close()
        self.assertFalse(self.display.path.exists())


@unittest.skipUnless(shutil.which('Xephyr') and shutil.which('xdpyinfo') and os.environ.get('DISPLAY'),
                     'needs Xephyr, xdpyinfo and an X display')
class RealXephyr(unittest.TestCase):
    def test_successive_connections_keep_being_served(self):
        # Regression: without -noreset the server resets when its last client leaves, closing the
        # inherited socket, and the next connection waits for ever.
        display = lazy.LazyXephyr(lazy.free_display(first=97), '300x200', 'xephyr-run-test')
        display.open()
        display.start()
        try:
            for _ in range(3):
                probe = subprocess.run(['xdpyinfo', '-display', display.display], capture_output=True, timeout=10)
                self.assertEqual(probe.returncode, 0)
        finally:
            display.close()


if __name__ == '__main__':
    unittest.main()
