import errno
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest

from xephyr_run import connect_filter as cf
from xephyr_run import native


def sockaddr_un(path):
    return struct.pack('=H', socket.AF_UNIX) + path.encode() + b'\0'


class Policy(unittest.TestCase):
    def test_first_matching_rule_wins_and_default_allows(self):
        policy = cf.rules_policy([('allow', r'^/run/x/X90$'), ('deny', r'^@'), ('deny', r'^/run/x/')])
        unix = lambda name: cf.Address(socket.AF_UNIX, name, b'')
        self.assertTrue(policy(unix('/run/x/X90')))
        self.assertFalse(policy(unix('/run/x/X0')))
        self.assertFalse(policy(unix('@/tmp/.X11-unix/X0')))
        self.assertTrue(policy(unix('/elsewhere/sock')))
        self.assertTrue(policy(cf.Address(socket.AF_INET, None, b'')))

    def test_rejects_unknown_verdict(self):
        with self.assertRaises(ValueError):
            cf.rules_policy([('permit', '.*')])


class ParseAddress(unittest.TestCase):
    def test_abstract_path_and_unnamed(self):
        pid = os.getpid()
        self.assertEqual(cf.parse_address(struct.pack('=H', 1) + b'\0hello', pid).name, '@hello')
        self.assertEqual(cf.parse_address(struct.pack('=H', 1), pid).name, '')
        address = cf.parse_address(sockaddr_un('/tmp/../tmp/./some.sock'), pid)
        self.assertEqual(address.name, os.path.realpath('/tmp/some.sock'))
        self.assertEqual(address.raw, sockaddr_un(os.path.realpath('/tmp/some.sock')))

    def test_relative_path_uses_the_programs_working_directory(self):
        address = cf.parse_address(sockaddr_un('rel.sock'), os.getpid())
        self.assertEqual(address.name, os.path.join(os.path.realpath(os.getcwd()), 'rel.sock'))

    def test_other_families_are_untouched(self):
        raw = struct.pack('=H', socket.AF_INET) + b'\x00' * 14
        address = cf.parse_address(raw, os.getpid())
        self.assertIsNone(address.name)
        self.assertEqual(address.raw, raw)

    def test_rejects_short_addresses(self):
        with self.assertRaises(OSError):
            cf.parse_address(b'\x01', os.getpid())


def supported():
    try:
        process = cf.popen_confined(['true'], lambda address: True)
    except (RuntimeError, OSError):
        return False
    process.wait()
    return True


class Server(threading.Thread):
    """Accepts connections on a listening socket and counts them."""
    def __init__(self, listener):
        super().__init__(daemon=True)
        self.listener = listener
        self.listener.settimeout(0.1)
        self.accepted = 0
        self.stopped = False
        self.start()

    def run(self):
        while not self.stopped:
            try:
                self.listener.accept()[0].close()
                self.accepted += 1
            except socket.timeout:
                pass
            except OSError:
                return

    def stop(self):
        self.stopped = True
        self.join()
        self.listener.close()


def unix_server(address):
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(address)
    listener.listen(64)
    return Server(listener)


CONNECTS = r'''
import ctypes, errno, json, socket, sys
libc = ctypes.CDLL(None, use_errno=True)
def attempt(family, address):
    s = socket.socket(family)
    try:
        s.connect(address)
        return 'ok'
    except OSError as error:
        return errno.errorcode.get(error.errno, str(error.errno))
    finally:
        s.close()
targets = json.loads(sys.argv[1])
results = {
    'allowed': attempt(socket.AF_UNIX, targets['allowed']),
    'denied': attempt(socket.AF_UNIX, targets['denied']),
    'abstract': attempt(socket.AF_UNIX, ('\0' + targets['abstract']).encode()),
    'tcp': attempt(socket.AF_INET, ('127.0.0.1', targets['port'])),
}
ctypes.set_errno(0)
results['io_uring'] = 'ok' if libc.syscall(425, 1, None) >= 0 else errno.errorcode[ctypes.get_errno()]
print(json.dumps(results))
'''

RACE = r'''
import ctypes, socket, struct, sys, threading
good, bad, count = sys.argv[1], sys.argv[2], int(sys.argv[3])
libc = ctypes.CDLL(None, use_errno=True)
pack = lambda path: struct.pack('=H', 1) + path.encode() + b'\0'
a, b = pack(good), pack(bad)
buffer = ctypes.create_string_buffer(a, len(a))
stop = False
def flip():
    while not stop:
        ctypes.memmove(buffer, b, len(b))
        ctypes.memmove(buffer, a, len(a))
threading.Thread(target=flip, daemon=True).start()
for _ in range(count):
    s = socket.socket(socket.AF_UNIX)
    libc.connect(s.fileno(), buffer, len(a))
    s.close()
stop = True
'''


class RaceHarness(unittest.TestCase):
    def test_the_flipping_program_does_reach_the_denied_socket_when_unconfined(self):
        directory = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory, True)
        servers = {name: unix_server(os.path.join(directory, name + '.sock')) for name in ('good', 'evil')}
        for server in servers.values():
            self.addCleanup(server.stop)
        subprocess.run([sys.executable, '-c', RACE, os.path.join(directory, 'good.sock'),
                        os.path.join(directory, 'evil.sock'), '150'], check=True, timeout=60)
        self.assertGreater(servers['evil'].accepted, 0)
        self.assertGreater(servers['good'].accepted, 0)


def native_available():
    try:
        native.binary()
    except RuntimeError:
        return False
    return True


class ConfinedTests:
    """The same behaviour, whichever supervisor enforces it."""
    def setUp(self):
        self.directory = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.directory, True)
        self.allowed = os.path.join(self.directory, 'good.sock')
        self.denied = os.path.join(self.directory, 'evil.sock')
        self.rules = [('allow', '^' + cf.ere_escape(self.allowed) + '$'), ('deny', '.*')]
        self.servers = {}
        for name, path in (('allowed', self.allowed), ('denied', self.denied)):
            self.servers[name] = unix_server(path)
            self.addCleanup(self.servers[name].stop)

    def run_confined(self, *script, expect=0):
        process = self.launch([sys.executable, '-c', *script], stdout=subprocess.PIPE, text=True)
        output = process.communicate(timeout=60)[0]
        self.assertEqual(process.returncode, expect)
        return output

    def test_exit_status_is_passed_through(self):
        self.run_confined('import sys; sys.exit(7)', expect=7)

    def test_limits(self):
        abstract = socket.socket(socket.AF_UNIX)
        abstract.bind(b'\0confined-test-%d' % os.getpid())
        abstract.listen(4)
        self.addCleanup(abstract.close)
        tcp = socket.socket()
        tcp.bind(('127.0.0.1', 0))
        tcp.listen(4)
        self.addCleanup(tcp.close)
        targets = {'allowed': self.allowed, 'denied': self.denied, 'port': tcp.getsockname()[1],
                   'abstract': 'confined-test-%d' % os.getpid()}
        results = json.loads(self.run_confined(CONNECTS, json.dumps(targets)))
        self.assertEqual(results, {'allowed': 'ok', 'denied': 'EACCES', 'abstract': 'ECONNREFUSED',
                                   'tcp': 'ok', 'io_uring': 'EPERM'})
        self.assertEqual(self.servers['denied'].accepted, 0)

    def test_changing_the_address_during_the_check_cannot_reach_a_denied_socket(self):
        self.run_confined(RACE, self.allowed, self.denied, '150')
        self.assertEqual(self.servers['denied'].accepted, 0)
        self.assertGreater(self.servers['allowed'].accepted, 0)


@unittest.skipUnless(supported(), 'seccomp user notification is not available here')
class PythonConfined(ConfinedTests, unittest.TestCase):
    def launch(self, argv, **kwargs):
        return cf.popen_confined(argv, cf.rules_policy(self.rules), **kwargs)


@unittest.skipUnless(native_available(), 'the compiled supervisor cannot be built here')
class NativeConfined(ConfinedTests, unittest.TestCase):
    def launch(self, argv, **kwargs):
        return native.popen(argv, self.rules, **kwargs)

    def test_bad_regular_expression_is_refused(self):
        process = native.popen([sys.executable, '-c', 'pass'], [('deny', '(')], stderr=subprocess.PIPE, text=True)
        self.assertIn('bad regular expression', process.communicate(timeout=60)[1])
        self.assertEqual(process.returncode, 2)


if __name__ == '__main__':
    unittest.main()
