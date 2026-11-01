"""Confine a program's connect() calls with seccomp user notification.

A seccomp filter pauses every connect() the confined program makes and hands the target address
to a policy. If the policy allows it, the supervisor (this process) performs the connect itself,
on the program's own socket, using the copy of the address it has already checked. The program
cannot change the address between the check and the use, which is the flaw in letting the kernel
carry on with the original call.

Limits, by design:
  * Only connect() is trapped. Unix datagram sockets can be addressed with sendto/sendmsg without
    connecting, and those are not covered. Descriptors the program inherits or is sent over a
    socket are not covered either.
  * io_uring can connect without a connect syscall, so io_uring_setup is refused outright.
  * Unix path sockets are judged by their canonical path in the supervisor's filesystem view, and
    the connect is made to that path. A directory the program can rewrite could still be swapped
    for a symlink after the check; use paths in directories it cannot modify (such as /tmp/.X11-unix).
  * x86_64 and aarch64 Linux only (needs pidfd_getfd, kernel 5.6+, and seccomp listeners, 5.7+).

This module is deliberately independent of the rest of xephyr-run.
"""
from __future__ import annotations

import ctypes
import dataclasses
import errno
import fcntl
import os
import platform
import re
import select
import socket
import struct
import subprocess
import sys
import threading

ARCHES = {
    'x86_64': {'audit': 0xC000003E, 'connect': 42, 'seccomp': 317},
    'aarch64': {'audit': 0xC00000B7, 'connect': 203, 'seccomp': 277},
}
SYS_IO_URING_SETUP = 425
SYS_PIDFD_GETFD = 438
X32_BIT = 0x40000000

PR_SET_NO_NEW_PRIVS = 38
SECCOMP_SET_MODE_FILTER = 1
SECCOMP_FILTER_FLAG_NEW_LISTENER = 1 << 3
RET_KILL_PROCESS = 0x80000000
RET_ERRNO = 0x00050000
RET_USER_NOTIF = 0x7FC00000
RET_ALLOW = 0x7FFF0000

AF_UNIX = socket.AF_UNIX
SOCKADDR_MAX = 128
UNIX_PATH_MAX = 108

NOTIF = struct.Struct('=QIIiIQ6Q')   # seccomp_notif: id, pid, flags, then seccomp_data
RESPONSE = struct.Struct('=QqiI')    # seccomp_notif_resp: id, val, error, flags


def _ioc(direction, number, size):
    return (direction << 30) | (size << 16) | (ord('!') << 8) | number


NOTIF_RECV = _ioc(3, 0, NOTIF.size)
NOTIF_SEND = _ioc(3, 1, RESPONSE.size)
NOTIF_ID_VALID = _ioc(1, 2, 8)

libc = ctypes.CDLL(None, use_errno=True)
libc.connect.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]


class SockFilter(ctypes.Structure):
    _fields_ = [('code', ctypes.c_uint16), ('jt', ctypes.c_uint8), ('jf', ctypes.c_uint8), ('k', ctypes.c_uint32)]


class SockFprog(ctypes.Structure):
    _fields_ = [('len', ctypes.c_ushort), ('filter', ctypes.POINTER(SockFilter))]


@dataclasses.dataclass
class Address:
    family: int
    name: str | None   # AF_UNIX: '@' + abstract name, or the canonical absolute path ('' if unnamed); else None
    raw: bytes         # the sockaddr that will be connected to; rewritten to the canonical path for Unix paths


def architecture():
    try:
        return ARCHES[platform.machine()]
    except KeyError:
        raise RuntimeError(f'connect filtering is not supported on {platform.machine()}') from None


def build_program(info):
    """Classic BPF: kill foreign ABIs, trap connect, refuse io_uring_setup, allow the rest."""
    steps = [('ld', 4), ('jeq', info['audit'], None, 'kill'), ('ld', 0)]
    if info['audit'] == ARCHES['x86_64']['audit']:
        steps.append(('jset', X32_BIT, 'kill', None))
    steps += [('jeq', info['connect'], 'notify', None), ('jeq', SYS_IO_URING_SETUP, 'deny', None),
              ('ret', RET_ALLOW),
              ('label', 'notify'), ('ret', RET_USER_NOTIF),
              ('label', 'deny'), ('ret', RET_ERRNO | errno.EPERM),
              ('label', 'kill'), ('ret', RET_KILL_PROCESS)]
    labels, index = {}, 0
    for step in steps:
        if step[0] == 'label':
            labels[step[1]] = index
        else:
            index += 1
    program, index = [], 0
    for step in steps:
        if step[0] == 'label':
            continue
        index += 1
        if step[0] == 'ld':
            program.append(SockFilter(0x20, 0, 0, step[1]))
        elif step[0] == 'ret':
            program.append(SockFilter(0x06, 0, 0, step[1]))
        else:
            code = {'jeq': 0x15, 'jset': 0x45}[step[0]]
            jump = lambda label: 0 if label is None else labels[label] - index
            program.append(SockFilter(code, jump(step[2]), jump(step[3]), step[1]))
    array = (SockFilter * len(program))(*program)
    return SockFprog(len(program), array), array


def install_and_exec(send_fd, argv):
    """Child side: install the filter, send the listener to the supervisor, then become the program."""
    sender = socket.socket(fileno=send_fd)
    try:
        info = architecture()
        program, _keep = build_program(info)
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'prctl(PR_SET_NO_NEW_PRIVS)')
        listener = libc.syscall(info['seccomp'], SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER,
                                ctypes.byref(program))
        if listener < 0:
            raise OSError(ctypes.get_errno(), 'seccomp(SET_MODE_FILTER)')
        socket.send_fds(sender, [b'ok'], [listener])
        os.close(listener)
    except (OSError, RuntimeError) as error:
        sender.send(b'error: ' + str(error).encode())
        raise SystemExit(1)
    sender.close()
    os.execvp(argv[0], argv)


def read_memory(pid, address, size):
    try:
        with open(f'/proc/{pid}/mem', 'rb', buffering=0) as memory:
            data = os.pread(memory.fileno(), size, address)
    except (OSError, OverflowError):
        raise OSError(errno.EFAULT, 'cannot read address') from None
    if len(data) != size:
        raise OSError(errno.EFAULT, 'cannot read address')
    return data


def parse_address(raw, pid):
    if len(raw) < 2:
        raise OSError(errno.EINVAL, 'address too short')
    family = struct.unpack_from('=H', raw)[0]
    if family != AF_UNIX:
        return Address(family, None, raw)
    body = raw[2:]
    if body[:1] == b'\0':
        return Address(family, '@' + body[1:].decode('latin-1'), raw)
    path = body.split(b'\0', 1)[0]
    if not path:
        return Address(family, '', raw)
    text = os.fsdecode(path)
    if not os.path.isabs(text):
        text = os.path.join(os.readlink(f'/proc/{pid}/cwd'), text)
    canonical = os.fsencode(os.path.realpath(text))
    if len(canonical) >= UNIX_PATH_MAX:
        raise OSError(errno.ENAMETOOLONG, 'path too long')
    return Address(family, os.fsdecode(canonical), struct.pack('=H', AF_UNIX) + canonical + b'\0')


def rules_policy(rules):
    """Policy from ordered ('allow'|'deny', regex) rules, first match wins, matched with re.search
    against Address.name. Unix addresses that match nothing, and all non-Unix addresses, are allowed."""
    compiled = []
    for verdict, pattern in rules:
        if verdict not in ('allow', 'deny'):
            raise ValueError(f'rule verdict must be allow or deny, not {verdict!r}')
        compiled.append((verdict == 'allow', re.compile(pattern)))

    def policy(address):
        if address.name is not None:
            for allowed, pattern in compiled:
                if pattern.search(address.name):
                    return allowed
        return True
    return policy


def ere_escape(text):
    """Escape text for a POSIX extended regular expression; the result is also valid for Python's re."""
    return re.sub(r'([.\[\]()*+?{}|^$\\])', r'\\\1', text)


def popen_confined_rules(argv, rules, **kwargs):
    """popen_confined with ordered ('allow'|'deny', POSIX ERE) rules. Uses the compiled supervisor,
    and the Python one if that cannot be built."""
    from . import native
    try:
        native.binary()
    except RuntimeError as error:
        print(f'xephyr-run: using the slower Python connect filter ({error})', file=sys.stderr)
        return popen_confined(argv, rules_policy(rules), **kwargs)
    return native.popen(argv, rules, **kwargs)


def _reply(listener, notification_id, error=0):
    try:
        fcntl.ioctl(listener, NOTIF_SEND, RESPONSE.pack(notification_id, 0, error, 0))
    except OSError:
        pass   # the program died or was interrupted; nobody is waiting


def _connect_for(pid, descriptor, raw):
    """Connect the program's own socket (the same open file description) to raw, returning 0 or -errno."""
    pidfd = os.pidfd_open(pid)
    try:
        duplicate = libc.syscall(SYS_PIDFD_GETFD, pidfd, descriptor, 0)
        if duplicate < 0:
            return -ctypes.get_errno()
        try:
            if libc.connect(duplicate, raw, len(raw)) < 0:
                return -ctypes.get_errno()
            return 0
        finally:
            os.close(duplicate)
    finally:
        os.close(pidfd)


def _handle(listener, notification, policy):
    notification_id, pid = notification[0], notification[1]
    descriptor, pointer, length = notification[6:9]
    try:
        if not 2 <= length <= SOCKADDR_MAX:
            return _reply(listener, notification_id, -errno.EINVAL)
        raw = read_memory(pid, pointer, length)
        fcntl.ioctl(listener, NOTIF_ID_VALID, struct.pack('=Q', notification_id))
        address = parse_address(raw, pid)
        if not policy(address):
            # A refused abstract socket looks like one nobody listens on: X libraries try the abstract
            # name first and only fall back to the file socket on ECONNREFUSED or ENOENT, not EACCES.
            refusal = errno.ECONNREFUSED if (address.name or '').startswith('@') else errno.EACCES
            return _reply(listener, notification_id, -refusal)
        _reply(listener, notification_id, _connect_for(pid, descriptor, address.raw))
    except OSError as error:
        _reply(listener, notification_id, -(error.errno or errno.EIO))
    except Exception:
        _reply(listener, notification_id, -errno.EACCES)   # fail closed


def _supervise(listener, policy):
    handlers = []
    poller = select.poll()
    poller.register(listener, select.POLLIN)
    try:
        while True:
            for _, event in poller.poll(500):
                if event & (select.POLLHUP | select.POLLERR | select.POLLNVAL):
                    return
                if event & select.POLLIN:
                    buffer = bytearray(NOTIF.size)
                    try:
                        fcntl.ioctl(listener, NOTIF_RECV, buffer, True)
                    except OSError:
                        continue   # the program went away before we could receive it
                    handler = threading.Thread(target=_handle, args=(listener, NOTIF.unpack(buffer), policy),
                                               daemon=True)
                    handler.start()
                    handlers.append(handler)
            handlers = [handler for handler in handlers if handler.is_alive()]
    finally:
        for handler in handlers:
            handler.join(5)
        os.close(listener)


def popen_confined(argv, policy, **kwargs):
    """subprocess.Popen(argv, **kwargs), with every connect() it makes decided by policy(Address) -> bool.

    The returned Popen has a .supervisor thread, which ends when the program and its children are gone."""
    architecture()
    receiver, sender = socket.socketpair()
    try:
        process = subprocess.Popen([sys.executable, '-I', os.path.abspath(__file__), str(sender.fileno()), '--', *argv],
                                   pass_fds=[sender.fileno()], **kwargs)
    finally:
        sender.close()
    try:
        receiver.settimeout(10)
        message, descriptors, _, _ = socket.recv_fds(receiver, 256, 1)
    except OSError as error:
        process.kill()
        process.wait()
        raise RuntimeError(f'could not set up the connect filter: {error}') from None
    finally:
        receiver.close()
    if not descriptors:
        process.wait()
        raise RuntimeError(message.decode(errors='replace') or 'could not set up the connect filter')
    process.supervisor = threading.Thread(target=_supervise, args=(descriptors[0], policy), daemon=True)
    process.supervisor.start()
    return process


if __name__ == '__main__':
    install_and_exec(int(sys.argv[1]), sys.argv[3:])
