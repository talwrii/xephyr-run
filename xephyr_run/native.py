"""The compiled connect-filter supervisor: built on first use with the ziglang compiler, then cached."""
import hashlib
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

SOURCE = Path(__file__).with_name('connect_filter.c')


def cache_directory():
    cache = Path(os.environ.get('XDG_CACHE_HOME') or Path.home()/'.cache')
    return cache/'xephyr-run'


def compile_command():
    """Static musl builds with ziglang, which brings its own C library; any system compiler otherwise."""
    zig = subprocess.run([sys.executable, '-m', 'ziglang', 'version'], capture_output=True)
    if zig.returncode == 0:
        return [sys.executable, '-m', 'ziglang', 'cc', '-target', f'{platform.machine()}-linux-musl']
    for name in ('cc', 'gcc', 'clang'):
        if shutil.which(name):
            return [name]
    raise RuntimeError('no C compiler found; install the ziglang package')


def binary():
    """Path of the compiled supervisor, built if this source has not been built before.
    Delete the cache directory to force a rebuild with a different compiler."""
    digest = hashlib.sha256(SOURCE.read_bytes() + platform.machine().encode()).hexdigest()[:16]
    target = cache_directory()/f'connect-filter-{digest}'
    if target.exists():
        return target
    command = compile_command()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f'{target.name}.{os.getpid()}.tmp')
    build = subprocess.run([*command, '-O2', '-pthread', '-o', str(temporary), str(SOURCE)],
                           capture_output=True, text=True)
    if build.returncode != 0:
        temporary.unlink(missing_ok=True)
        raise RuntimeError('could not compile the connect filter: ' + build.stderr.strip()[-500:])
    os.replace(temporary, target)
    return target


def popen(argv, rules, **kwargs):
    """subprocess.Popen(argv, **kwargs) under ordered ('allow'|'deny', POSIX ERE) connect rules.
    The returned process is the supervisor, which exits with the program's status."""
    flags = []
    for verdict, pattern in rules:
        if verdict not in ('allow', 'deny'):
            raise ValueError(f'rule verdict must be allow or deny, not {verdict!r}')
        flags += [f'--{verdict}', pattern]
    return subprocess.Popen([str(binary()), *flags, '--', *argv], **kwargs)
