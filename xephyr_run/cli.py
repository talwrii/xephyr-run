"""Run one X client inside its own named Xephyr window; the window manager places it."""
import argparse
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

from . import connect_filter, lazy, registry

SOCKETS = lazy.SOCKETS
free_display = lazy.free_display


def parse_size(text):
    if not re.fullmatch(r'\d+x\d+', text):
        raise ValueError('Size must look like 640x400')
    return text


def screen_size(display):
    env = dict(os.environ, DISPLAY=display)
    return tuple(subprocess.run(['xdotool', 'getdisplaygeometry'], env=env, capture_output=True,
                                text=True, check=True).stdout.split())


def fill(display, width, height):
    """Stretch the client's top-level window over the nested screen; there is no window manager inside to do it."""
    env = dict(os.environ, DISPLAY=display)
    # No --sync: killing a client that is waiting (as a timeout does) leaves this Xephyr unresponsive.
    # An empty answer just means the window is not there yet, and follow() asks again.
    found = subprocess.run(['xdotool', 'search', '--onlyvisible', '--maxdepth', '1', '--name', '.'],
                           env=env, capture_output=True, text=True, timeout=10)
    window = found.stdout.split()[0]
    subprocess.run(['xdotool', 'windowmove', window, '0', '0', 'windowsize', window, width, height],
                   env=env, check=True)


def follow(client, display, on_start=lambda: None, eager=False):
    """Start the Xephyr when the client first connects to its display (at once if eager), then keep
    the client filling the nested screen as its window is resized, until the client exits. A client
    that never uses X never gets a Xephyr, unless eager."""
    started, last = False, None
    while client.poll() is None:
        if not started:
            if not eager and not display.connection_waiting(0.1):
                continue
            display.start()
            on_start()
            started = True
        try:
            current = screen_size(display.display)
            if current != last:
                fill(display.display, *current)
                last = current
        except (subprocess.TimeoutExpired, IndexError):
            pass   # the client has no window yet; look again shortly
        time.sleep(0.2)
    return client.returncode


def confine_rules(number, sockets=SOCKETS):
    """Connect rules that leave a client only its own nested display: no abstract sockets, and no
    X socket other than X<number>."""
    base = connect_filter.ere_escape(os.path.realpath(sockets))
    return [('allow', f'^{base}/X{number}$'), ('deny', '^@'), ('deny', f'^{base}/')]


def command_of(args):
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        raise ValueError('Give a command after --')
    return command


def run(args):
    command = command_of(args)
    name = registry.validate_name(args.name or Path(command[0]).name)
    if registry.load(name):
        raise ValueError(f'{name} is already running; use a different --name or kill it first')
    number = free_display()
    display = lazy.LazyXephyr(number, parse_size(args.size), f'xephyr-run-{name}')
    # So a kill still cleans up. A shell starts background jobs with SIGINT ignored, so ask for it again.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    signal.signal(signal.SIGINT, signal.default_int_handler)
    display.open()
    record = {'name': name, 'display': display.display, 'server_pid': None, 'pid': os.getpid(),
              'command': command, 'started': time.time()}
    client = None
    try:
        registry.save(record)
        environment = dict(os.environ, DISPLAY=display.display)
        if args.confine:
            client = connect_filter.popen_confined_rules(command, confine_rules(number), env=environment)
        else:
            client = subprocess.Popen(command, env=environment)
        return follow(client, display, lambda: registry.save(dict(record, server_pid=display.server.pid)),
                      eager=args.always_start_xephyr)
    finally:
        registry.remove(name)
        if client and client.poll() is None:
            client.terminate()
        display.close()


def find(name):
    record = registry.load(registry.validate_name(name))
    if not record:
        raise ValueError(f'No running instance named {name}')
    return record


def list_instances(args):
    for record in registry.records():
        server = record['server_pid'] or 'not started'
        print(f'{record["name"]}\t{record["display"]}\t{server}\t{" ".join(record["command"])}')
    return 0


def kill(args):
    """Ask the xephyr-run process to stop; it stops the client and its Xephyr and cleans up."""
    os.kill(find(args.name)['pid'], signal.SIGTERM)
    return 0


def attach(args):
    return subprocess.run(command_of(args), env=dict(os.environ, DISPLAY=find(args.name)['display'])).returncode


def parser():
    p = argparse.ArgumentParser(description='Run X clients in their own named Xephyr windows.')
    sub = p.add_subparsers(dest='action', required=True)
    runner = sub.add_parser('run', help='Start a Xephyr and run a command in it')
    runner.add_argument('-n', '--name', help='Instance name (default: the command name)')
    runner.add_argument('-s', '--size', default='640x400', help='Initial size (default: %(default)s)')
    runner.add_argument('--always-start-xephyr', action='store_true',
                        help='Start Xephyr at once instead of when the client first connects to X (for debugging)')
    runner.add_argument('--no-confine', dest='confine', action='store_false',
                        help='Allow the client to connect to your other X servers (confined by default, see README)')
    sub.add_parser('list', help='List running instances: name, display, Xephyr pid, command')
    killer = sub.add_parser('kill', help='Stop an instance by name')
    killer.add_argument('name')
    attacher = sub.add_parser('attach', help="Run a command on an instance's display")
    attacher.add_argument('name')
    for command in (runner, attacher):
        command.add_argument('command', nargs=argparse.REMAINDER, help='-- COMMAND [ARGS...]')
    return p


def main():
    args = parser().parse_args()
    try:
        return {'run': run, 'list': list_instances, 'kill': kill, 'attach': attach}[args.action](args)
    except (ValueError, RuntimeError, OSError, IndexError, subprocess.SubprocessError) as error:
        print(f'xephyr-run: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
