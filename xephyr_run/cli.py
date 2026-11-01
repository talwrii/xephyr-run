"""Run one X client inside its own named Xephyr window; the window manager places it."""
import argparse
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

from . import connect_filter, registry

SOCKETS = Path('/tmp/.X11-unix')


def parse_size(text):
    if not re.fullmatch(r'\d+x\d+', text):
        raise ValueError('Size must look like 640x400')
    return text


def free_display(sockets=SOCKETS, first=90):
    number = first
    while (sockets/f'X{number}').exists():
        number += 1
    return number


def wait_for(path, timeout=5):
    deadline = time.time() + timeout
    while not path.exists():
        if time.time() > deadline:
            raise RuntimeError('Xephyr did not start')
        time.sleep(0.05)


def screen_size(display):
    env = dict(os.environ, DISPLAY=display)
    return tuple(subprocess.run(['xdotool', 'getdisplaygeometry'], env=env, capture_output=True,
                                text=True, check=True).stdout.split())


def fill(display, width, height):
    """Stretch the client's top-level window over the nested screen; there is no window manager inside to do it."""
    env = dict(os.environ, DISPLAY=display)
    found = subprocess.run(['xdotool', 'search', '--sync', '--onlyvisible', '--maxdepth', '1', '--name', '.'],
                           env=env, capture_output=True, text=True, timeout=10)
    window = found.stdout.split()[0]
    subprocess.run(['xdotool', 'windowmove', window, '0', '0', 'windowsize', window, width, height],
                   env=env, check=True)


def follow(client, display):
    """Keep the client filling the nested screen as its Xephyr window is resized, until the client exits."""
    last = None
    while client.poll() is None:
        current = screen_size(display)
        if current != last:
            fill(display, *current)
            last = current
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
    size = parse_size(args.size)
    number = free_display()
    display = f':{number}'
    server = subprocess.Popen(['Xephyr', display, '-screen', size, '-title', f'xephyr-run-{name}',
                               '-resizeable', '-no-host-grab'])
    try:
        wait_for(SOCKETS/f'X{number}')
        registry.save({'name': name, 'display': display, 'server_pid': server.pid, 'pid': os.getpid(),
                       'command': command, 'started': time.time()})
        environment = dict(os.environ, DISPLAY=display)
        if args.confine:
            client = connect_filter.popen_confined_rules(command, confine_rules(number), env=environment)
        else:
            client = subprocess.Popen(command, env=environment)
        return follow(client, display)
    finally:
        registry.remove(name)
        server.terminate()
        server.wait()


def find(name):
    record = registry.load(registry.validate_name(name))
    if not record:
        raise ValueError(f'No running instance named {name}')
    return record


def list_instances(args):
    for record in registry.records():
        print(f'{record["name"]}\t{record["display"]}\t{record["server_pid"]}\t{" ".join(record["command"])}')
    return 0


def kill(args):
    os.kill(find(args.name)['server_pid'], signal.SIGTERM)
    return 0


def attach(args):
    return subprocess.run(command_of(args), env=dict(os.environ, DISPLAY=find(args.name)['display'])).returncode


def parser():
    p = argparse.ArgumentParser(description='Run X clients in their own named Xephyr windows.')
    sub = p.add_subparsers(dest='action', required=True)
    runner = sub.add_parser('run', help='Start a Xephyr and run a command in it')
    runner.add_argument('-n', '--name', help='Instance name (default: the command name)')
    runner.add_argument('-s', '--size', default='640x400', help='Initial size (default: %(default)s)')
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
