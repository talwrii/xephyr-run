# xephyr-run
Run X11 programs in xephyr jails so that they cannot talk to other X11 and perform actions or spy on your keypresses.

Thin wrapper around Xephyr which deals with some defaults and tracks xephyr X11 sessions.
Has some seccomp syscall filtering magic to prevent the jailed process from talking to other X sessions.

AI-generated and unreviewed. Mostly tested by the AI itself.

Run one X client in its own named [Xephyr](https://www.freedesktop.org/wiki/Software/Xephyr/)
window. The client talks to the nested X server, not your session, so it cannot
snoop your keystrokes, screenshot other windows or read your clipboard, as long as it is also
stopped from connecting to your main X server (see [Confinement](#confinement-the-default); this
is on by default). Your window manager places the Xephyr window like any other, and the client is
stretched to fill it, following resizes. Xephyr exits when the client does.

## Installation
`pipx install xephyr-run`

Requires `Xephyr` and `xdotool`. The package also installs `ziglang`, which compiles the connect
filter described below on first use.

## Usage

```bash
xephyr-run run -- xeyes
xephyr-run run -n term -- xterm -fa 'DejaVu Sans Mono' -fs 10
xephyr-run run --no-confine -- some-trusted-x-program   # switch the connect filter off
xephyr-run list                    # name, display, Xephyr pid, command
xephyr-run attach term -- xwininfo -root -tree
xephyr-run kill term
```

The name defaults to the command's name, and two instances cannot share one. The
Xephyr window is titled `xephyr-run-NAME`, which a window manager rule can match (for i3,
`for_window [title="^xephyr-run-"] floating enable`).
`-s WIDTHxHEIGHT` sets the initial size (default 640x400).

Instances are recorded in `$XDG_STATE_HOME/xephyr-run/NAME.json` (default
`~/.local/state/xephyr-run`) and cleaned up when they exit.


## Caveats
This tool only jails X11 access. You might like to combine it with some other sort of jail (which I
may do persently). However, I felt this feature on its own was a useful demonstraction.


## Alternatives and prior work 
ed:  used Xerphyr direction with a jail

ed: there was some socker of docker thing that did this

## Why a plain Xephyr is not enough
By itself, Xephyr does not prevent arbitrary code from connecting to your main X11 server. With a
normal configuration, a program running as you can find the main server and connect to it: by its
file socket `/tmp/.X11-unix/X0` or by the abstract socket `@/tmp/.X11-unix/X0`. Desktop sessions
usually let any local process of your user in without a cookie (`xhost` lists `SI:localuser:you`),
so hiding `~/.Xauthority` does not help. A client that connects there can log your keystrokes,
take screenshots, and type into other windows.

There are approaches for securing X11 servers (a separate Unix user, restricted X access control,
untrusted cookies, a container or VM), but on Ubuntu everything is user based, and this tool is
meant to work without changing your X11 configuration. So instead of changing what the X server
allows, `xephyr-run` limits what the client can connect to.

The host can see into the Xephyr window (pixels and input), but as a single opaque window: it
cannot see the client's own windows, and `xwininfo -root -tree` on the host does not list them.

## Confinement (the default)
Unless you pass `--no-confine`, the client runs under a **connect filter** that stops it connecting
to any X server other than its own nested one:

* every abstract Unix socket is refused (`ECONNREFUSED`, so X libraries fall back to the file socket);
* every Unix socket under `/tmp/.X11-unix` is refused (`EACCES`) except the instance's own display;
* everything else, including all network connections, is allowed.

Things the client may legitimately use over abstract sockets, such as a D-Bus session bus
configured with `unix:abstract=`, stop working. Try the program you intend to run, and use
`--no-confine` for programs you trust and which need them.

It does not need root, a container, or a network namespace.

### How the connect filter works

`xephyr_run/connect_filter.c` is a small supervisor. It runs your command with a
[seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html) filter that pauses each `connect()`
and hands it to the supervisor (seccomp user notification). The supervisor:

1. copies the socket address out of the program's memory **once**;
2. judges that copy against the ordered rules (first match wins; no match means allow);
3. if allowed, performs the `connect()` itself on the program's own socket (through `pidfd_getfd`),
   using the same copy.

Because the connect is made from the copy, the program cannot change the address between the
check and the use, which is the flaw in letting the kernel carry on with the original call.
A Unix path is canonicalised first (relative paths use the program's working directory, symlinks
are resolved) and the connect goes to that canonical path.

The filter also refuses `io_uring_setup` (io_uring can connect without a `connect` syscall) and
kills a process that switches to a different syscall ABI.

The first time a confined client is started, the supervisor is compiled with the `ziglang` package
(a self-contained C compiler, no system toolchain needed) into a static binary cached in
`$XDG_CACHE_HOME/xephyr-run` (default `~/.cache/xephyr-run`); the first build takes roughly
20 seconds. Delete that directory to force a rebuild. If it cannot be compiled, a slower Python
implementation of the same logic (`xephyr_run/connect_filter.py`) is used, with a warning.

The seccomp code is independent of the rest of the tool. `connect_filter.py` and
`connect_filter.c` know nothing about X11 and can be reused with other rules:

```python
from xephyr_run import connect_filter
process = connect_filter.popen_confined_rules(['some-command'], [('deny', '^@')])
# or with an arbitrary Python decision function: connect_filter.popen_confined(argv, lambda address: ...)
```

### Limits

* Only `connect()` is checked. A Unix **datagram** socket can be addressed with
  `sendto`/`sendmsg` without connecting, and those are not covered. X11 uses stream sockets.
* A descriptor the client inherits, or is passed over another socket, is not covered.
* The supervisor's work is done per `connect()`, so a program that connects very often pays for
  it; X clients connect rarely. The overhead has not been measured.
* Path rules judge the canonical path in the supervisor's filesystem view. A directory the client can
  write to could be swapped for a symlink after the check; `/tmp/.X11-unix` is sticky and root-owned.
* Linux on x86_64 or aarch64 only, kernel 5.7 or newer (seccomp listeners and `pidfd_getfd`).
* The supervisor exits when the client does; other processes the client left running keep the filter
  but their connects then fail.
* Landlock could do part of this without a supervisor (it can scope abstract Unix sockets since ABI 6),
  but as far as I know it cannot yet restrict connecting to a pathname socket on kernel ABI 8.
* I am lazy and do not build versions of this for differnt hardware - but I wanted something 
  performant which others can use. I therefore outsource the building of filtering code to run time 
  using `ziglang`
 

## Development

```bash
pipx install --editable .
python3 -m unittest discover -s tests
```

Run the tests with the pipx environment's Python so `ziglang` is available; otherwise the compiled
supervisor's tests are skipped if no system C compiler exists. The tests check both supervisors
against real sockets, including a test where a thread rewrites the address while `connect()` is
pending (and a control test showing that the same program does reach the forbidden socket
when unfiltered).
