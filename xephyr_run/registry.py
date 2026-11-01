"""Records of running instances, one JSON file per name, pruned when their Xephyr is gone."""
import json
import os
import re
from pathlib import Path

NAME = re.compile(r'[A-Za-z0-9_-]+')


def directory():
    state = Path(os.environ.get('XDG_STATE_HOME') or Path.home()/'.local'/'state')
    return state/'xephyr-run'


def validate_name(name):
    if not NAME.fullmatch(name):
        raise ValueError('Names may only contain letters, digits, _ and -')
    return name


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def save(record, where=None):
    where = where or directory()
    where.mkdir(parents=True, exist_ok=True)
    (where/f'{validate_name(record["name"])}.json').write_text(json.dumps(record))


def remove(name, where=None):
    (where or directory()).joinpath(f'{validate_name(name)}.json').unlink(missing_ok=True)


def load(name, where=None):
    """The live record for name, or None; a record whose Xephyr has exited is deleted."""
    where = where or directory()
    path = where/f'{validate_name(name)}.json'
    try:
        record = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    if not alive(record['pid']):
        path.unlink(missing_ok=True)
        return None
    return record


def records(where=None):
    where = where or directory()
    if not where.is_dir():
        return []
    found = (load(path.stem, where) for path in sorted(where.glob('*.json')) if NAME.fullmatch(path.stem))
    return [record for record in found if record]
