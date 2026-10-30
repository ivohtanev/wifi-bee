"""Durable private task files and common progress formatting."""
import json
import os
from pathlib import Path
import tempfile


def secure(path, session):
    os.chown(path, session.uid, session.gid)
    path.chmod(0o700 if path.is_dir() else 0o600)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path, data, session):
    fd, temp = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    temp = Path(temp)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        secure(temp, session)
        os.replace(temp, path)
        sync_directory(path.parent)
    finally:
        temp.unlink(missing_ok=True)


def writable_directory(path, session):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    secure(path, session)
    fd, name = tempfile.mkstemp(prefix='.write-test-', dir=path)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(b'write-test\n')
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        Path(name).unlink(missing_ok=True)
    sync_directory(path)


def durable_touch(path, session):
    with path.open('ab') as stream:
        stream.flush()
        os.fsync(stream.fileno())
    secure(path, session)


def size(value):
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if value < 1024:
            return f'{value:.1f} {unit}'
        value /= 1024
    return f'{value:.1f} PiB'


def duration(seconds):
    if seconds is None or seconds < 0:
        return 'изчислява се'
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return (f'{days}д ' if days else '') + f'{hours:02}:{minutes:02}:{seconds:02}'


def bar(done, total, width=28):
    fraction = min(1, max(0, done / total)) if total else 0
    filled = int(width * fraction)
    return '[' + '#' * filled + '-' * (width - filled) + '] ' + (f'{fraction:.1%}' if total else 'изчислява се')
