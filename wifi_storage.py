"""Durable private task files and common progress formatting."""
import json
import os
from pathlib import Path
import tempfile


def secure(path, session):
    path = no_symlinks(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        import stat
        mode = os.fstat(fd).st_mode
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ValueError('Неподдържан тип файл: ' + str(path))
        os.fchown(fd, session.uid, session.gid)
        os.fchmod(fd, 0o700 if stat.S_ISDIR(mode) else 0o600)
    finally:
        os.close(fd)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path, data, session):
    path = no_symlinks(path)
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
    path = no_symlinks(path)
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
    path = no_symlinks(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'ab') as stream:
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


MIN_FREE_BYTES = 128 * 1024 * 1024
MIN_FREE_INODES = 128


def no_symlinks(path):
    """Reject links in every existing path component, including the leaf."""
    path = Path(os.path.abspath(path))
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError('Символна връзка не е разрешена: ' + str(part))
    return path


def contained(path, root):
    path, root = no_symlinks(path), no_symlinks(root)
    if not path.is_relative_to(root) or path == root:
        raise ValueError('Пътят е извън работната папка: ' + str(path))
    return path


def check_space(path, extra=0):
    path = Path(path)
    while not path.exists():
        path = path.parent
    info = os.statvfs(path)
    if info.f_bavail * info.f_frsize < MIN_FREE_BYTES + extra or (info.f_files and info.f_favail < MIN_FREE_INODES):
        raise OSError(28, 'Недостатъчно свободно място/inode-и; запазен резерв 128 MiB', str(path))


def file_digest(path):
    import hashlib
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def durable_move(source, target, session):
    """Retryable cross-filesystem publish: copy/fsync/hash/link/fsync/unlink."""
    source, target = no_symlinks(source), no_symlinks(target)
    if not source.is_file():
        raise ValueError('Липсва обикновен файл: ' + str(source))
    writable_directory(target.parent, session)
    before = source.stat()
    expected = file_digest(source)
    if target.exists():
        if not target.is_file() or file_digest(target) != expected:
            raise FileExistsError('Различен файл вече съществува: ' + str(target))
    else:
        check_space(target.parent, before.st_size)
        fd, name = tempfile.mkstemp(prefix='.' + target.name + '.', suffix='.part', dir=target.parent)
        staging = Path(name)
        try:
            with os.fdopen(fd, 'wb') as output, source.open('rb') as incoming:
                while block := incoming.read(1024 * 1024):
                    check_space(target.parent)
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
            after = source.stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or file_digest(staging) != expected:
                raise OSError('Източникът се промени или копието не съвпада: ' + str(source))
            secure(staging, session)
            # link publishes atomically without overwriting a concurrent destination.
            os.link(staging, target)
            sync_directory(target.parent)
        finally:
            staging.unlink(missing_ok=True)
    with target.open('rb') as stream:
        os.fsync(stream.fileno())
    sync_directory(target.parent)
    source.unlink()
    sync_directory(source.parent)
    return {'name': target.name, 'bytes': before.st_size, 'sha256': expected}
