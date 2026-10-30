"""Explicit, reversible archives; provenance follows content, not paths."""
import json
from pathlib import Path
import os
import time
import uuid

from wifi_storage import (atomic_json, contained, durable_move, file_digest,
                          no_symlinks, sync_directory, writable_directory)


def archive_folder(base, category, session):
    root = base / 'archive' / category
    writable_directory(base / 'archive', session)
    writable_directory(root, session)
    return root


def move_captures(base, paths, session, restore=False):
    active = session.destination
    archive = archive_folder(base, 'captures', session)
    source_root, destination = (archive, active) if restore else (active, archive)
    paths = [contained(path, source_root) for path in paths]
    for path in paths:
        if not path.is_file() or path.suffix != '.pcapng':
            raise ValueError('Архивират се само capture файлове.')
        target = destination / path.name
        no_symlinks(target)
        if target.exists() and file_digest(target) != file_digest(path):
            raise FileExistsError('В целта има различен запис: ' + target.name)
    journal_dir = base / 'data' / 'transfers'
    writable_directory(journal_dir, session)
    journal = journal_dir / (uuid.uuid4().hex + '.json')
    state = {'created': time.time(), 'kind': 'restore' if restore else 'archive',
             'destination': str(destination), 'pending': [str(p) for p in paths], 'done': []}
    atomic_json(journal, state, session)
    for path in paths:
        result = durable_move(path, destination / path.name, session)
        state['done'].append(result)
        state['pending'].remove(str(path))
        atomic_json(journal, state, session)
    return destination


def move_dataset(base, folder, session, restore=False):
    active = base / 'data' / 'ready'
    archive = archive_folder(base, 'ready', session)
    source_root, destination = (archive, active) if restore else (active, archive)
    folder = contained(folder, source_root)
    if folder.parent != source_root or not (folder / 'manifest.json').is_file():
        raise ValueError('Неподдържан набор за архивиране.')
    for path in folder.rglob('*'):
        no_symlinks(path)
    writable_directory(destination, session)
    target = destination / folder.name
    no_symlinks(target)
    if target.exists():
        raise FileExistsError('Наборът вече съществува: ' + str(target))
    # Dataset and hashcat job are separate: never relocate job inputs/restore.
    os.rename(folder, target)
    sync_directory(source_root)
    sync_directory(destination)
    return target


def extracted_index(base):
    index = set()
    for root in (base / 'data' / 'ready', base / 'archive' / 'ready', base / 'data' / 'cache'):
        for path in root.glob('*/manifest.json'):
            try:
                record = json.loads(no_symlinks(path).read_text())
                if record.get('category') in ('ready', 'cache'):
                    for source in record.get('sources', []):
                        index.add((Path(source['path']).name, source['sha256']))
            except (OSError, ValueError, KeyError, TypeError):
                continue
    return index


def extracted_paths(paths, index, cache):
    """Only matching filenames need hashing; cache invalidates when a file changes."""
    names = {name for name, digest in index}
    found = set()
    for path in paths:
        if path.name not in names:
            continue
        stat = path.stat()
        key = (str(path), stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
        if key not in cache:
            cache[key] = file_digest(no_symlinks(path))
        if (path.name, cache[key]) in index:
            found.add(path)
    return found
