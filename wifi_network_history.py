"""Persistent network inventory; original manifests and run files remain authoritative."""
import hashlib
import json
import sqlite3
from pathlib import Path

from wifi_storage import no_symlinks, secure, writable_directory


def records(path):
    if not path.is_file():
        return []
    result = []
    for line in path.read_text().splitlines():
        fields = line.strip().split('*')
        if len(fields) != 9 or fields[0] != 'WPA' or fields[1] not in ('01', '02'):
            continue
        try:
            ap, client = fields[3].lower(), fields[4].lower()
            if len(bytes.fromhex(ap)) != 6 or len(bytes.fromhex(client)) != 6:
                continue
            ssid = bytes.fromhex(fields[5])
            if not 1 <= len(ssid) <= 32:
                continue
        except ValueError:
            continue
        result.append((hashlib.sha256(line.strip().encode()).hexdigest(), ap, client,
                       ssid.hex(), ssid.decode('utf-8', errors='backslashreplace')))
    return result


def mac(value):
    return ':'.join(value[i:i + 2] for i in range(0, 12, 2))


def inventory(path):
    groups = {}
    for digest, ap, client, ssid, name in records(path):
        item = groups.setdefault((ap, ssid), [name, set(), set()])
        item[1].add(client)
        item[2].add(digest)
    return [f'{name!r} • BSSID {mac(ap)} • {len(hashes)} WPA записа • клиенти: '
            + ', '.join(mac(c) for c in sorted(clients))
            for (ap, ssid), (name, clients, hashes) in sorted(groups.items())]


def synchronize(base, session):
    root = base / 'data'
    writable_directory(root, session)
    path = no_symlinks(root / 'network-history.sqlite3')
    # Create with private permissions before SQLite opens it.
    path.touch(mode=0o600, exist_ok=True)
    secure(path, session)
    db = sqlite3.connect(path)
    try:
        with db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS evidence (
                    source TEXT, digest TEXT, ap TEXT, client TEXT, ssid TEXT, name TEXT,
                    PRIMARY KEY(source, digest));
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY, metadata TEXT);
                DELETE FROM evidence;
                DELETE FROM runs;
            ''')
            sources = list((base / 'data' / 'ready').glob('*/wpa.22000'))
            sources += list((base / 'archive' / 'ready').glob('*/wpa.22000'))
            for run in (base / 'data' / 'hashcat').glob('*/run.json'):
                try:
                    meta = json.loads(run.read_text())
                    db.execute('INSERT OR REPLACE INTO runs VALUES (?, ?)', (meta['id'], json.dumps(meta)))
                    sources.append(run.parent / 'input.22000')
                except (OSError, ValueError, KeyError):
                    continue
            for source in sources:
                for row in records(source):
                    db.execute('INSERT OR IGNORE INTO evidence VALUES (?, ?, ?, ?, ?, ?)',
                               (str(source), *row))
        return db
    except BaseException:
        db.close()
        raise


def state(meta):
    if meta.get('status') == 'finished':
        return 'изчерпана' if meta.get('returncode') == 1 else 'намерени съвпадения; не доказва пълно покритие'
    return {'stopped': 'спряна', 'interrupted': 'прекъсната', 'error': 'грешка',
            'running': 'стартирана (статусът може да е остарял)'}.get(meta.get('status'), meta.get('status', '?'))


def previous(base, session, hashes, candidate=None, attack_mode=0):
    current = records(hashes)
    networks = {(r[1], r[3]) for r in current}
    digests = {r[0] for r in current}
    signature = hashlib.sha256(candidate.read_bytes()).hexdigest() if candidate else None
    db = synchronize(base, session)
    lines = []
    try:
        for run_id, raw in db.execute('SELECT id, metadata FROM runs ORDER BY id DESC'):
            meta = json.loads(raw)
            source = str(base / 'data' / 'hashcat' / run_id / 'input.22000')
            evidence = list(db.execute('SELECT digest, ap, ssid FROM evidence WHERE source=?', (source,)))
            matched = {(ap, ssid) for digest, ap, ssid in evidence} & networks
            if not matched:
                continue
            exact = bool({r[0] for r in evidence} & digests)
            same = signature == meta.get('candidate_source_sha256') and attack_mode == meta.get('attack_mode', 0) if signature else False
            lines.append(f'{run_id} • {len(matched)} съвпадащи мрежи • '
                         + ('има същия WPA запис' if exact else 'различни WPA записи')
                         + ' • ' + state(meta) + (' • същият вход и режим' if same else '')
                         + ' • ' + Path(meta.get('original_dictionary', meta.get('dictionary', '?'))).name)
    finally:
        db.close()
    return lines


def browse(screen, session, write):
    from wifi_analysis import select
    base = session.destination.parent
    db = synchronize(base, session)
    try:
        networks = list(db.execute('SELECT DISTINCT ap, ssid, name FROM evidence ORDER BY name, ap'))
    finally:
        db.close()
    while True:
        choice = select(screen, 'Мрежи и история', [f'{name!r} • {mac(ap)}' for ap, ssid, name in networks], write,
                        ['SSID е име на мрежата; имената на клиентските устройства не са налични.',
                         'Същият BSSID/SSID не доказва непроменена парола.'])
        if choice is None:
            return
        ap, ssid, name = networks[choice]
        db = synchronize(base, session)
        try:
            rows = list(db.execute('SELECT DISTINCT source, client FROM evidence WHERE ap=? AND ssid=?', (ap, ssid)))
            details = ['Клиент: ' + mac(client) + ' • ' + source for source, client in rows]
            for run_id, raw in db.execute('SELECT id, metadata FROM runs ORDER BY id DESC'):
                source = str(base / 'data' / 'hashcat' / run_id / 'input.22000')
                if any(r[0] == source for r in rows):
                    meta = json.loads(raw)
                    details.append(run_id + ' • ' + state(meta) + ' • ' + meta.get('dictionary', '?')
                                   + ' • резултати: ' + meta.get('results', '?'))
        finally:
            db.close()
        select(screen, f'{name!r} • {mac(ap)}', ['Назад'], write, details)
