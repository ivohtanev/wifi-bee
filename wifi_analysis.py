import logging
"""Offline capture inventory, analysis and provenance-aware exports."""
import concurrent.futures
import curses
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

VERSION = 1


def run(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=600)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or 'Неуспешен анализ')
    return result.stdout + result.stderr


def fingerprint(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def analyze(paths, folder):
    sources = []
    snapshot = folder / 'sources'
    snapshot.mkdir()
    for path in paths:
        before = path.stat()
        dest = snapshot / path.name
        shutil.copyfile(path, dest)
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise RuntimeError('Файлът се променя; спри записа преди анализ: ' + path.name)
        sources.append({'path': str(path.resolve()), 'sha256': fingerprint(dest), 'bytes': dest.stat().st_size})
    key = hashlib.sha256(json.dumps({'version': VERSION, 'sources': sources}, sort_keys=True).encode()).hexdigest()[:24]
    ready = folder / 'ready'
    ready.mkdir()
    log = run(['hcxpcapngtool', '-o', str(ready / 'wpa.22000'), *map(str, sorted(snapshot.iterdir()))])
    (folder / 'converter.log').write_text(log)
    hashes = ready / 'wpa.22000'
    count = len(hashes.read_text().splitlines()) if hashes.exists() else 0
    cache = folder / 'cache'
    cache.mkdir()
    totals = {'packets': 0, 'eapol': 0, 'auth': 0, 'data': 0}
    networks = set()
    for index, path in enumerate(sorted(snapshot.iterdir())):
        out = cache / f'{index + 1:04d}-frames.tsv'
        with out.open('w') as handle:
            result = subprocess.run(['tshark', '-r', str(path), '-T', 'fields', '-E', 'header=y',
                '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'wlan.fc.type_subtype',
                '-e', 'wlan.bssid', '-e', 'wlan.ssid', '-e', 'eapol.type'], stdout=handle,
                stderr=subprocess.PIPE, text=True, timeout=600)
        if result.returncode:
            raise RuntimeError(result.stderr)
        with out.open() as stream:
            next(stream, None)
            for line in stream:
                fields = line.rstrip('\n').split('\t')
                totals['packets'] += 1
                totals['eapol'] += bool(fields[5])
                totals['auth'] += fields[2] == '0x000b'
                totals['data'] += fields[2].startswith('0x002')
                if fields[3] or fields[4]:
                    networks.add((fields[3], fields[4]))
    report = {'schema_version': VERSION, 'id': key, 'sources': sources, 'totals': totals,
              'hashcat_mode': 22000, 'converter_accepted_records': count,
              'networks': sorted(networks),
              'classification': 'Converter accepted does not guarantee password recovery. Cache is unclassified evidence, not a count of incomplete handshakes.',
              'tools': {'hcxpcapngtool': run(['hcxpcapngtool', '-v']).strip(),
                        'tshark': run(['tshark', '-v']).splitlines()[0]}}
    (folder / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2))
    return report


def export(base, folder, report, category, session):
    target = base / 'data' / category / report['id']
    if (target / 'manifest.json').exists():
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.export-', dir=target.parent))
    try:
        shutil.copytree(folder / category, staging, dirs_exist_ok=True)
        if category == 'cache':
            shutil.copytree(folder / 'sources', staging / 'sources')
        shutil.copyfile(folder / 'converter.log', staging / 'converter.log')
        manifest = {**report, 'category': category, 'created_at': time.time()}
        manifest['outputs'] = {str(p.relative_to(staging)): fingerprint(p) for p in staging.rglob('*') if p.is_file()}
        (staging / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2))
        for p in [base / 'data', target.parent, staging, *staging.rglob('*')]:
            os.chown(p, session.uid, session.gid)
            p.chmod(0o700 if p.is_dir() else 0o600)
        staging.rename(target)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return target


def select(screen, title, options, write, details=()):
    selected = 0
    while True:
        screen.erase()
        height, width = screen.getmaxyx()
        write(screen, 0, title, curses.A_BOLD)
        write(screen, 1, '↑/↓ избор • Enter • Q назад • PgUp/PgDn')
        # Reserve room for the list even on short terminals.
        summary = list(details)[:max(0, min(7, height - 7))]
        for row, line in enumerate(summary, 2):
            write(screen, row, line)
        top = 3 + len(summary)
        visible = max(1, height - top - 2)
        first = max(0, selected - visible + 1)
        for i in range(first, min(len(options), first + visible)):
            write(screen, top + i - first, ('▶ ' if i == selected else '  ') + options[i],
                  curses.A_REVERSE if i == selected else 0)
        write(screen, height - 2, f'{selected + 1}/{len(options)}')
        screen.refresh()
        key = screen.getch()
        if key in (27, ord('q'), ord('Q')):
            return None
        if key in (10, 13, curses.KEY_ENTER):
            return selected
        step = {curses.KEY_DOWN: 1, curses.KEY_UP: -1, curses.KEY_NPAGE: visible, curses.KEY_PPAGE: -visible}.get(key, 0)
        selected = max(0, min(len(options) - 1, selected + step))


def inspect(screen, paths, base, session, write):
    with tempfile.TemporaryDirectory(prefix='wifi-analysis-') as temp:
        folder = Path(temp)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(analyze, paths, folder)
            while not future.done():
                screen.erase()
                write(screen, 0, f'Анализ на {len(paths)} файла…', curses.A_BOLD)
                write(screen, 2, 'hcxpcapngtool + tshark • изчакване на резултата')
                screen.refresh()
                screen.getch()
            report = future.result()
        while True:
            count = report['converter_accepted_records']
            totals = report['totals']
            labels = []
            for category, label in [('ready', f'Готови за hashcat 22000: {count}'), ('cache', 'Кеш / частични данни: оригинали + TSV')]:
                dest = base / 'data' / category / report['id']
                labels.append(label + (' • извлечени: ' + str(dest) if (dest / 'manifest.json').exists() else ' • извлечи'))
            choice = select(screen, 'Резултат от анализа', labels + ['Назад'], write, [
                f'Файлове: {len(paths)} • пакети: {totals["packets"]} • мрежи/SSID: {len(report["networks"])}',
                f'EAPOL: {totals["eapol"]} • auth: {totals["auth"]} • data: {totals["data"]}',
                f'hcxpcapngtool прие {count} записа; това не гарантира възстановяване на парола.',
                'Кешът включва всички доказателства, не само непълни handshake-и.',
                'TSV/PCAPNG: tshark / Wireshark; подробности и източници: manifest.json'])
            if choice is None or choice == 2:
                return
            if choice == 0 and not count:
                continue
            export(base, folder, report, ('ready', 'cache')[choice], session)


def browse(screen, session, write):
    base = session.destination.parent
    while True:
        groups = {}
        for path in sorted(session.destination.glob('*.pcapng')):
            match = re.match(r'^(\d+)_', path.name)
            if match:
                groups.setdefault(match[1], []).append(path)
        keys = sorted(groups, key=int, reverse=True)
        if not keys:
            select(screen, 'Няма записи', ['Назад'], write)
            return
        choice = select(screen, 'Анализ • серии', [f'Серия {k} • {len(groups[k])} файла' for k in keys], write)
        if choice is None:
            return
        paths = groups[keys[choice]]
        while True:
            file_choice = select(screen, 'Серия ' + keys[choice], ['Всички от серията'] + [p.name for p in paths], write)
            if file_choice is None:
                break
            try:
                inspect(screen, paths if file_choice == 0 else [paths[file_choice - 1]], base, session, write)
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                logging.getLogger('wifi').exception('Грешка при анализ')
                select(screen, 'Грешка при анализа', ['Назад'], write, [str(exc)])
