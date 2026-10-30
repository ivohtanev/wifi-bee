from wifi_ui import navigation, capture_location, breadcrumb
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
import textwrap

from wifi_capture_info import summary as capture_summary, journal_details
from wifi_network_history import inventory, synchronize
from wifi_ui import footer
from wifi_process import Processes
from wifi_archive import archive_folder, move_captures, extracted_index, extracted_paths
from wifi_storage import secure, no_symlinks, check_space, sync_directory

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
        no_symlinks(path)
        check_space(folder, path.stat().st_size)
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
    archived = base / 'archive' / category / report['id']
    if (archived / 'manifest.json').exists():
        return archived
    if (target / 'manifest.json').exists():
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.export-', dir=target.parent))
    try:
        shutil.copytree(folder / category, staging, dirs_exist_ok=True)
        if category == 'cache':
            shutil.copytree(folder / 'sources', staging / 'sources')
        shutil.copyfile(folder / 'converter.log', staging / 'converter.log')
        check_space(staging)
        manifest = {**report, 'category': category, 'created_at': time.time()}
        manifest['outputs'] = {str(p.relative_to(staging)): fingerprint(p) for p in staging.rglob('*') if p.is_file()}
        (staging / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2))
        for p in [base / 'data', target.parent, staging, *staging.rglob('*')]:
            secure(p, session)
            if p.is_file():
                with p.open('rb') as stream:
                    os.fsync(stream.fileno())
        for directory in sorted((p for p in staging.rglob('*') if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
            sync_directory(directory)
        sync_directory(staging)
        staging.rename(target)
        sync_directory(target.parent)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return target


def select(screen, title, options, write, details=(), hotkeys=None, initial_selected=0):
    selected = initial_selected
    detail_offset = 0
    while True:
        screen.erase()
        height, width = screen.getmaxyx()
        write(screen, 0, breadcrumb(title), curses.A_BOLD)
        write(screen, 1, '↑/↓ избор • Enter • Q назад • PgUp/PgDn')
        items = list(options() if callable(options) else options)
        implicit_back = 'Назад' not in items
        if implicit_back:
            items.append('Назад')
        selected = max(0, min(selected, len(items) - 1))
        wrapped = [part for line in details for part in (textwrap.wrap(str(line), max(1, width - 4)) or [''])]
        # Reserve room for the list even on short terminals.
        detail_rows = max(0, min(7, height - 7))
        detail_offset = min(detail_offset, max(0, len(wrapped) - detail_rows))
        summary = wrapped[detail_offset:detail_offset + detail_rows]
        for row, line in enumerate(summary, 2):
            write(screen, row, line)
        top = 3 + len(summary)
        visible = max(1, height - top - 2)
        first = max(0, selected - visible + 1)
        for i in range(first, min(len(items), first + visible)):
            write(screen, top + i - first, ('▶ ' if i == selected else '  ') + ('★ ' if items[i].startswith('★ ') else '') + f'[{i + 1}] ' + items[i].removeprefix('★ '),
                  curses.A_REVERSE if i == selected else 0)
        write(screen, height - 2, f'{selected + 1}/{len(items)} • ←/→ подробности {detail_offset + 1}/{max(1, len(wrapped))}')
        footer(screen, '↑/↓ избор • Enter • Q/Esc назад • PgUp/PgDn' + (' • K архив • A премести' if hotkeys else ''))
        screen.refresh()
        key = screen.getch()
        if hotkeys and key in hotkeys:
            return (hotkeys[key], selected)
        if key in (27, ord('q'), ord('Q')):
            return None
        if key in (10, 13, curses.KEY_ENTER):
            return None if implicit_back and selected == len(items) - 1 else selected
        if key in (curses.KEY_LEFT, curses.KEY_RIGHT):
            detail_offset = max(0, detail_offset + (1 if key == curses.KEY_RIGHT else -1) * max(1, detail_rows))
        step = {curses.KEY_DOWN: 1, curses.KEY_UP: -1, curses.KEY_NPAGE: visible, curses.KEY_PPAGE: -visible}.get(key, 0)
        selected = max(0, min(len(items) - 1, selected + step))


@navigation(lambda a: 'Анализ на файлове • ' + capture_location(a))
def inspect(screen, paths, base, session, write):
    with tempfile.TemporaryDirectory(prefix='wifi-analysis-') as temp:
        folder = Path(temp)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(analyze, paths, folder)
            while not future.done():
                screen.erase()
                write(screen, 0, f'Анализ на {len(paths)} файла…', curses.A_BOLD)
                write(screen, 2, 'hcxpcapngtool + tshark • изчакване на резултата')
                footer(screen, 'Анализът работи • изчакай резултата')
                screen.refresh()
                screen.getch()
            report = future.result()
        while True:
            count = report['converter_accepted_records']
            totals = report['totals']
            labels = []
            for category, label in [('ready', f'Готови за hashcat 22000: {count}'), ('cache', 'Кеш / частични данни: оригинали + TSV')]:
                dest = base / 'data' / category / report['id']
                archived_dest = base / 'archive' / category / report['id']
                if (archived_dest / 'manifest.json').exists():
                    dest = archived_dest
                labels.append(label + (' • [Извлечени] ' + str(dest) if (dest / 'manifest.json').exists() else ' • извлечи'))
            choice = select(screen, 'Резултат от анализа', labels + ['Мрежи и устройства', 'Назад'], write, [
                f'Файлове: {len(paths)} • пакети: {totals["packets"]} • мрежи/SSID: {len(report["networks"])}',
                f'EAPOL: {totals["eapol"]} • auth: {totals["auth"]} • data: {totals["data"]}',
                f'hcxpcapngtool прие {count} записа; това не гарантира възстановяване на парола.',
                'Кешът включва всички доказателства, не само непълни handshake-и.',
                'TSV/PCAPNG: tshark / Wireshark; подробности и източници: manifest.json'])
            if choice is None or choice == 3:
                return
            if choice == 2:
                select(screen, 'Мрежи и устройства', ['Назад'], write,
                       inventory(folder / 'ready' / 'wpa.22000') +
                       [f'BSSID {ap} • SSID {name!r} (наблюдавана мрежа)' for ap, name in report['networks']] +
                       ['SSID е име на мрежата, не на клиентското устройство.'])
                continue
            if choice == 0 and not count:
                continue
            export(base, folder, report, ('ready', 'cache')[choice], session)
            synchronize(base, session).close()


ARCHIVE_KEYS = {ord('k'): 'open_archive', ord('K'): 'open_archive', ord('a'): 'archive', ord('A'): 'archive'}


@navigation(lambda a: 'Анализ' + (' › Архив' if a['archived'] else ''))
def browse(screen, session, write, archived=False):
    base = session.destination.parent
    digest_cache = {}
    readiness = {}
    root = archive_folder(base, 'captures', session) if archived else session.destination
    cursor = 0
    while True:
        groups = {}
        for path in sorted(root.glob('*.pcapng')):
            match = re.match(r'^(\d+)_', path.name)
            if match and not path.is_symlink():
                groups.setdefault(match[1], []).append(path)
        keys = sorted(groups, key=int, reverse=True)
        index = extracted_index(base)
        extracted = extracted_paths([p for paths in groups.values() for p in paths], index, digest_cache)
        processes = Processes()
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        probes = {}
        # Archived files are never submitted to a readiness converter.
        for k in ([] if archived else keys):
            paths = groups[k]
            signature = tuple((str(p), p.stat().st_size, p.stat().st_mtime_ns) for p in paths)
            if signature not in readiness:
                probes[k] = (signature, pool.submit(series_ready, paths, processes))
        def labels():
            result = []
            for k in keys:
                paths = groups[k]
                marked = sum(p in extracted for p in paths)
                label = f'Серия {k} • {len(paths)} файла'
                if marked:
                    label += ' • [Извлечени]' if marked == len(paths) else f' • [Извлечени {marked}/{len(paths)}]'
                if not archived:
                    signature = tuple((str(p), p.stat().st_size, p.stat().st_mtime_ns) for p in paths)
                    if k in probes and probes[k][1].done():
                        readiness[signature] = probes[k][1].result()
                    label += (' • [Проверява се…]' if signature not in readiness else
                              ' • [Готов]' if readiness[signature] else
                              ' • [Няма готови данни]' if readiness[signature] is False else ' • [Непроверена]')
                result.append(label)
            return result + ['Назад'] + ([] if archived else ['Архив'])
        try:
            choice = select(screen, 'Анализ • ' + ('архив' if archived else 'серии'), labels, write,
                            ['A върху запис: ' + ('възстанови' if archived else 'архивирай веднага') +
                             ' • Enter отваря' + ('' if archived else ' • K отваря Архив')], hotkeys=ARCHIVE_KEYS,
                            initial_selected=min(cursor, max(0, len(keys) - 1)))
        finally:
            processes.close()
            pool.shutdown(wait=True, cancel_futures=True)
        action, selected = choice if isinstance(choice, tuple) else ('open', choice)
        if selected is not None:
            cursor = selected
        if action == 'open_archive':
            if not archived:
                browse(screen, session, write, archived=True)
            continue
        if selected is None or selected == len(keys):
            return
        if not archived and selected == len(keys) + 1:
            browse(screen, session, write, archived=True)
            continue
        try:
            paths = groups[keys[selected]]
            if action == 'archive':
                move_captures(base, paths, session, restore=archived)
                continue
            browse_series(screen, session, write, paths, archived, digest_cache)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            logging.getLogger('wifi').exception('Грешка при анализ/архив')
            select(screen, 'Операцията не завърши', ['Назад'], write, [str(exc), 'Нищо не се презаписва. Завършените местения остават в целта.'])


@navigation(capture_location)
def browse_series(screen, session, write, paths, archived, digest_cache):
    base = session.destination.parent
    cursor = 0
    while paths:
        extracted = extracted_paths(paths, extracted_index(base), digest_cache)
        file_choice = select(screen, 'Серия • ' + ('архив' if archived else 'записи'),
                             ['Всички от серията'] + [f'Запис на трафик ({p.name})' + (' [Извлечени]' if p in extracted else '') for p in paths] + ['Статистика monitor / устройства (цялата серия)'],
                             write, ['A: ' + ('възстанови избраното' if archived else 'архивирай избраното веднага')], hotkeys=ARCHIVE_KEYS,
                             initial_selected=min(cursor, len(paths)))
        action, selected = file_choice if isinstance(file_choice, tuple) else ('open', file_choice)
        if selected is not None:
            cursor = selected
        if action == 'open_archive':
            if not archived:
                browse(screen, session, write, archived=True)
            paths = [p for p in paths if p.exists()]
            continue
        if selected is None or selected > len(paths) + 1:
            return
        if selected == len(paths) + 1:
            if action == 'open':
                show_capture_info(screen, session, write, paths)
            continue
        chosen = paths if selected == 0 else [paths[selected - 1]]
        if action == 'archive':
            move_captures(base, chosen, session, restore=archived)
            paths = [p for p in paths if p not in chosen]
        else:
            inspect(screen, chosen, base, session, write)


def series_ready(paths, processes=None):
    """Probe converter acceptance without exporting or changing captures."""
    try:
        before = [(p.stat().st_size, p.stat().st_mtime_ns) for p in paths]
        with tempfile.TemporaryDirectory(prefix='wifi-series-') as temp:
            out = Path(temp) / 'wpa.22000'
            result = (processes.run if processes else subprocess.run)(['hcxpcapngtool', '-o', str(out), *map(str, paths)],
                                    capture_output=True, timeout=30)
            after = [(p.stat().st_size, p.stat().st_mtime_ns) for p in paths]
            if result.returncode or before != after:
                return None
            return out.is_file() and out.stat().st_size > 0
    except (OSError, RuntimeError, subprocess.SubprocessError):
        return None


@navigation(lambda a: 'Статистика monitor • ' + capture_location(a))
def show_capture_info(screen, session, write, paths):
    processes = Processes()
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = pool.submit(capture_summary, paths, processes)
    try:
        while not future.done():
            screen.erase()
            write(screen, 0, 'Четене на monitor файловете…', curses.A_BOLD)
            footer(screen, 'Q/Esc отказ • анализ само при поискване')
            screen.refresh()
            if screen.getch() in (27, ord('q'), ord('Q')):
                return
        details = journal_details(session.destination.parent, paths) + future.result()
        select(screen, 'Статистика monitor / устройства', ['Назад'], write, details)
    finally:
        processes.close()
        pool.shutdown(wait=True, cancel_futures=True)
