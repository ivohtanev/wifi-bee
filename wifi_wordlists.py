from wifi_ui import navigation, capture_location, breadcrumb
"""Pinned, verified wordlist downloads. No downloaded code or archives are executed."""
import curses
import datetime as dt
import hashlib
import json
import logging
import os
from pathlib import Path
import shutil
import threading
import time
import urllib.request
import uuid

from wifi_analysis import select
from wifi_ui import footer
from wifi_storage import atomic_json, bar, duration, secure, size, sync_directory, writable_directory, check_space, no_symlinks

CATALOG = Path(__file__).with_name('wordlist_catalog.json')


def catalog():
    return json.loads(CATALOG.read_text(encoding='utf-8'))


def dictionaries(base):
    return sorted(p for p in (base / 'wordlists').glob('*')
                  if p.is_file() and p.suffix.lower() in ('.txt', '.dic', '.lst', '.wordlist'))


def sha256_file(path, cancel=None):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            if cancel is not None and cancel.is_set():
                raise Cancelled('Подготовката е отказана.')
            digest.update(block)
    return digest.hexdigest()


def wpa_word(line):
    value = line.rstrip(b'\r\n')
    if value.startswith(b'$HEX[') and value.endswith(b']'):
        try:
            value = bytes.fromhex(value[5:-1].decode('ascii'))
        except (ValueError, UnicodeError):
            return False
    return 8 <= len(value) <= 63


def filter_wpa(source, target, cancel=None, progress=None):
    kept = skipped = 0
    no_symlinks(source)
    no_symlinks(target)
    last_check = time.monotonic()
    processed = 0
    total = source.stat().st_size
    with source.open('rb') as incoming, target.open('wb') as outgoing:
        for line in incoming:
            processed += len(line)
            if time.monotonic() - last_check >= 1:
                check_space(target.parent)
                last_check = time.monotonic()
                if progress:
                    progress(processed, total)
            if cancel is not None and cancel.is_set():
                raise Cancelled('Подготовката е отказана.')
            if wpa_word(line):
                outgoing.write(line.rstrip(b'\r\n') + b'\n')
                kept += 1
            else:
                skipped += 1
        outgoing.flush()
        os.fsync(outgoing.fileno())
    return kept, skipped


class Cancelled(Exception):
    pass


def transfer(entry, folder, session, state, cancel):
    """Only publish a complete file after both source and output hashes match."""
    token = uuid.uuid4().hex
    cancel = Deadline(cancel, 3600)
    raw = folder / ('.download-' + token + '.part')
    prepared = folder / ('.prepared-' + token + '.part')
    try:
        writable_directory(folder, session)
        check_space(folder)
        required = entry['bytes'] + entry['installed_bytes'] + 1024 * 1024
        if shutil.disk_usage(folder).free < required:
            raise OSError('Недостатъчно свободно място. Освободи поне ' + size(required) + '.')
        state.update(phase='Свързване…', done=0, total=entry['bytes'], started=time.monotonic())
        request = urllib.request.Request(entry['url'], headers={'User-Agent': 'wifi-console-wordlists/1'})
        with urllib.request.urlopen(request, timeout=15) as response, raw.open('xb') as stream:
            secure(raw, session)
            if not response.geturl().startswith('https://'):
                raise ValueError('Изтеглянето трябва да остане по HTTPS.')
            length = response.headers.get('Content-Length')
            if length and int(length) != entry['bytes']:
                raise ValueError('Размерът на източника е променен; използвай ръчно изтегляне.')
            state['phase'] = 'Изтегляне'
            while True:
                if cancel.is_set():
                    raise Cancelled('Изтеглянето е отказано.')
                check_space(folder)
                block = getattr(response, 'read1', response.read)(64 * 1024)
                if not block:
                    break
                stream.write(block)
                state['done'] += len(block)
                if state['done'] > entry['bytes']:
                    raise ValueError('Получени са повече данни от очакваното.')
            stream.flush()
            os.fsync(stream.fileno())
        state['phase'] = 'Проверка на SHA-256 и подготовка…'
        if state['done'] != entry['bytes'] or sha256_file(raw, cancel) != entry['sha256']:
            raise ValueError('Непълен или променен файл: SHA-256 не съвпада. Опитай отново.')
        if entry['filter'] == 'all':
            os.replace(raw, prepared)
        else:
            with raw.open('rb') as source, prepared.open('xb') as target:
                secure(prepared, session)
                for line in source:
                    if cancel.is_set():
                        raise Cancelled('Подготовката е отказана.')
                    line = line.rstrip(b'\r\n')
                    valid = line.isdigit() if entry['filter'] == 'digits' else line.isalpha()
                    if 8 <= len(line) <= 63 and valid:
                        target.write(line + b'\n')
                target.flush()
                os.fsync(target.fileno())
        if sha256_file(prepared, cancel) != entry['installed_sha256']:
            raise ValueError('Проверка на подготвения речник: SHA-256 не съвпада.')
        if cancel.is_set():
            raise Cancelled('Изтеглянето е отказано.')
        # Verify the pinned upstream output first, then derive a WPA-only file.
        filtered = raw
        kept, skipped = filter_wpa(prepared, filtered, cancel)
        os.replace(filtered, prepared)
        state.update(lines=kept, skipped=skipped, installed_bytes=prepared.stat().st_size)
        destination = folder / entry['filename']
        secure(prepared, session)
        if cancel.is_set():
            raise Cancelled('Изтеглянето е отказано.')
        os.replace(prepared, destination)
        sync_directory(folder)
        atomic_json(folder / (entry['id'] + '.json'), {**entry, 'downloaded_at': time.time(), 'wpa_lines': kept, 'wpa_skipped': skipped, 'wpa_sha256': sha256_file(destination)}, session)
        state['phase'] = 'Готово — проверен SHA-256'
        state['terminal'] = 'success'
    finally:
        raw.unlink(missing_ok=True)
        prepared.unlink(missing_ok=True)


def manual_instructions(entry, folder):
    target = folder / entry['filename']
    if entry['filter'] == 'all':
        instructions = f'Запази обикновения текстов файл като: {target}'
    else:
        instructions = ('Това е филтрирана извадка. Запази източника като: ' +
                        str(folder / (entry['id'] + '-source.txt')) +
                        '\nЗа точната извадка остави само редове с 8–63 ASCII ' +
                        ('цифри' if entry['filter'] == 'digits' else 'букви A–Z/a–z') +
                        f', по един на ред, LF край. Запази като: {target}')
    return ('Източник: ' + entry['source'] + '\nДиректен линк: ' + entry['url'] + '\n' +
            instructions + '\nSHA-256 източник: ' + entry['sha256'] +
            '\nSHA-256 краен файл: ' + entry['installed_sha256'] +
            '\nНекомпресирани .txt/.dic/.lst/.wordlist файлове се показват в Hashcat → Избери речник.\n')


@navigation(lambda a: 'Изтегляне › ' + a['entry']['id'])
def download(screen, session, write, entry):
    base = session.destination.parent
    folder = base / 'wordlists'
    logs = base / 'log'
    writable_directory(logs, session)
    name = 'wordlist-download-' + entry['id'] + '-' + dt.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6]
    log = logs / (name + '.log')
    help_file = logs / (name + '-manual.txt')
    help_file.write_text(manual_instructions(entry, folder), encoding='utf-8')
    secure(help_file, session)
    state = {'terminal': 'running', 'phase': 'Подготовка', 'done': 0, 'total': entry['bytes'], 'started': time.monotonic()}
    cancel = threading.Event()
    def worker():
        try:
            with log.open('w') as output:
                secure(log, session)
                output.write(entry['url'] + '\n')
                try:
                    transfer(entry, folder, session, state, cancel)
                except Exception as exc:
                    state['error'] = str(exc)
                    state['cancelled'] = isinstance(exc, Cancelled)
                    state['terminal'] = 'cancelled' if state['cancelled'] else 'error'
                    output.write(type(exc).__name__ + ': ' + str(exc) + '\n')
                    if not isinstance(exc, Cancelled):
                        logging.getLogger('wifi').exception('Wordlist download failed: %s', entry['id'])
                output.write(state['phase'] + '\n')
        except Exception as exc:
            state['error'] = str(exc)
            state['terminal'] = 'error'
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    screen.timeout(200)
    try:
        while thread.is_alive():
            screen.erase()
            elapsed = max(.001, time.monotonic() - state['started'])
            speed = state['done'] / elapsed
            lines = [entry['category'] + ' • ' + entry['name'], state['phase'],
                     bar(state['done'], state['total']),
                     f'{size(state["done"])} / {size(state["total"])} • {size(speed)}/s',
                     'Остава: ' + duration((state['total'] - state['done']) / speed if speed else None),
                     'Преди WPA филтъра: ' + size(entry['installed_bytes']) + f' • {entry["lines"]:,} реда',
                     'Q / Esc: отказ • файлът се появява едва след проверка',
                     'Ръчно изтегляне: ' + str(help_file)]
            for row, line in enumerate(lines):
                write(screen, row + 1, line)
            footer(screen, 'Q/Esc отказва изтеглянето')
            screen.refresh()
            if screen.getch() in (27, ord('q'), ord('Q')):
                cancel.set()
                state['phase'] = 'Отказ… изчакване на мрежата (до 15 s)'
    finally:
        cancel.set()
        thread.join(timeout=16)
        if thread.is_alive():
            state['error'] = 'Отмяната още приключва; няма потвърден успех.'
            state['terminal'] = 'cancelling'
            # Do not leave a worker capable of publishing after returning to the menu.
            while thread.is_alive():
                screen.erase()
                write(screen, 1, 'Отмяна… изчаква се работникът да освободи файловете.')
                footer(screen, 'Изчакай приключването на текущата операция')
                screen.refresh()
                thread.join(timeout=0.2)
    if state['terminal'] != 'success':
        state.setdefault('error', 'Изтеглянето не е потвърдено като завършено.')
        select(screen, 'Изтеглянето не завърши', ['Назад'], write,
               [state['error'], 'Провери интернет, свободното място и правата за запис.',
                'Ръчен линк и точно име: ' + str(help_file), 'Лог: ' + str(log), entry['source']])
    else:
        select(screen, 'Речникът е готов', ['Назад'], write,
               [str(folder / entry['filename']), f'{state["lines"]:,} WPA реда • пропуснати: {state["skipped"]:,} • {size(state["installed_bytes"])}',
                'SHA-256 проверен. Достъпен в Hashcat → Нова проверка.'])


@navigation('Речници')
def browse(screen, session, write):
    base = session.destination.parent
    while True:
        try:
            entries = catalog()
            labels = [f'{e["name"]} ({e["filename"]}) • [{e["category"]}] ' +
                      f'{size(e["bytes"])} → {size(e["installed_bytes"])}' +
                      (' • наличен' if (base / 'wordlists' / e['filename']).is_file() else '') for e in entries]
            idx = select(screen, 'Речници • изтегляне', labels + ['Назад'], write,
                         ['Enter изтегля • размер: за теглене → готов файл • SHA-256 проверка',
                          'Цифровите/буквените извадки се филтрират автоматично след изтегляне.',
                          'Всички списъци се филтрират до 8–63 байта преди проверка.',
                          'Няма надеждно подбран български списък тук. Може да добавиш собствен .txt.',
                          'Папка: ' + str(base / 'wordlists')])
            if idx is None or idx == len(entries):
                return
            entry = entries[idx]
            target = base / 'wordlists' / entry['filename']
            if target.exists():
                if select(screen, 'Речникът вече съществува', ['Назад', 'Изтегли и замени след проверка'], write, [str(target)]) != 1:
                    continue
            download(screen, session, write, entry)
        except (OSError, ValueError, RuntimeError) as exc:
            logging.getLogger('wifi').exception('Wordlist catalog failed')
            select(screen, 'Грешка при речниците', ['Назад'], write,
                   [str(exc), 'Провери права и свободно място. Подробности: log/wifi-console.log'])


def dictionary_label(path):
    entry = next((e for e in catalog() if e['filename'] == path.name), None)
    title = entry['name'] if entry else path.stem.replace('_', ' ').replace('-', ' ')
    return f'{title} ({path.name}) • {size(path.stat().st_size)}'


class Deadline:
    def __init__(self, event, seconds):
        self.event, self.until = event, time.monotonic() + seconds

    def is_set(self):
        if time.monotonic() >= self.until:
            raise TimeoutError('Изтеглянето/подготовката надхвърли общия срок от 1 час.')
        return self.event.is_set()
