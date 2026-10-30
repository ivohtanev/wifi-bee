"""Dictionary and installed-mask runs over verified WPA 22000 exports."""
import curses
import datetime as dt
import fcntl
import json
import logging
import os
import pty
import re
import tty
from pathlib import Path
import shutil
import signal
import subprocess
import time
import traceback
import struct
import sys
import platform
import uuid

from wifi_analysis import fingerprint, select, ARCHIVE_KEYS
from wifi_archive import archive_folder, move_dataset


from wifi_storage import (secure, atomic_json, writable_directory, durable_touch,
                          bar, duration, check_space, no_symlinks, contained)
from wifi_wordlists import dictionaries, dictionary_label, browse as browse_wordlists, filter_wpa
from wifi_network_history import inventory, previous, synchronize, browse as browse_networks
from wifi_ui import footer


def load_dataset(folder):
    no_symlinks(folder)
    no_symlinks(folder / 'manifest.json')
    no_symlinks(folder / 'wpa.22000')
    manifest = json.loads((folder / 'manifest.json').read_text())
    hashes = folder / 'wpa.22000'
    if manifest.get('category') != 'ready' or manifest.get('hashcat_mode') != 22000:
        raise ValueError('Неподдържан набор: нужен е ready / режим 22000.')
    expected = manifest.get('outputs', {}).get('wpa.22000')
    if not expected or fingerprint(hashes) != expected:
        raise ValueError('Данните са променени или непълни. Извлечи ги отново чрез Анализ.')
    lines = hashes.read_text().splitlines()
    if not lines or any(not line.startswith(('WPA*01*', 'WPA*02*')) for line in lines):
        raise ValueError('Липсват използваеми WPA записи.')
    return manifest, hashes, len(lines)


def explain(code):
    return {
        -signal.SIGINT: 'Задачата е спряна от потребителя. Резултатите са запазени; възобнови от наличния checkpoint.',
        -signal.SIGTERM: 'Процесът е прекратен. Резултатите остават; провери наличието на checkpoint.',
        0: 'Hashcat приключи успешно. Виж recovered.txt за намерените записи.',
        1: 'Избраното пространство от кандидати е изчерпано. Възможно е да има частичен успех; виж recovered.txt. Това не доказва, че паролата е невъзстановима.',
        2: 'Задачата е прекратена. Вече намерените резултати са запазени.',
        3: 'Задачата е прекратена при checkpoint.',
        4: 'Достигнат е времевият лимит.',
        5: 'Hashcat е спрян преди пълно приключване. Виж лога за причината.',
        6: 'Hashcat не успя да започне/довърши задачата; провери backend и лога.',
    }.get(code, f'Грешка (код {code}). Възможни причини: GPU/OpenCL драйвер, памет, права или невалидни данни. Точната причина е в лога.')


def text_input(screen, write, title):
    value = bytearray()
    while True:
        screen.erase()
        write(screen, 0, title, curses.A_BOLD)
        write(screen, 2, 'Пълен път • Enter избира • Esc отказва')
        write(screen, 4, value.decode('utf-8', errors='replace')[-max(1, screen.getmaxyx()[1] - 3):])
        footer(screen, 'Текст: път (малко h) • Enter избира • Esc отказ • F1 помощ')
        screen.refresh()
        key = getattr(screen, 'read_text_key', screen.getch)()
        if key == 27:
            return None
        if key in (10, 13, curses.KEY_ENTER):
            return value.decode('utf-8').strip()
        if key in (curses.KEY_BACKSPACE, 127, 8):
            value = bytearray(value.decode('utf-8', errors='ignore')[:-1].encode('utf-8'))
        elif 32 <= key <= 255:
            value.append(key)


def stop_process(proc):
    if proc.poll() is None:
        os.killpg(proc.pid, signal.SIGINT)
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()


class StatusReader:
    """Incremental log reader; never drops a JSON record split across writes."""
    def __init__(self, path, offset=0):
        self.path = path
        self.offset = offset
        self.pending = b''
        self.latest = {}
        self.messages = []

    def update(self):
        with self.path.open('rb') as stream:
            stream.seek(self.offset)
            block = stream.read(1024 * 1024)
            self.offset = stream.tell()
        lines = (self.pending + block).split(b'\n')
        self.pending = lines.pop()[-1024 * 1024:]
        for raw in lines:
            line = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', raw.decode('utf-8', errors='replace')).strip()
            line = re.sub(r'\[s\]tatus.*?=>\s*', '', line).strip()
            try:
                record = json.JSONDecoder().raw_decode(line[line.index('{'):])[0]
            except (ValueError, TypeError):
                record = None
            if isinstance(record, dict) and isinstance(record.get('progress'), list) and len(record['progress']) == 2:
                self.latest = record
            elif line:
                self.messages = (self.messages + [line])[-4:]
        return self.latest


def display_plain(line):
    # Outfile format 1,2: hash:plain. WPA hashes themselves contain no colons.
    plain = line.partition(':')[2]
    if plain.startswith('$HEX[') and plain.endswith(']'):
        try:
            plain = bytes.fromhex(plain[5:-1]).decode('utf-8', errors='backslashreplace')
        except ValueError:
            pass
    return ''.join(c if c.isprintable() else f'\\x{ord(c):02x}' for c in plain)


class ResultReader:
    """Count all complete records; retain only a bounded display tail."""
    def __init__(self, path):
        self.path, self.offset, self.pending = path, 0, b''
        self.count, self.lines = 0, []

    def update(self):
        with no_symlinks(self.path).open('rb') as stream:
            stream.seek(self.offset)
            while block := stream.read(1024 * 1024):
                self.offset = stream.tell()
                lines = (self.pending + block).split(b'\n')
                self.pending = lines.pop()
                for line in lines:
                    if b':' in line:
                        self.count += 1
                        self.lines.append(line.decode('utf-8', errors='replace').rstrip('\r'))
                self.lines = self.lines[-50:]
        return self.lines


def result_snapshot(path):
    reader = ResultReader(path)
    return reader.update()


def save_progress(job, metadata, status, session):
    metadata['snapshot_at'] = time.time()
    metadata['progress'] = status
    metadata['checkpoint_available'] = (job / 'hashcat.restore').is_file()
    for name in ('recovered.txt', 'hashcat.potfile', 'hashcat.restore'):
        path = job / name
        if path.exists():
            try:
                secure(path, session)
                with path.open('rb') as stream:
                    os.fsync(stream.fileno())
            except FileNotFoundError:
                # hashcat removes its checkpoint on successful completion.
                pass
    atomic_json(job / 'run.json', metadata, session)
    if metadata.get('finished'):
        synchronize(job.parent.parent.parent, session).close()


def build_command(metadata, job):
    if metadata.get('attack_mode', 0) not in (0, 3) or not re.fullmatch(r'[A-Za-z0-9_-]+', metadata['id']):
        raise ValueError('Невалидна задача/режим.')
    dictionary = no_symlinks(Path(metadata['dictionary']))
    command = ['hashcat', '-m', '22000', '-a', str(metadata.get('attack_mode', 0)), '-w', '1',
               '--status', '--status-json', '--status-timer', '1', '--session', 'wifi-' + metadata['id'],
               '--restore-file-path', str(job / 'hashcat.restore'), '--potfile-path', str(job / 'hashcat.potfile'),
               '--outfile', str(job / 'recovered.txt'), '--outfile-format', '1,2',
               str(job / 'input.22000'), str(dictionary)]
    if metadata.get('attack_mode') == 3 and dictionary.name == 'hashcat-default.hcmask':
        command += ['--increment', '--increment-min', '8', '--increment-max', '15']
    return command


def validate_restore(path, job, expected):
    # Hashcat Linux restore v6/v7: u32 version, cwd[256], 2*u32,
    # alignment + u64 words_cur, u32 argc + alignment + pointer, newline argv.
    raw = no_symlinks(path).read_bytes()
    if len(raw) < 296 or len(raw) > 1024 * 1024:
        raise ValueError('Повреден/неподдържан restore файл.')
    argc = struct.unpack_from('<I', raw, 280)[0]
    cwd = raw[4:260].split(b'\0', 1)[0].decode('utf-8')
    arguments = raw[296:].decode('utf-8').splitlines()
    if Path(cwd) != job or argc != len(arguments) or arguments != expected:
        raise ValueError('Restore аргументите не съвпадат с валидираната задача.')


def resume_command(metadata, job):
    job = no_symlinks(job)
    dictionary = no_symlinks(Path(metadata['dictionary']))
    source = no_symlinks(job / 'input.22000')
    if not metadata.get('dictionary_sha256') or fingerprint(dictionary) != metadata['dictionary_sha256']:
        raise ValueError('Речникът/маската липсва или е променен. Върни оригиналния файл преди възобновяване.')
    if fingerprint(source) != metadata['input_sha256']:
        raise ValueError('Входните WPA записи са променени. Не може безопасно да се възобнови.')
    restore = job / 'hashcat.restore'
    if not restore.is_file():
        raise ValueError('Няма checkpoint от hashcat. Започни нова проверка.')
    command = build_command(metadata, job)
    validate_restore(restore, job, command)
    help_text = subprocess.run(['hashcat', '--help'], capture_output=True, text=True, timeout=15, check=True).stdout
    if '--restore-position' in help_text:
        return [*command, '--restore-position']
    return ['hashcat', '--session', 'wifi-' + metadata['id'], '--restore-file-path', str(restore), '--restore']


def draw_run(screen, write, metadata, status, reader, results, job):
    screen.erase()
    write(screen, 0, 'Hashcat • ' + ('маски' if metadata.get('attack_mode') == 3 else 'речникова проверка'), curses.A_BOLD)
    progress = status.get('progress', [0, 0])
    done, total = progress
    rejected = status.get('rejected', 0)
    devices = status.get('devices', [])
    speed = sum(d.get('speed', 0) for d in devices)
    stop = status.get('estimated_stop', 0)
    eta = max(0, stop - time.time()) if stop > 1 else None
    recovered = status.get('recovered_hashes', [metadata.get('recovered', 0), metadata['records']])
    lines = [('Маска: ' if metadata.get('attack_mode') == 3 else 'Речник: ') + Path(metadata.get('original_dictionary', metadata['dictionary'])).name,
             bar(done, total),
             f'Обработени: {done:,} / {total:,} • отхвърлени: {rejected:,}',
             f'Проверки (без отхвърлените): {max(0, done - rejected):,} • {speed:,.0f} H/s',
             'Остава: ' + duration(eta) + ' • тази сесия: ' + duration(time.time() - metadata['resumed_at']),
             f'Потвърдени записи: {recovered[0]} / {recovered[1]} • checkpoint: {status.get("restore_point", "изчакване")}',
             'Резултати: ' + str(job / 'recovered.txt'),
             'Отхвърлени = невалидни кандидати (напр. дължина), а не грешни пароли.']
    for row, line in enumerate(lines, 2):
        write(screen, row, line)
    row = 11
    guess = status.get('guess', {})
    write(screen, row, f'Шаблон/файл {guess.get("guess_base_offset", "?")}/{guess.get("guess_base_count", "?")}: {guess.get("guess_base", "подготовка")}')
    row += 1
    for device in devices:
        def metric(key, suffix):
            value = device.get(key, -1)
            return str(value) + suffix if value is not None and value >= 0 else 'н/д'
        write(screen, row, f'#{device.get("device_id", "?")} {device.get("device_type", "Устройство")} ' +
              f'{device.get("device_name", "виж лога")} • {device.get("speed", 0):,.0f} H/s')
        write(screen, row + 1, f'Температура: {metric("temp", "°C")} • натоварване: {metric("util", "%")} • вентилатор: {metric("fanspeed", "%")}')
        row += 2
    if not devices:
        write(screen, row, 'Инициализация на GPU/CPU… първата статистика може да се забави.')
        row += 1
    if results:
        write(screen, row, 'НАМЕРЕНА ПАРОЛА — съвпада с WPA запис; запазена:', curses.A_BOLD)
        write(screen, row + 1, display_plain(results[-1]) if metadata.get('show_password') else '•••••••• • V показва/скрива', curses.A_BOLD)
        row += 2
    state_label = {3: 'Работи', 4: 'Пауза', 5: 'Изчерпан', 6: 'Намерени', 7: 'Прекратен', 10: 'Спрян при checkpoint'}.get(status.get('status'), 'Подготовка')
    write(screen, row, state_label + ' • ' + metadata.get('control_message', 'Статистика: на 1 s; текущ шаблон/файл.'))
    row += 1
    for message in ([] if status else reader.messages[-2:]):
        write(screen, row, ''.join(c if c.isprintable() else ' ' for c in message))
        row += 1
    footer(screen, 'S статус • P пауза • R продължи • B пропусни • C/Q/Esc запази и спри')
    screen.refresh()


def execute(screen, session, write, folder, dictionary, resume_job=None, attack_mode=0, prevent_sleep=False):
    if attack_mode not in (0, 3):
        raise ValueError('Неподдържан режим на проверка.')
    base = session.destination.parent.resolve()
    screen.timeout(200)
    def preparation_progress(done, total):
        screen.erase()
        write(screen, 0, 'Подготовка на WPA речник • ' + bar(done, total))
        footer(screen, 'Q/Esc отказва подготовката')
        screen.refresh()
        if screen.getch() in (ord('q'), ord('Q'), 27):
            raise ValueError('Подготовката е отказана.')
    if not shutil.which('hashcat'):
        raise ValueError('hashcat не е инсталиран или не е в PATH. Инсталирай hashcat и GPU/OpenCL драйвера.')
    screen.erase()
    write(screen, 0, 'Подготовка: проверка на файловете, SHA-256 и запис на диска…')
    footer(screen, 'Подготовка на hashcat • изчакай')
    screen.refresh()
    check_space(base)
    jobs = base / 'data' / 'hashcat'
    log_dir = base / 'log'
    writable_directory(jobs, session)
    writable_directory(log_dir, session)
    if resume_job is None:
        manifest, hashes, count = load_dataset(folder)
        dictionary = no_symlinks(dictionary)
        if not dictionary.is_file() or dictionary.stat().st_size == 0:
            raise ValueError('Входният файл липсва или е празен. Нужен е текстов речник или .hcmask файл.')
        with dictionary.open('rb') as stream:
            sample = stream.read(8192)
        if b'\x00' in sample or sample.startswith((b'\x1f\x8b', b'PK\x03\x04')):
            raise ValueError('Речникът изглежда двоичен/архивиран. Разархивирай го до текстов файл.')
        run_id = dt.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
        job = jobs / run_id
        writable_directory(job, session)
        original_dictionary = dictionary
        skipped = 0
        if attack_mode == 0:
            dictionary = job / 'candidates.txt'
            kept, skipped = filter_wpa(original_dictionary, dictionary, progress=preparation_progress)
            if not kept:
                raise ValueError('Няма кандидати с допустима WPA дължина: 8–63 байта.')
        if attack_mode == 3:
            prepared_mask = job / dictionary.name
            patterns = mask_patterns(dictionary)
            usable = patterns if dictionary.name == 'hashcat-default.hcmask' else [line for line in patterns if 8 <= mask_length(line) <= 63]
            if not usable:
                raise ValueError('Маската няма шаблони с WPA дължина 8–63 байта.')
            prepared_mask.write_text('\n'.join(usable) + '\n')
            dictionary = prepared_mask
        source = job / 'input.22000'
        shutil.copyfile(hashes, source)
        if fingerprint(source) != manifest['outputs']['wpa.22000']:
            raise ValueError('Наборът е променен по време на подготовката.')
        shutil.copyfile(folder / 'manifest.json', job / 'source-manifest.json')
        command = ['hashcat', '-m', '22000', '-a', str(attack_mode), '-w', '1', '--status', '--status-json',
                   '--status-timer', '1', '--session', 'wifi-' + run_id,
                   '--restore-file-path', str(job / 'hashcat.restore'),
                   '--potfile-path', str(job / 'hashcat.potfile'),
                   '--outfile', str(job / 'recovered.txt'), '--outfile-format', '1,2',
                   str(source), str(dictionary)]
        if attack_mode == 3 and dictionary.name == 'hashcat-default.hcmask':
            command += ['--increment', '--increment-min', '8', '--increment-max', '15']
        metadata = {'prevent_sleep': prevent_sleep, 'attack_mode': attack_mode, 'id': run_id, 'dataset': str(folder), 'source_id': manifest['id'],
                    'original_dictionary': str(original_dictionary), 'filtered_out': skipped,
                    'dictionary': str(dictionary), 'dictionary_sha256': fingerprint(dictionary),
                    'candidate_source_sha256': fingerprint(original_dictionary),
                    'input_sha256': fingerprint(source), 'command': command, 'records': count,
                    'started': time.time(), 'status': 'starting', 'results': str(job / 'recovered.txt')}
    else:
        job = contained(resume_job, jobs)
        metadata = json.loads((job / 'run.json').read_text())
        command = None
        writable_directory(job, session)
    # Lock is inherited by hashcat so an orphaned process also blocks a second resume.
    with no_symlinks(job / '.run.lock').open('a') as lock:
        secure(job / '.run.lock', session)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError('Тази задача вече работи. Спри активния процес преди възобновяване.') from exc
        if resume_job is not None:
            command = resume_command(metadata, job)
        suffix = ('-resume-' + uuid.uuid4().hex[:6]) if resume_job else ''
        log = log_dir / ('hashcat-' + metadata['id'] + suffix + '.log')
        metadata.update(log=str(log), resumed_at=time.time(), status='starting', show_password=False)
        metadata.pop('control_message', None)
        metadata.pop('error', None)
        metadata.pop('finished', None)
        result = job / 'recovered.txt'
        # Fail before launching if results, potfile, metadata or logs cannot be written.
        for path in (result, job / 'hashcat.potfile', log):
            durable_touch(path, session)
        for path in job.iterdir():
            secure(path, session)
        metadata['environment'] = tool_environment()
        metadata.setdefault('created_environment', metadata['environment'])
        if Path(metadata['dictionary']).parent == job:
            Path(metadata['dictionary']).chmod(0o400)
        save_progress(job, metadata, metadata.get('progress', {}), session)
        proc = None
        control_fd = slave_fd = None
        checkpoint_requested = False
        checkpoint_sent = False
        checkpoint_not_before = 0
        reader = StatusReader(log)
        status = {}
        result_reader = ResultReader(result)
        results = result_reader.update()
        last_save = time.monotonic()
        last_result_size = result.stat().st_size
        last_disk_check = 0
        old_umask = os.umask(0o077)
        previous_hook = getattr(screen, 'poll_hook', None)
        def monitor():
            nonlocal status, results, last_save, last_result_size, last_disk_check
            status = reader.update()
            now = time.monotonic()
            if now - last_disk_check >= 2:
                check_space(job)
                check_space(log.parent)
                last_disk_check = now
            result_size = result.stat().st_size
            if result_size != last_result_size:
                results = result_reader.update()
                metadata['recovered'] = result_reader.count
                save_progress(job, metadata, status, session)
                last_result_size, last_save = result_size, now
            elif now - last_save >= 10:
                save_progress(job, metadata, status, session)
                last_save = now
            if previous_hook:
                previous_hook()

        try:
            with log.open('a') as output:
                output.write('Command: ' + json.dumps(command, ensure_ascii=False) + '\n')
                output.flush()
                os.fsync(output.fileno())
                control_fd, slave_fd = pty.openpty()
                tty.setraw(slave_fd)
                launch_command = command
                if metadata.get('prevent_sleep'):
                    if not shutil.which('systemd-inhibit'):
                        raise ValueError('Липсва systemd-inhibit; изключи забраната за заспиване.')
                    launch_command = ['systemd-inhibit', '--what=idle:sleep', '--mode=block', '--no-ask-password',
                                      '--who=Wi-Fi console', '--why=Active hashcat check', '--', *command]
                proc = subprocess.Popen(launch_command, cwd=job, stdin=slave_fd,
                                        stdout=output, stderr=subprocess.STDOUT, start_new_session=True,
                                        pass_fds=(lock.fileno(),), env={**os.environ, 'LC_ALL': 'C'})
                os.close(slave_fd)
                slave_fd = None
                metadata.update(status='running', pid=proc.pid)
                save_progress(job, metadata, status, session)
                screen.timeout(200)
                screen.poll_hook = monitor
                while proc.poll() is None:
                    monitor()
                    if checkpoint_requested and not checkpoint_sent and time.monotonic() >= checkpoint_not_before and status.get('status') == 3:
                        os.write(control_fd, b'c')
                        checkpoint_sent = True
                    draw_run(screen, write, metadata, status, reader, results, job)
                    key = screen.getch()
                    if key in (ord('v'), ord('V')):
                        metadata['show_password'] = not metadata.get('show_password', False)
                    elif key in (ord('s'), ord('S'), ord('p'), ord('P'), ord('r'), ord('R')) and not checkpoint_requested:
                        os.write(control_fd, chr(key).lower().encode())
                        metadata['control_message'] = { 's': 'Заявена нова статистика.', 'p': 'Заявена пауза • R продължава.', 'r': 'Заявено продължаване.' }[chr(key).lower()]
                    elif key in (ord('b'), ord('B')) and not checkpoint_requested:
                        if select(screen, 'Пропускане на текущия шаблон/файл?', ['Назад', 'Пропусни'], write,
                                  ['Останалите кандидати от този шаблон няма да се проверят.']) == 1:
                            os.write(control_fd, b'b')
                    elif key in (ord('c'), ord('C'), ord('q'), ord('Q'), 27) and not checkpoint_requested:
                        if select(screen, 'Запазване и спиране?', ['Не — продължи', 'Да — запази и спри'], write,
                                  ['Изчаква безопасната точка на hashcat; може да отнеме време.',
                                   'След това: История → Възобнови от checkpoint.']) == 1:
                            # Resume a paused engine so it can reach the next safe point.
                            os.write(control_fd, b'r')
                            # Separate keys: hashcat uses buffered getchar behind select().
                            # Also covers a pause whose JSON status has not arrived yet.
                            checkpoint_not_before = time.monotonic() + 1
                            checkpoint_requested = True
                            metadata['control_message'] = 'Запазване и спиране… изчаква следващия checkpoint.'
                status = reader.update()
                metadata.update(status='finished' if proc.returncode in (0, 1) else 'stopped',
                                returncode=proc.returncode, message=explain(proc.returncode))
        except BaseException as exc:
            metadata.update(status='interrupted' if isinstance(exc, KeyboardInterrupt) else 'error', error=str(exc))
            if not isinstance(exc, (KeyboardInterrupt, SystemExit)):
                logging.getLogger('wifi').exception('Hashcat task %s failed', metadata['id'])
            try:
                with log.open('a') as output:
                    output.write('\nPython error: ' + repr(exc) + '\n')
            except OSError:
                pass
            raise
        finally:
            original_error = sys.exc_info()[0] is not None
            screen.poll_hook = previous_hook
            try:
                if proc is not None:
                    stop_process(proc)
                    metadata['returncode'] = proc.returncode
                metadata['finished'] = time.time()
                result_reader.update()
                metadata['recovered'] = result_reader.count
                save_progress(job, metadata, status, session)
            except (OSError, ValueError):
                logging.getLogger('wifi').exception('Финалният запис не успя; оригиналните файлове остават.')
                if not original_error:
                    raise
            finally:
                for fd in (slave_fd, control_fd):
                    if fd is not None:
                        os.close(fd)
                os.umask(old_umask)
    results = result_snapshot(result)
    select(screen, 'Hashcat • резултат', ['Назад'], write,
           [metadata.get('message', metadata['status']), f'Намерени записи: {metadata["recovered"]}',
            'Паролите са в История → Покажи намерени пароли.' if results else 'Няма намерена парола.',
            'Резултати: ' + str(result), 'Лог: ' + str(log),
            'Възобновяване: ' + ('наличен checkpoint' if (job / 'hashcat.restore').exists() else 'няма checkpoint'),
            'История: ' + str(job / 'run.json')])


def browse(screen, session, write):
    base = session.destination.parent
    while True:
        choice = select(screen, 'Hashcat', ['Нова проверка', 'Предишни задачи / резултати / възобновяване', 'Изтегли речници', 'Мрежи и история', 'Назад'], write)
        if choice is None or choice == 4:
            return
        try:
            if choice == 3:
                browse_networks(screen, session, write)
                continue
            if choice == 2:
                browse_wordlists(screen, session, write)
                continue
            if choice == 1:
                runs = sorted((base / 'data' / 'hashcat').glob('*/run.json'), reverse=True)
                idx = select(screen, 'История', [history_label(p) for p in runs] or ['Няма задачи'], write)
                if runs and idx is not None:
                    record = json.loads(runs[idx].read_text())
                    job = runs[idx].parent
                    action = select(screen, 'Задача ' + record['id'],
                                    ['Назад', 'Възобнови от checkpoint', 'Покажи намерени пароли'], write,
                                    [record.get('message', record['status']), f'Намерени: {record.get("recovered", 0)}',
                                     'Лог: ' + record['log'], 'Резултати: ' + record['results'],
                                     ('Маска: ' if record.get('attack_mode') == 3 else 'Речник: ') + record['dictionary'],
                                     'Checkpoint: ' + ('наличен' if (job / 'hashcat.restore').exists() else 'няма'),
                                     'Статусът running след авария може да е остарял; проверяваме заключването.'])
                    if action == 1:
                        execute(screen, session, write, Path(record['dataset']), Path(record['dictionary']), resume_job=job)
                    elif action == 2:
                        result_path = Path(record['results'])
                        recovered = result_snapshot(result_path) if result_path.exists() else []
                        select(screen, 'Намерени пароли • потвърдени срещу WPA записа',
                               [display_plain(line) for line in recovered] or ['Няма намерени пароли'], write,
                               ['Пълен файл: ' + str(result_path),
                                'Показани са последните записи; файлът запазва всички.'])
                continue
            folder = choose_dataset(screen, session, write)
            if folder is None:
                continue
            load_dataset(folder)
            available = dictionaries(base)
            masks = builtin_masks(base, session) + installed_masks()
            labels = [dictionary_label(p) for p in available]
            labels += [label for path, label in masks]
            idx = select(screen, 'Избери речник или автоматични комбинации',
                         labels + ['Въведи път до речник'], write,
                         ['Речник: проверява думите от файла. Маска: генерира комбинации без речник.',
                          'Цифрови маски и инсталирани шаблони на hashcat.',
                          'Маските следват своя шаблон; някои могат да работят изключително дълго.'])
            if idx is None:
                continue
            attack_mode = 0
            if idx == len(labels):
                value = text_input(screen, write, 'Речник: една кандидат-парола на ред')
                if not value:
                    continue
                dictionary = no_symlinks(Path(value).expanduser())
            elif idx < len(available):
                dictionary = available[idx]
            else:
                dictionary = masks[idx - len(available)][0]
                attack_mode = 3
                if select(screen, 'Какво проверява избраната маска', ['Назад', 'Продължи'], write, mask_details(dictionary)) != 1:
                    continue
            prevent_sleep = False
            while True:
                preparation = select(screen, 'Подготовка на проверката', ['Назад', 'Старт', 'Без заспиване: ' + ('ДА' if prevent_sleep else 'НЕ')], write,
                      ['Режим 22000 • ' + ('маска (генерирани комбинации)' if attack_mode == 3 else 'речник') + ' • ниско натоварване (-w 1)',
                       'Съвпадение потвърждава WPA записа, не текущата парола на рутера.',
                       'Спира след всички намерени записи или изчерпване на кандидатите.',
                       ('Маските могат да отнемат години; виж напредъка; C запазва и спира.' if attack_mode == 3 else 'Проверява само кандидатите в избрания файл.'),
                       'Данни: ' + str(folder), 'Файл: ' + str(dictionary),
                       'Намерени пароли → data/hashcat/<задача>/recovered.txt']
                      + inventory(folder / 'wpa.22000')
                      + ['Предишни проверки (същата мрежа не доказва същата парола):']
                      + (previous(base, session, folder / 'wpa.22000', dictionary, attack_mode) or ['Няма предишни проверки за тези мрежи.']))
                if preparation == 2:
                    prevent_sleep = not prevent_sleep
                    continue
                if preparation == 1:
                    execute(screen, session, write, folder, dictionary, attack_mode=attack_mode, prevent_sleep=prevent_sleep)
                break

        except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
            logging.getLogger('wifi').exception('Hashcat workflow failed')
            error_log = base / 'log' / ('hashcat-error-' + dt.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6] + '.log')
            try:
                writable_directory(error_log.parent, session)
                error_log.write_text(traceback.format_exc(), encoding='utf-8')
                secure(error_log, session)
            except OSError:
                error_log = base / 'log' / 'wifi-console.log'
            select(screen, 'Hashcat не може да продължи', ['Назад'], write,
                   [str(exc), 'Провери свободното място, правата и формата на файловете.',
                    'При GPU грешка: провери драйвера с hashcat -I.', 'Подробности: ' + str(error_log)])


def installed_masks():
    """Discover package-provided masks; never pretend an absent preset exists."""
    roots = [Path('/usr/share/hashcat/masks'), Path('/usr/local/share/hashcat/masks')]
    executable = shutil.which('hashcat')
    if executable:
        roots.append(Path(executable).resolve().parent / 'masks')
    titles = {
        'hashcat-default': 'Автоматични комбинации — стандартна маска на Hashcat, 8–15 знака',
        '8char-1l-1u-1d-1s-compliant': 'Маска — 8 знака с малка/главна буква, цифра и символ',
        '8char-1l-1u-1d-1s-noncompliant': 'Маски — други комбинации от 8 знака',
    }
    found = {}
    for root in roots:
        for path in sorted(root.glob('*.hcmask')):
            if path.is_file() and path.stat().st_size:
                title = titles.get(path.stem, ('Букви/цифри/символи от RockYou — набор ' + path.stem.split('-')[1] if path.stem.startswith('rockyou-') else 'Шаблони — ' + path.stem.replace('-', ' ')))
                found.setdefault(path.name, (path, f'{title} ({path.name})'))
    return sorted(found.values(), key=lambda item: (item[0].name != 'hashcat-default.hcmask', item[0].name))


def dataset_checkpoint(base, folder):
    for path in (base / 'data' / 'hashcat').glob('*/run.json'):
        try:
            record = json.loads(path.read_text())
            if (record.get('source_id') == folder.name or Path(record['dataset']).resolve() == folder.resolve()) and (path.parent / 'hashcat.restore').is_file():
                return True
        except (OSError, ValueError, KeyError):
            continue
    return False


def history_label(path):
    try:
        record = json.loads(path.read_text())
        date = dt.datetime.fromtimestamp(record['started']).strftime('%d.%m.%Y %H:%M')
        state = {'finished': 'Завършена', 'stopped': 'Спряна', 'running': 'Стартирана',
                 'error': 'Грешка', 'interrupted': 'Прекъсната'}.get(record['status'], record['status'])
        checkpoint = '★ ' if (path.parent / 'hashcat.restore').is_file() else ''
        return f'{checkpoint}{date} • {state} • ' + Path(record.get('original_dictionary', record['dictionary'])).name + f' • намерени: {record.get("recovered", 0)}'
    except (OSError, ValueError, KeyError):
        return path.parent.name + ' • нечетима история'


def builtin_masks(base, session):
    folder = base / 'data' / 'masks'
    writable_directory(folder, session)
    presets = [('digits-8', [8], 'Само цифри — точно 8 цифри (100 милиона)'),
               ('digits-9-10', [9, 10], 'Само цифри — 9 до 10 цифри (11 милиарда)')]
    result = []
    for name, lengths, title in presets:
        path = folder / (name + '.hcmask')
        content = ''.join('?d' * length + '\n' for length in lengths)
        if not path.exists():
            with path.open('x') as stream:
                stream.write(content)
            secure(path, session)
        result.append((path, title))
    return result


def mask_details(path):
    patterns = mask_patterns(path)
    reason = ('Проверява цифрови пароли, включително започващи с 0. Подходяща при очаквана цифрова Wi-Fi парола.'
              if path.stem.startswith('digits-') else
              'Проверява структурирани комбинации. Подходяща, ако паролата следва тези шаблони; не обхваща всички Wi-Fi пароли.')
    if 'compliant' in path.stem:
        reason += ' Този набор разглежда позиции за малки/главни латински букви, цифри и символи в 8 знака.'
    elif path.stem.startswith('rockyou-'):
        reason += ' Шаблоните са извлечени от RockYou; това не доказва честота при Wi-Fi пароли.'
    elif path.name == 'hashcat-default.hcmask':
        reason += ' Началото е буква/цифра, средата — малки букви/цифри, а краят допуска символи и цифров суфикс.'
    return ['Файл: ' + path.name, reason,
            '?d = цифра; ?l = малка латинска; ?u = главна; ?s = символ; ?a = всички печатни ASCII.',
            '?1…?8 = наборите преди запетаите; останалите знаци са буквални.',
            ('Дължини 8–15 с постепенно удължаване.' if path.name == 'hashcat-default.hcmask' else 'Само шаблоните с 8–63 байта ще се проверяват; по-късите се пропускат.'),
            'Прогресът и оставащото време са за текущия шаблон. ←/→ прелиства описанието.',
            *[f'[{i + 1}] {pattern}' for i, pattern in enumerate(patterns)]]


def mask_patterns(path):
    with path.open() as stream:
        return [line.rstrip('\r\n') for line in stream if line.strip() and not line.startswith('#')]


def mask_length(pattern):
    mask = re.split(r'(?<!\\),', pattern)[-1].replace('\\,', ',')
    return len(re.findall(rb'\?.|[^?]', mask.encode('utf-8')))


def choose_dataset(screen, session, write, archived=False):
    base = session.destination.parent
    root = archive_folder(base, 'ready', session) if archived else base / 'data' / 'ready'
    while True:
        datasets = sorted(root.glob('*/manifest.json'))
        labels = []
        for path in datasets:
            data = json.loads(path.read_text())
            marker = '★ ' if dataset_checkpoint(base, path.parent) else ''
            seen = len(previous(base, session, path.parent / 'wpa.22000'))
            marker += f'[{seen} предишни проверки] ' if seen else ''
            labels.append(marker + f'Набор {path.parent.name} • {len(inventory(path.parent / "wpa.22000"))} мрежи • {data.get("converter_accepted_records", "?")} записа • [Извлечени]')
        choice = select(screen, 'Готови набори' + (' • архив' if archived else ''),
                        labels + ['Назад'] + ([] if archived else ['Архив']), write,
                        ['A: ' + ('възстанови избрания набор' if archived else 'архивирай избрания набор веднага; K отваря Архив'),
                         'Архивирането запазва задачите, резултатите и checkpoint-ите.'], hotkeys=ARCHIVE_KEYS)
        action, selected = choice if isinstance(choice, tuple) else ('open', choice)
        if action == 'open_archive':
            if not archived:
                chosen = choose_dataset(screen, session, write, archived=True)
                if chosen is not None:
                    return chosen
            continue
        if selected is None or selected == len(datasets):
            return None
        if not archived and selected == len(datasets) + 1:
            chosen = choose_dataset(screen, session, write, archived=True)
            if chosen is not None:
                return chosen
            continue
        folder = datasets[selected].parent
        if action == 'archive':
            move_dataset(base, folder, session, restore=archived)
        else:
            return folder


def tool_environment():
    info = {'platform': ' '.join(os.uname()), 'python': platform.python_version()}
    try:
        result = subprocess.run(['hashcat', '--version'], capture_output=True, text=True, timeout=5)
        info['hashcat'] = result.stdout.strip() if result.returncode == 0 else 'неизвестна версия'
    except (OSError, TypeError, subprocess.SubprocessError):
        info['hashcat'] = 'неизвестна версия'
    driver = Path('/proc/driver/nvidia/version')
    if driver.is_file():
        info['nvidia_driver'] = driver.read_text().strip()
    return info
