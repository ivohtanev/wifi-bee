"""Explicit dictionary runs over verified, exported WPA 22000 records."""
import curses
import datetime as dt
import fcntl
import json
import logging
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
import traceback
import uuid

from wifi_analysis import fingerprint, select


from wifi_storage import (secure, atomic_json, writable_directory, durable_touch,
                          bar, duration, size)
from wifi_wordlists import dictionaries, browse as browse_wordlists


def load_dataset(folder):
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
        1: 'Речникът е изчерпан. Възможно е да има частичен успех; виж recovered.txt. Това не доказва, че паролата е невъзстановима.',
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
        screen.refresh()
        key = screen.getch()
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
            line = raw.decode('utf-8', errors='replace').strip()
            try:
                record = json.loads(line)
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


def result_snapshot(path):
    # Results are typically tiny; cap display reads, preserve the full original file.
    with path.open('rb') as stream:
        stream.seek(max(0, path.stat().st_size - 65536))
        lines = stream.read().splitlines()
    return [line.decode('utf-8', errors='replace') for line in lines if b':' in line]


def save_progress(job, metadata, status, session):
    metadata['snapshot_at'] = time.time()
    metadata['progress'] = status
    metadata['checkpoint_available'] = (job / 'hashcat.restore').is_file()
    for name in ('recovered.txt', 'hashcat.potfile', 'hashcat.restore'):
        path = job / name
        if path.exists():
            secure(path, session)
            try:
                with path.open('rb') as stream:
                    os.fsync(stream.fileno())
            except FileNotFoundError:
                # hashcat removes its checkpoint on successful completion.
                pass
    atomic_json(job / 'run.json', metadata, session)


def resume_command(metadata, job):
    dictionary = Path(metadata['dictionary'])
    source = job / 'input.22000'
    if not metadata.get('dictionary_sha256') or fingerprint(dictionary) != metadata['dictionary_sha256']:
        raise ValueError('Речникът липсва или е променен. Върни оригиналния файл преди възобновяване.')
    if fingerprint(source) != metadata['input_sha256']:
        raise ValueError('Входните WPA записи са променени. Не може безопасно да се възобнови.')
    restore = job / 'hashcat.restore'
    if not restore.is_file():
        raise ValueError('Няма checkpoint от hashcat. Задачата е завършила или е спряна преди първия checkpoint; започни нова проверка.')
    help_text = subprocess.run(['hashcat', '--help'], capture_output=True, text=True, timeout=15, check=True).stdout
    if '--restore-position' in help_text:
        # New hashcat releases require the original arguments to be supplied explicitly.
        return [*metadata['command'], '--restore-position']
    return ['hashcat', '--session', 'wifi-' + metadata['id'], '--restore-file-path', str(restore), '--restore']


def draw_run(screen, write, metadata, status, reader, results, job):
    screen.erase()
    write(screen, 0, 'Hashcat • речникова проверка', curses.A_BOLD)
    progress = status.get('progress', [0, 0])
    done, total = progress
    rejected = status.get('rejected', 0)
    devices = status.get('devices', [])
    speed = sum(d.get('speed', 0) for d in devices)
    stop = status.get('estimated_stop', 0)
    eta = max(0, stop - time.time()) if stop > 1 else None
    recovered = status.get('recovered_hashes', [metadata.get('recovered', 0), metadata['records']])
    lines = ['Речник: ' + Path(metadata['dictionary']).name,
             bar(done, total),
             f'Обработени: {done:,} / {total:,} • отхвърлени: {rejected:,}',
             f'Проверки (без отхвърлените): {max(0, done - rejected):,} • {speed:,.0f} H/s',
             'Остава: ' + duration(eta) + ' • тази сесия: ' + duration(time.time() - metadata['resumed_at']),
             f'Потвърдени записи: {recovered[0]} / {recovered[1]} • checkpoint: {status.get("restore_point", "изчакване")}',
             'Резултати: ' + str(job / 'recovered.txt'),
             'S/Q/Esc: стоп • статистика на 10 s • resume от checkpoint на hashcat']
    for row, line in enumerate(lines, 2):
        write(screen, row, line)
    row = 11
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
        write(screen, row + 1, display_plain(results[-1]), curses.A_BOLD)
        row += 2
    for message in reader.messages[-2:]:
        write(screen, row, ''.join(c if c.isprintable() else ' ' for c in message))
        row += 1
    screen.refresh()


def execute(screen, session, write, folder, dictionary, resume_job=None):
    base = session.destination.parent.resolve()
    if not shutil.which('hashcat'):
        raise ValueError('hashcat не е инсталиран или не е в PATH. Инсталирай hashcat и GPU/OpenCL драйвера.')
    screen.erase()
    write(screen, 0, 'Подготовка: проверка на файловете, SHA-256 и запис на диска…')
    screen.refresh()
    jobs = base / 'data' / 'hashcat'
    log_dir = base / 'log'
    writable_directory(jobs, session)
    writable_directory(log_dir, session)
    if resume_job is None:
        manifest, hashes, count = load_dataset(folder)
        dictionary = dictionary.resolve()
        if not dictionary.is_file() or dictionary.stat().st_size == 0:
            raise ValueError('Речникът липсва или е празен. Нужен е текстов файл с по една кандидат-парола на ред.')
        with dictionary.open('rb') as stream:
            sample = stream.read(8192)
        if b'\x00' in sample or sample.startswith((b'\x1f\x8b', b'PK\x03\x04')):
            raise ValueError('Речникът изглежда двоичен/архивиран. Разархивирай го до текстов файл.')
        run_id = dt.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
        job = jobs / run_id
        writable_directory(job, session)
        source = job / 'input.22000'
        shutil.copyfile(hashes, source)
        if fingerprint(source) != manifest['outputs']['wpa.22000']:
            raise ValueError('Наборът е променен по време на подготовката.')
        shutil.copyfile(folder / 'manifest.json', job / 'source-manifest.json')
        command = ['hashcat', '-m', '22000', '-a', '0', '-w', '1', '--status', '--status-json',
                   '--status-timer', '1', '--session', 'wifi-' + run_id,
                   '--restore-file-path', str(job / 'hashcat.restore'),
                   '--potfile-path', str(job / 'hashcat.potfile'),
                   '--outfile', str(job / 'recovered.txt'), '--outfile-format', '1,2',
                   str(source), str(dictionary)]
        metadata = {'id': run_id, 'dataset': str(folder), 'source_id': manifest['id'],
                    'dictionary': str(dictionary), 'dictionary_sha256': fingerprint(dictionary),
                    'input_sha256': fingerprint(source), 'command': command, 'records': count,
                    'started': time.time(), 'status': 'starting', 'results': str(job / 'recovered.txt')}
    else:
        job = resume_job.resolve()
        metadata = json.loads((job / 'run.json').read_text())
        command = None
        writable_directory(job, session)
    # Lock is inherited by hashcat so an orphaned process also blocks a second resume.
    with (job / '.run.lock').open('a') as lock:
        secure(job / '.run.lock', session)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError('Тази задача вече работи. Спри активния процес преди възобновяване.') from exc
        if resume_job is not None:
            command = resume_command(metadata, job)
        suffix = ('-resume-' + uuid.uuid4().hex[:6]) if resume_job else ''
        log = log_dir / ('hashcat-' + metadata['id'] + suffix + '.log')
        metadata.update(log=str(log), resumed_at=time.time(), status='starting')
        metadata.pop('error', None)
        metadata.pop('finished', None)
        result = job / 'recovered.txt'
        # Fail before launching if results, potfile, metadata or logs cannot be written.
        for path in (result, job / 'hashcat.potfile', log):
            durable_touch(path, session)
        for path in job.iterdir():
            secure(path, session)
        save_progress(job, metadata, metadata.get('progress', {}), session)
        proc = None
        reader = StatusReader(log)
        status = {}
        results = result_snapshot(result)
        last_save = time.monotonic()
        last_result_size = result.stat().st_size
        old_umask = os.umask(0o077)
        try:
            with log.open('a') as output:
                output.write('Command: ' + json.dumps(command, ensure_ascii=False) + '\n')
                output.flush()
                os.fsync(output.fileno())
                proc = subprocess.Popen(command, cwd=job, stdin=subprocess.DEVNULL,
                                        stdout=output, stderr=subprocess.STDOUT, start_new_session=True,
                                        pass_fds=(lock.fileno(),), env={**os.environ, 'LC_ALL': 'C'})
                metadata.update(status='running', pid=proc.pid)
                save_progress(job, metadata, status, session)
                screen.timeout(200)
                while proc.poll() is None:
                    status = reader.update()
                    result_size = result.stat().st_size
                    if result_size != last_result_size:
                        results = result_snapshot(result)
                        metadata['recovered'] = len(results)
                        # New results are flushed immediately, independent of the 10-second timer.
                        save_progress(job, metadata, status, session)
                        last_result_size = result_size
                        last_save = time.monotonic()
                    if time.monotonic() - last_save >= 10:
                        save_progress(job, metadata, status, session)
                        last_save = time.monotonic()
                    draw_run(screen, write, metadata, status, reader, results, job)
                    if screen.getch() in (ord('s'), ord('S'), ord('q'), ord('Q'), 27):
                        if select(screen, 'Спиране на hashcat?', ['Не — продължи', 'Да — спри'], write,
                                  ['Резултатите остават. Възобновяване от последния checkpoint.',
                                   'Някои комбинации след checkpoint може да се проверят повторно.']) == 1:
                            stop_process(proc)
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
            try:
                if proc is not None:
                    stop_process(proc)
                    metadata['returncode'] = proc.returncode
                metadata['finished'] = time.time()
                with result.open('rb') as stream:
                    metadata['recovered'] = sum(1 for line in stream if b':' in line)
                save_progress(job, metadata, status, session)
            finally:
                os.umask(old_umask)
    results = result_snapshot(result)
    select(screen, 'Hashcat • резултат', ['Назад'], write,
           [metadata.get('message', metadata['status']), f'Намерени записи: {metadata["recovered"]}',
            ('Парола: ' + display_plain(results[-1])) if results else 'Няма намерена парола.',
            'Резултати: ' + str(result), 'Лог: ' + str(log),
            'Възобновяване: ' + ('наличен checkpoint' if (job / 'hashcat.restore').exists() else 'няма checkpoint'),
            'История: ' + str(job / 'run.json')])


def browse(screen, session, write):
    base = session.destination.parent
    while True:
        choice = select(screen, 'Hashcat', ['Нова речникова проверка', 'Предишни задачи / резултати / възобновяване', 'Изтегли речници', 'Назад'], write)
        if choice is None or choice == 3:
            return
        try:
            if choice == 2:
                browse_wordlists(screen, session, write)
                continue
            if choice == 1:
                runs = sorted((base / 'data' / 'hashcat').glob('*/run.json'), reverse=True)
                idx = select(screen, 'История', [p.parent.name for p in runs] or ['Няма задачи'], write)
                if runs and idx is not None:
                    record = json.loads(runs[idx].read_text())
                    job = runs[idx].parent
                    action = select(screen, 'Задача ' + record['id'],
                                    ['Назад', 'Възобнови от checkpoint', 'Покажи намерени пароли'], write,
                                    [record.get('message', record['status']), f'Намерени: {record.get("recovered", 0)}',
                                     'Лог: ' + record['log'], 'Резултати: ' + record['results'],
                                     'Речник: ' + record['dictionary'],
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
            datasets = sorted((base / 'data' / 'ready').glob('*/manifest.json'))
            labels = []
            for path in datasets:
                data = json.loads(path.read_text())
                labels.append(f'{path.parent.name} • {data.get("converter_accepted_records", "?")} записа • ' +
                              ', '.join(Path(x['path']).name.split('_')[0] for x in data.get('sources', []))[:60])
            idx = select(screen, 'Избери готов набор', labels or ['Няма готови данни — използвай Анализ → извлечи готови'], write)
            if not datasets or idx is None:
                continue
            folder = datasets[idx].parent
            load_dataset(folder)
            available = dictionaries(base)
            idx = select(screen, 'Избери речник', [p.name + ' • ' + size(p.stat().st_size) for p in available] + ['Въведи път до речник'], write)
            if idx is None:
                continue
            if idx == len(available):
                value = text_input(screen, write, 'Речник: една кандидат-парола на ред')
                if not value:
                    continue
                dictionary = Path(value).expanduser().resolve()
            else:
                dictionary = available[idx]
            if select(screen, 'Подготовка на проверката', ['Назад', 'Старт'], write,
                      ['Режим 22000 • речник • ниско натоварване (-w 1)',
                       'Съвпадение потвърждава WPA записа, не текущата парола на рутера.',
                       'Hashcat спира след всички намерени записи или изчерпан речник.', 'Данни: ' + str(folder),
                       'Речник: ' + str(dictionary), 'Намерени пароли → data/hashcat/<задача>/recovered.txt']) == 1:
                execute(screen, session, write, folder, dictionary)
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
