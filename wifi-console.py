#!/usr/bin/env python3
"""Interactive Wi-Fi recorder; run sudo ./wifi-console.py --owner USER."""
import argparse
import json
import curses
import datetime as dt
import fcntl
import locale
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import pwd
import queue
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time

from wifi_ui import guarded_ui, footer
from wifi_hashcat import browse as browse_hashcat
from wifi_wordlists import browse as browse_wordlists
from wifi_live import LiveSummary, device_label, signal_label, auth_label
from wifi_analysis import browse as browse_analysis, select
from wifi_storage import (atomic_json, check_space, durable_move, no_symlinks, secure,
                          writable_directory, sync_directory, file_digest)
from wifi_privilege import Radio, drop_privileges

BASE = Path(__file__).resolve().parent
LIMIT = 50000 * 1024
ROTATE_SECONDS = 2000
# Omit payload-free acknowledgements, medium-access handshakes and null data.
# Keep beacons/probes (network capabilities), all other management, data,
# EAPOL, and retries: a retransmission may be the only copy we received.
# These excluded frames are still useful for radio diagnostics; use full mode.
CAPTURE_FILTER = ('not (type ctl subtype ack or type ctl subtype cts or '
                  'type ctl subtype rts or type ctl subtype 0x90 or '
                  'type ctl subtype 0x80 or type data subtype null or '
                  'type data subtype qos)')


def stamp():
    return dt.datetime.now().astimezone().strftime('%Y-%m-%d_%H-%M-%S')


def size(value):
    return f'{value / 1024 / 1024:.2f} MiB'


def next_record_number():
    with no_symlinks(BASE / '.wifi-record-number').open('a+') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        handle.seek(0)
        old = handle.read().strip()
        numbers = [int(m.group(1)) for root in (BASE / 'captures', BASE / 'archive' / 'captures') for p in root.glob('*.pcapng')
                   if (m := re.match(r'^(\d+)_', p.name))]
        number = max([int(old) if old else 0, *numbers]) + 1
        handle.seek(0)
        handle.truncate()
        handle.write(str(number))
        handle.flush()
        os.fsync(handle.fileno())
    return number


def iw_read(*args):
    result = subprocess.run(['iw', *args], capture_output=True, text=True, timeout=5)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or 'Грешка от iw')
    return result.stdout


def current_channel(interface):
    match = re.search(r'channel\s+(\d+)\s+\((\d+) MHz\)', iw_read('dev', interface, 'info'))
    return f'{match[1]} ({match[2]} MHz)' if match else 'неизвестен'


def channel_choices(interface):
    info = iw_read('dev', interface, 'info')
    phy = re.search(r'wiphy\s+(\d+)', info)
    if not phy:
        raise RuntimeError('Не е намерено радио за ' + interface)
    channels = {}
    for line in iw_read('phy', 'phy' + phy[1], 'info').splitlines():
        match = re.search(r'([0-9.]+) MHz \[(\d+)\]', line)
        if match and 'disabled' not in line:
            channels[int(match[2])] = int(float(match[1]))
    return channels


class Session:
    def __init__(self, interface='wifi_mon', owner=None):
        self.interface = interface
        account = pwd.getpwnam(owner) if owner else pwd.getpwuid(BASE.stat().st_uid)
        self.owner, self.uid, self.gid = account.pw_name, account.pw_uid, account.pw_gid
        self.filter_junk = False
        self.channel = 'текущият'
        self.proc = None
        self.stop_requested = False
        self.temp = None
        self.destination = BASE / 'captures'
        self.prefix = None
        self.saved = False
        self.started = None
        self.packet_count = None
        self.error = ''
        self.rows = []
        self.log = []
        self.events = queue.Queue()
        self.reader = None
        self.live = None
        self.radio = None
        self.disk_checked = 0
        self.capture_state = {}
        self.byte_rate = 0
        self.byte_sample = (time.monotonic(), 0)
        self.dropped = None

    @property
    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def start(self):
        if self.running:
            return
        if self.temp and not self.saved:
            self.finish()
            if not self.saved:
                raise RuntimeError('Неприбран запис: ' + str(self.temp))
        check_space(self.destination)
        check_space(Path('/var/tmp'))
        channel_info = current_channel(self.interface)
        channel = re.match(r'(\d+)', channel_info)
        if not channel:
            raise RuntimeError('Не може да се установи текущият канал. Избери канал преди Старт.')
        self.channel = channel_info
        self.prefix = f'{next_record_number():06d}_ch-{channel[1]}_{stamp()}'
        writable_directory(self.destination, self)
        self.temp = Path(tempfile.mkdtemp(prefix='.recording-' + self.prefix + '-', dir='/var/tmp'))
        # dumpcap drops DAC override privileges: its staging directory must
        # remain owned by the launching uid, with a traversable parent.
        # captures is private to the output owner and is entered only at finish.
        self.saved = False
        self.packet_count = None
        self.error = ''
        self.rows, self.log = [], []
        self.events = queue.Queue()
        self.started = time.monotonic()
        self.byte_sample = (self.started, 0)
        self.dropped = None
        self.stop_requested = False
        cmd = ['dumpcap', '-i', self.interface, '-s', '0',
               '-b', f'filesize:{LIMIT // 1024}',
               '-b', f'duration:{ROTATE_SECONDS}', '-w', str(self.temp / (self.prefix + '.pcapng'))]
        if self.filter_junk:
            cmd += ['-f', CAPTURE_FILTER]
        if not shutil.which('systemd-inhibit'):
            self.temp.rmdir()
            self.temp = None
            raise RuntimeError('Липсва systemd-inhibit; записът не е стартиран.')
        cmd = ['systemd-inhibit', '--what=idle:sleep', '--mode=block',
               '--who=Wi-Fi console', '--why=Active Wi-Fi packet recording',
               '--no-ask-password', '--', *cmd]
        try:
            if self.radio:
                self.proc = self.radio.start(self.temp / (self.prefix + '.pcapng'), self.filter_junk)
            else:
                self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                             start_new_session=True, env={**os.environ, 'LC_ALL': 'C'})
        except OSError:
            self.temp.rmdir()
            self.temp = None
            raise
        self.capture_state = {'prefix': self.prefix, 'destination': str(self.destination),
                              'pid': self.proc.pid, 'start_ticks': process_start(self.proc.pid),
                              'uid': self.uid, 'created': time.time(), 'files': [], 'status': 'recording'}
        atomic_json(self.temp / 'session.json', self.capture_state, self)
        pipe, events = self.proc.stderr, self.events

        def read_output():
            pending = bytearray()
            with pipe:
                while chunk := pipe.read(1):
                    if chunk in (b'\r', b'\n', b'\b'):
                        if pending:
                            events.put(pending.decode('utf-8', errors='replace'))
                            pending.clear()
                    else:
                        pending.extend(chunk)
                if pending:
                    events.put(pending.decode('utf-8', errors='replace'))
        self.reader = threading.Thread(target=read_output, daemon=True)
        self.reader.start()
        if self.live:
            self.live.close()
        self.live = LiveSummary(self.temp, self.prefix)

    def update(self):
        if self.running and time.monotonic() - self.disk_checked >= 2:
            self.disk_checked = time.monotonic()
            try:
                check_space(self.temp)
                check_space(self.destination)
            except OSError as exc:
                self.error = str(exc) + ' • записът се спира; файловете се пазят.'
                self.stop()
                return
        # Drain final stderr after the reader has seen EOF, including fast failures.
        if self.proc and self.proc.poll() is not None and self.reader:
            self.reader.join(timeout=1)
        while True:
            try:
                line = self.events.get_nowait().strip()
            except queue.Empty:
                break
            dropped = re.search(r'(?:Packets dropped|Dropped):\s*(\d+)', line, re.I)
            if dropped:
                self.dropped = int(dropped[1])
            match = re.search(r'Packets(?: captured)?:\s*(\d+)', line)
            if match or line.isdecimal():
                self.packet_count = int(match[1] if match else line)
            else:
                self.log = (self.log + [line])[-6:]
                logging.getLogger('wifi').info('capture: %s', line)
        if self.proc and self.proc.poll() is not None and not self.saved:
            if self.live:
                self.live.close()
            if self.proc.returncode and not self.stop_requested and not self.error:
                detail = ' | '.join(self.log[-4:])
                self.error = f'Записът приключи с код {self.proc.returncode}: {detail or "няма диагностичен текст"}'
                logging.getLogger('wifi').error(self.error)
            self.finish()
        self.rows = []
        folder = self.destination if self.saved else self.temp
        if folder and self.prefix:
            for path in sorted(folder.glob(self.prefix + '*.pcapng')):
                try:
                    self.rows.append((path.name, path.stat().st_size))
                except FileNotFoundError:
                    pass

        current = sum(n for _, n in self.rows)
        now, previous = self.byte_sample
        elapsed = time.monotonic() - now
        if elapsed >= 1:
            self.byte_rate = max(0, current - previous) / elapsed
            self.byte_sample = (time.monotonic(), current)

    def stop(self):
        self.stop_requested = True
        if self.live:
            self.live.close()
        if self.running and self.radio:
            self.proc.stop()
        if self.running:
            os.killpg(self.proc.pid, signal.SIGINT)
            try:
                self.proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGTERM)
                try:
                    self.proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                    self.proc.wait()
        if self.reader:
            self.reader.join(timeout=1)
        self.finish()
        self.update()

    def finish(self):
        if not self.temp or self.saved or self.running:
            return
        try:
            writable_directory(self.destination, self)
            self.capture_state['status'] = 'saving'
            known = {item['name'] for item in self.capture_state.get('pending', [])}
            pending = self.capture_state.setdefault('pending', [])
            for source in sorted(self.temp.glob('*.pcapng')):
                if source.name not in known:
                    pending.append({'name': source.name, 'bytes': source.stat().st_size, 'sha256': file_digest(source)})
            atomic_json(self.temp / 'session.json', self.capture_state, self)
            for item in list(pending):
                name = item['name']
                if Path(name).name != name or not name.endswith('.pcapng'):
                    raise ValueError('Невалиден запис в recovery журнала.')
                source, target = self.temp / name, self.destination / name
                if source.exists():
                    result = durable_move(source, target, self)
                elif target.is_file() and file_digest(no_symlinks(target)) == item['sha256']:
                    result = item
                else:
                    raise OSError('Липсва неприбраният запис: ' + name)
                self.capture_state.setdefault('files', []).append(result)
                pending.remove(item)
                atomic_json(self.temp / 'session.json', self.capture_state, self)
            self.capture_state['status'] = 'saved'
            journal_dir = self.destination / '.sessions'
            writable_directory(journal_dir, self)
            atomic_json(journal_dir / (self.prefix + '.json'), self.capture_state, self)
            (self.temp / 'session.json').unlink()
            self.temp.rmdir()
            sync_directory(self.temp.parent)
            self.saved = True
            if self.error.startswith('Неуспешно прибиране:'):
                self.error = ''
        except (OSError, ValueError) as exc:
            logging.getLogger('wifi').exception('Неуспешно прибиране на запис')
            self.error = f'Неуспешно прибиране: {exc}. Неприбрани: {self.temp}; вече прибрани: {self.destination}. Опитай възстановяване.'


def process_start(pid):
    try:
        return Path(f'/proc/{int(pid)}/stat').read_text().rsplit(')', 1)[1].split()[19]
    except (OSError, ValueError, IndexError):
        return None


def abandoned_sessions(session):
    found = []
    for path in Path('/var/tmp').glob('.recording-*/session.json'):
        try:
            no_symlinks(path)
            record = json.loads(path.read_text())
            if record['uid'] != session.uid or Path(record['destination']) != session.destination:
                continue
            current = process_start(record['pid'])
            if current is not None and (not record.get('start_ticks') or current == record['start_ticks']):
                continue
            if re.fullmatch(r'[A-Za-z0-9_.-]+', record['prefix']):
                found.append((path.parent, record))
        except (OSError, ValueError, KeyError):
            continue
    return found


def recover_captures(screen, session):
    for folder, record in abandoned_sessions(session):
        choice = select(screen, 'Неприбрана capture сесия', ['Остави за по-късно', 'Възстанови записите'], write,
                        [str(folder), 'Двигателят е спрян. Съществуващи различни файлове не се презаписват.'])
        if choice == 1:
            session.temp, session.prefix, session.capture_state = folder, record['prefix'], record
            session.saved = False
            session.finish()
            if session.error:
                select(screen, 'Възстановяване', ['Назад'], write, [session.error])


def write(screen, row, text, attr=0):
    height, width = screen.getmaxyx()
    if 0 <= row < height - 1 and width > 2:
        try:
            screen.addnstr(row, 1, text, width - 2, attr)
        except curses.error:
            pass


def choose_channel(screen, session, normal, highlight):
    if session.running:
        raise RuntimeError('Спри записа преди смяна на канал.')
    channels = channel_choices(session.interface)
    common = [ch for ch in (1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161) if ch in channels]
    options = ['Остави текущия: ' + current_channel(session.interface)]
    options += [f'Канал {ch} • {channels[ch]} MHz' for ch in common]
    options += ['Ръчно въвеждане на канал', 'Назад']
    selected = 0
    while True:
        screen.erase()
        write(screen, 0, 'Канал • ↑/↓ избор • Enter • Q отказ', curses.A_BOLD)
        write(screen, 2, 'Един фиксиран канал. Без прескачане.')
        height, width = screen.getmaxyx()
        count = max(1, height - 6)
        first = max(0, selected - count + 1)
        for index in range(first, min(len(options), first + count)):
            label = ('▶ ' if index == selected else '  ') + f'[{index + 1}] ' + options[index]
            write(screen, 4 + index - first, label.ljust(max(0, width - 2)), highlight if index == selected else normal)
        footer(screen, '↑/↓ избор • Enter избира канал • Q/Esc назад')
        screen.refresh()
        key = screen.getch()
        if key == curses.KEY_UP:
            selected = (selected - 1) % len(options)
        elif key == curses.KEY_DOWN:
            selected = (selected + 1) % len(options)
        elif key in (27, ord('q'), ord('Q')):
            return
        elif key in (10, 13, curses.KEY_ENTER):
            if selected in (0, len(options) - 1):
                return
            if selected == len(options) - 2:
                screen.erase()
                write(screen, 1, 'Номер на канал (празно = отказ):')
                write(screen, 3, 'Поддържани: ' + ', '.join(map(str, sorted(channels))))
                footer(screen, 'Цифри: канал • Enter потвърждава • Esc отказ')
                screen.timeout(-1)
                curses.echo()
                curses.curs_set(1)
                try:
                    value = screen.getstr(5, 1, 8).decode().strip()
                finally:
                    curses.noecho()
                    curses.curs_set(0)
                    screen.timeout(200)
                if not value:
                    return
                if not value.isdecimal() or int(value) not in channels:
                    raise RuntimeError('Неподдържан или забранен канал: ' + value)
                channel = int(value)
            else:
                channel = common[selected - 1]
            if session.radio:
                session.radio.request('channel', frequency=channels[channel])
                session.channel = current_channel(session.interface)
                return
            result = subprocess.run(['iw', 'dev', session.interface, 'set', 'freq', str(channels[channel])],
                                    capture_output=True, text=True, timeout=5)
            if result.returncode:
                raise RuntimeError('Каналът не е сменен: ' + result.stderr.strip())
            session.channel = current_channel(session.interface)
            return


def ui(screen, session):
    curses.curs_set(0)
    screen.keypad(True)
    screen.timeout(200)
    normal, highlight = 0, curses.A_REVERSE | curses.A_BOLD
    if curses.has_colors():
        curses.start_color()
        gray = 236 if curses.COLORS >= 256 else (8 if curses.COLORS >= 16 else curses.COLOR_BLUE)
        if 16 <= curses.COLORS < 256 and curses.can_change_color():
            curses.init_color(8, 180, 180, 180)
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_WHITE, gray)
        normal, highlight = curses.color_pair(1), curses.color_pair(2) | curses.A_BOLD
        screen.bkgd(' ', normal)
    recover_captures(screen, session)
    page, selected, message = 'menu', 0, ''
    device_offset = 0
    green = curses.A_BOLD
    device_bg = highlight
    device_ready_bg = highlight
    if curses.has_colors():
        curses.init_pair(3, curses.COLOR_GREEN, curses.COLOR_BLACK)
        green |= curses.color_pair(3)
        curses.init_pair(4, curses.COLOR_GREEN, gray)
        device_bg = curses.color_pair(2)
        device_ready_bg = curses.color_pair(4) | curses.A_BOLD
    while True:
        session.update()
        screen.erase()
        write(screen, 0, 'Wi-Fi конзола • ↑/↓ избор • Enter • Q назад/изход', curses.A_BOLD)
        if page == 'menu':
            options = ['Всички пакети (dumpcap)', 'Всички без служебен шум', 'Анализ на записи', 'Hashcat', 'Речници — изтегляне', 'Изход']
            write(screen, 2, 'wifi_mon • двата режима са без презаписване')
            start_row = 4
        else:
            options = ['Старт', 'Стоп', 'Канал: ' + session.channel, 'Назад']
            write(screen, 2, ('БЕЗ СЛУЖЕБЕН ШУМ' if session.filter_junk else 'ВСИЧКИ ПАКЕТИ') + ' • ' +
                  ('ЗАПИСВА • без автоматично заспиване' if session.running else 'СПРЯН'), curses.A_BOLD)
            packets = str(session.packet_count) if session.packet_count is not None else 'изчакване на брояча'
            elapsed = f' • време: {int(time.monotonic() - session.started)}s' if session.running else ''
            write(screen, 3, f'Общо записани пакети: {packets}' + elapsed)
            write(screen, 4, f'Нов файл при {size(LIMIT)} или {ROTATE_SECONDS} s / без презаписване • собственик: {session.owner}')
            folder = session.destination if session.saved else session.temp
            write(screen, 5, 'Папка: ' + str(folder or 'няма започната сесия'))
            write(screen, 6, 'След Стоп → ' + str(session.destination))
            start_row = 8
        for index, label in enumerate(options):
            label = ('▶ ' if selected == index else '  ') + f'[{index + 1}] ' + label
            write(screen, start_row + index, label.ljust(max(0, screen.getmaxyx()[1] - 2)),
                  highlight if selected == index else normal)
        if page == 'capture':
            height = screen.getmaxyx()[0]
            write(screen, 13, f'Файлове: {len(session.rows)} • {size(sum(n for _, n in session.rows))} • {size(session.byte_rate)}/s • загубени: ' + (str(session.dropped) if session.dropped is not None else 'н/д'))
            free = shutil.disk_usage(session.temp if session.temp and session.temp.exists() else BASE).free
            write(screen, 14, 'Свободно на диска: ' + size(free))
            if session.live:
                devices, ready, status = session.live.snapshot
                ordered = sorted(devices.items(), key=lambda item: (-item[1]['EAPOL'], -item[1]['AUTH'], item[0]))
                write(screen, 15, f'Устройства: {len(devices)} • приети AP/клиент двойки: {len(ready)}')
                visible = max(0, (height - 20) // 2)
                device_offset = min(device_offset, max(0, len(ordered) - max(1, visible)))
                for row, (mac, counts) in enumerate(ordered[device_offset:device_offset + visible]):
                    accepted = any(mac.replace(':', '').lower() in pair for pair in ready)
                    auth = auth_label(counts)
                    attr = green if accepted else normal
                    label = f'[{device_offset + row + 1}] {mac} • {signal_label(counts)} • {device_label(counts)}'
                    write(screen, 16 + row * 2, label.ljust(max(0, screen.getmaxyx()[1] - 2)),
                          device_ready_bg if accepted else device_bg)
                    write(screen, 17 + row * 2, ('  └─ ГОТОВ (hcx) • ' if accepted else '  └─ ') +
                          f'{counts["packets"]} pkt • {auth}', attr)
                write(screen, height - 4, status)
        write(screen, screen.getmaxyx()[0] - 3, session.error or message)
        footer(screen, '↑/↓ избор • Enter избира • Q/Esc назад/изход' +
               (' • PgUp/PgDn устройства' if page == 'capture' else ''))
        screen.refresh()
        key = screen.getch()
        if key in (curses.KEY_NPAGE, curses.KEY_PPAGE) and page == 'capture':
            device_offset = max(0, device_offset + (1 if key == curses.KEY_NPAGE else -1) * max(1, (screen.getmaxyx()[0] - 20) // 2))
        elif key == curses.KEY_UP:
            selected = (selected - 1) % len(options)
        elif key == curses.KEY_DOWN:
            selected = (selected + 1) % len(options)
        elif key in (27, ord('q'), ord('Q')):
            if page == 'capture':
                session.stop()
                page, selected = 'menu', 0
            else:
                return
        elif key in (10, 13, curses.KEY_ENTER):
            try:
                if page == 'menu':
                    if selected == 5:
                        return
                    if selected == 4:
                        browse_wordlists(screen, session, write)
                        continue
                    if selected == 3:
                        browse_hashcat(screen, session, write)
                        continue
                    if selected == 2:
                        browse_analysis(screen, session, write)
                        continue
                    session.filter_junk = selected == 1
                    session.channel = current_channel(session.interface)
                    page, selected = 'capture', 0
                elif selected == 0:
                    session.start()
                    message = ''
                elif selected == 1:
                    session.stop()
                    message = 'Записът е спрян; файловете са прибрани.' if session.saved else ''
                elif selected == 2:
                    choose_channel(screen, session, normal, highlight)
                else:
                    session.stop()
                    page, selected = 'menu', 0
            except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
                logging.getLogger('wifi').exception('Грешка в конзолата')
                message = str(exc)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description='Интерактивен Wi-Fi запис с dumpcap')
    parser.add_argument('--owner', help='Собственик на записите; по подразбиране собственикът на работната папка')
    args = parser.parse_args()
    if any(not shutil.which(tool) for tool in ('dumpcap', 'iw', 'systemd-inhibit')):
        raise SystemExit('Нужни са dumpcap, iw и systemd-inhibit.')
    locale.setlocale(locale.LC_ALL, '')
    session = Session(owner=args.owner)
    if os.geteuid() == 0:
        if not Path('/usr/bin/setpriv').is_file():
            raise SystemExit('Нужен е setpriv от util-linux за ограничените capture права.')
        account = pwd.getpwuid(session.uid)
        if account.pw_uid == 0:
            raise SystemExit('Нужен е обикновен собственик: --owner USER')
        session.radio = Radio(account, session.interface)
        try:
            drop_privileges(account)
        except BaseException:
            session.radio.close()
            raise
    elif session.uid != os.getuid():
        raise SystemExit('--owner трябва да е текущият потребител.')
    log_dir = BASE / 'log'
    writable_directory(log_dir, session)
    log_path = no_symlinks(log_dir / 'wifi-console.log')
    handler = RotatingFileHandler(log_path, maxBytes=5 * 1024 * 1024, backupCount=5, encoding='utf-8')
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(threadName)s %(message)s'))
    logging.getLogger('wifi').setLevel(logging.INFO)
    logging.getLogger('wifi').addHandler(handler)
    log_path.chmod(0o600)
    os.chown(log_path, session.uid, session.gid)
    logging.getLogger('wifi').info('Конзолата стартира')
    try:
        curses.wrapper(guarded_ui, session, ui)
    except KeyboardInterrupt:
        pass
    except Exception:
        logging.getLogger('wifi').exception('Неочаквана грешка')
        raise
    finally:
        try:
            session.stop()
        finally:
            if session.radio:
                session.radio.close()
        if session.temp:
            print('Файлове: ' + str(session.destination if session.saved else session.temp))
        if session.error:
            print(session.error)


if __name__ == '__main__':
    main()
