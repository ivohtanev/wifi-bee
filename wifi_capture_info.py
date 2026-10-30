"""On-demand packet inventory, never run while listing capture sessions."""
from collections import Counter
import datetime as dt
import json
import re
import subprocess
import tempfile

from wifi_live import readable
from wifi_storage import no_symlinks


def parse_frames(lines):
    first = last = None
    devices = {}
    frequencies = Counter()
    packets = 0
    for line in lines:
        fields = line.rstrip('\n').split('\t')
        if len(fields) != 6:
            continue
        timestamp, transmitter, receiver, frequency, ssid, name = fields
        packets += 1
        try:
            stamp = float(timestamp)
            first = stamp if first is None else min(first, stamp)
            last = stamp if last is None else max(last, stamp)
        except ValueError:
            pass
        if frequency:
            frequencies[frequency] += 1
        for address in (transmitter, receiver):
            if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', address) or int(address[:2], 16) & 1:
                continue
            item = devices.setdefault(address.lower(), Counter())
            item['packets'] += 1
            # Device names / advertised SSIDs belong only to the transmitter.
            if address == transmitter:
                if name:
                    item['име: ' + readable(name)] += 1
                if ssid:
                    try:
                        ssid = bytes.fromhex(ssid.replace(':', '')).decode('utf-8', errors='backslashreplace')
                    except ValueError:
                        pass
                    item['наблюдаван SSID: ' + readable(ssid)] += 1
    return first, last, packets, frequencies, devices


def summary(paths, processes):
    with tempfile.TemporaryFile(mode='w+') as output:
        for path in paths:
            result = processes.run(['tshark', '-r', str(no_symlinks(path)), '-T', 'fields', '-E', 'occurrence=f',
                '-e', 'frame.time_epoch', '-e', 'wlan.ta', '-e', 'wlan.ra',
                '-e', 'radiotap.channel.freq', '-e', 'wlan.ssid', '-e', 'wps.device_name'],
                stdout=output, stderr=subprocess.PIPE, text=True, timeout=120)
            if result.returncode:
                raise RuntimeError(result.stderr.strip() or 'Неуспешно прочитане на пакети.')
        output.seek(0)
        first, last, packets, frequencies, devices = parse_frames(output)
    channels = sorted({m[1] for p in paths if (m := re.search(r'_ch-(\d+)_', p.name))}, key=int)
    lines = ['Канал от името на записа: ' + (', '.join(channels) or 'не е записан'),
             f'Файлове: {len(paths)} • пакети: {packets} • наблюдавани MAC адреси: {len(devices)}']
    if first is not None:
        lines += ['Първи пакет: ' + dt.datetime.fromtimestamp(first).astimezone().isoformat(timespec='seconds'),
                  'Последен пакет: ' + dt.datetime.fromtimestamp(last).astimezone().isoformat(timespec='seconds'),
                  f'Интервал между първи и последен пакет: {last - first:.1f} s (включва паузите между файловете).']
    else:
        lines.append('Няма времеви данни от пакети.')
    lines.append('Наблюдавани честоти: ' + (', '.join(f'{f} MHz ({n} пакета)' for f, n in sorted(frequencies.items())) or 'няма radiotap данни'))
    lines.append('Пакетният интервал не включва тишината преди първия и след последния пакет.')
    lines.append('MAC адресите не доказват физическа самоличност; SSID не е име на устройство.')
    for address, counts in sorted(devices.items()):
        labels = [k for k in counts if k != 'packets']
        lines.append(address + f' • {counts["packets"]} пакета • ' + ('; '.join(sorted(labels)) or 'неизвестно име'))
    return lines


def journal_details(base, paths):
    numbers = {p.name.split('_')[0] for p in paths}
    lines = []
    for number in sorted(numbers):
        for path in (base / 'captures' / '.sessions').glob(number + '_*.json'):
            try:
                meta = json.loads(path.read_text())
                lines.append('Сесия ' + meta['prefix'] + ' • канал: ' + str(meta.get('channel', 'не е записан')))
                if 'monitor_seconds' in meta:
                    lines.append(f'Време на monitor процеса за цялата сесия: {meta["monitor_seconds"]:.1f} s')
            except (OSError, ValueError, KeyError, TypeError):
                continue
    return lines
