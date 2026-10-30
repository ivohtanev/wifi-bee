import logging
"""Read-only background summaries of the files written by dumpcap."""
from collections import Counter
from pathlib import Path
import subprocess
import tempfile
import threading
import time


def readable(value):
    """Keep packet-supplied control characters out of terminal output."""
    return ''.join(c if c.isprintable() else ' ' for c in value).strip()[:80]


def device_label(counts):
    for kind, prefix in [('name', ''), ('ssid', 'SSID: ')]:
        candidates = [(count, key[1]) for key, count in counts.items()
                      if isinstance(key, tuple) and key[0] == kind and key[1]]
        if candidates:
            return prefix + max(candidates)[1]
    return 'неизвестно име'


def signal_label(counts):
    samples = counts['signal_samples']
    return f"{counts['signal_sum'] / samples:.1f} dBm" if samples else 'няма RSSI'


def auth_label(counts):
    keys = ('AUTH', 'AssocReq', 'AssocResp', 'ReassocReq', 'ReassocResp',
            'Disassoc', 'Deauth', 'EAPOL', 'M1', 'M2', 'M3', 'M4')
    return ' '.join(f'{key}:{counts[key]}' for key in keys if counts[key]) or 'без auth'


def summarize(path):
    devices = {}
    command = ['tshark', '-r', str(path), '-T', 'fields', '-E', 'occurrence=f',
               '-e', 'wlan.ta', '-e', 'wlan.fc.type_subtype', '-e', 'eapol.type',
               '-e', 'wlan_rsna_eapol.keydes.msgnr', '-e', 'radiotap.dbm_antsignal',
               '-e', 'wlan.ssid', '-e', 'wps.device_name']
    with tempfile.TemporaryFile(mode='w+') as errors:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors, text=True)
        timer = threading.Timer(90, proc.kill)
        timer.start()
        try:
            for line in proc.stdout:
                fields = line.rstrip('\n').split('\t')
                if len(fields) != 7 or not fields[0]:
                    continue
                mac, subtype, eapol, msg, signal, ssid, name = fields
                try:
                    if int(mac[:2], 16) & 1:
                        continue
                except ValueError:
                    continue
                counts = devices.setdefault(mac, Counter())
                counts['packets'] += 1
                # One antenna reading per frame (occurrence=f); retain sums so
                # aggregation across rotated files is weighted by sample count.
                try:
                    dbm = int(signal)
                    if -127 <= dbm <= 0:
                        counts['signal_sum'] += dbm
                        counts['signal_samples'] += 1
                except ValueError:
                    pass
                if name:
                    counts[('name', readable(name))] += 1
                # Probe requests name a sought network, not the transmitter.
                if ssid and subtype in ('0x0008', '0x0005'):
                    try:
                        decoded = bytes.fromhex(ssid.replace(':', '')).decode('utf-8', errors='replace')
                    except ValueError:
                        decoded = ssid
                    if decoded.strip('\x00'):
                        counts[('ssid', readable(decoded))] += 1
                label = {'0x000b': 'AUTH', '0x0000': 'AssocReq', '0x0001': 'AssocResp',
                         '0x0002': 'ReassocReq', '0x0003': 'ReassocResp',
                         '0x000a': 'Disassoc', '0x000c': 'Deauth'}.get(subtype)
                if label:
                    counts[label] += 1
                if eapol:
                    counts['EAPOL'] += 1
                if msg in ('1', '2', '3', '4'):
                    counts['M' + msg] += 1
            code = proc.wait()
            errors.seek(0)
            error = errors.read()
            # dumpcap may currently be writing the last block.
            if code and 'cut short' not in error and 'appears to have been cut short' not in error:
                raise RuntimeError(error.strip() or 'tshark timeout')
        finally:
            timer.cancel()
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            proc.stdout.close()
    return devices


class LiveSummary:
    def __init__(self, folder, prefix):
        self.folder, self.prefix = folder, prefix
        self.snapshot = ({}, set(), 'Изчакване на статистика…')
        self.closed = {}
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.work, daemon=True)
        self.thread.start()

    def work(self):
        ready = set()
        checked = 0
        while not self.stop_event.is_set():
            try:
                paths = sorted(self.folder.glob(self.prefix + '*.pcapng'))
                totals = {}
                for path in paths:
                    if self.stop_event.is_set():
                        return
                    data = self.closed.get(path.name)
                    if data is None:
                        data = summarize(path)
                        if path != paths[-1]:
                            self.closed[path.name] = data
                    for mac, counts in data.items():
                        totals.setdefault(mac, Counter()).update(counts)
                status = 'Обновено ' + time.strftime('%H:%M:%S') + ' • статистика по предавател • PgUp/PgDn'
                if paths and time.monotonic() - checked >= 120:
                    with tempfile.TemporaryDirectory(prefix='wifi-ready-') as temp:
                        out = Path(temp) / 'wpa.22000'
                        result = subprocess.run(['hcxpcapngtool', '-o', str(out), *map(str, paths)],
                                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=90)
                        if result.returncode:
                            logging.getLogger('wifi').error('hcxpcapngtool: %s', result.stderr)
                            status += ' • проверката за готовност не успя'
                        elif out.exists():
                            for line in out.read_text().splitlines():
                                parts = line.split('*')
                                if len(parts) >= 6 and parts[0] == 'WPA' and parts[1] in ('01', '02'):
                                    ready.add((parts[3].lower(), parts[4].lower()))
                    checked = time.monotonic()
                self.snapshot = (totals, set(ready), status)
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                logging.getLogger('wifi').exception('Грешка при анализ')
                old, accepted, _ = self.snapshot
                self.snapshot = (old, accepted, 'Статистиката е остаряла: ' + str(exc)[:180])
            self.stop_event.wait(30)

    def close(self):
        self.stop_event.set()
        self.thread.join(timeout=1)
