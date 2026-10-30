import curses
import hashlib
import json
import os
import struct
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from wifi_ui import ConfirmScreen
from wifi_hashcat import load_dataset, execute, explain


def write_restore(path, job, command):
    header = bytearray(296)
    struct.pack_into('<I', header, 0, 600)
    cwd = str(job).encode()
    header[4:4 + len(cwd)] = cwd
    struct.pack_into('<I', header, 280, len(command))
    path.write_bytes(header + ('\n'.join(command) + '\n').encode())


class Screen:
    def __init__(self, keys):
        self.keys = iter(keys)
    def getch(self): return next(self.keys)
    def getmaxyx(self): return 24, 100
    def erase(self): pass
    def refresh(self): pass
    def timeout(self, value): pass
    def addnstr(self, *args): pass


class Features(unittest.TestCase):
    def setUp(self):
        patcher = patch('wifi_hashcat.tool_environment', return_value={'hashcat': 'test'})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_interrupt_default_no(self):
        screen = ConfirmScreen(Screen([-1, 10]))
        screen.pending = True
        self.assertEqual(screen.getch(), -1)
        self.assertFalse(screen.pending)

    def test_interrupt_yes(self):
        screen = ConfirmScreen(Screen([3, curses.KEY_DOWN, 10]))
        with self.assertRaises(KeyboardInterrupt): screen.getch()

    def test_repeat_interrupt_cancels(self):
        screen = ConfirmScreen(Screen([3, 3]))
        self.assertEqual(screen.getch(), -1)

    def dataset(self, base):
        folder = base / 'data' / 'ready' / 'sample'
        folder.mkdir(parents=True)
        hashes = folder / 'wpa.22000'
        hashes.write_text('WPA*01*synthetic-test-only\n')
        (folder / 'manifest.json').write_text(json.dumps({
            'id': 'sample', 'category': 'ready', 'hashcat_mode': 22000,
            'outputs': {'wpa.22000': hashlib.sha256(hashes.read_bytes()).hexdigest()}}))
        return folder

    def test_tampering_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = self.dataset(Path(temp))
            self.assertEqual(load_dataset(folder)[2], 1)
            (folder / 'wpa.22000').write_text('modified')
            with self.assertRaises(ValueError): load_dataset(folder)

    def test_exhausted_run_persists(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            folder = self.dataset(base)
            dictionary = base / 'words.txt'
            dictionary.write_text('test-password\n')
            session = types.SimpleNamespace(destination=base/'captures', uid=os.getuid(), gid=os.getgid())
            proc = Mock(returncode=1, pid=12345)
            proc.poll.return_value = 1
            with patch('wifi_hashcat.subprocess.Popen', return_value=proc) as popen, patch('wifi_hashcat.select'), patch('wifi_hashcat.shutil.which', return_value='/usr/bin/hashcat'):
                execute(Screen([]), session, lambda *a: None, folder, dictionary)
            command = popen.call_args.args[0]
            self.assertNotIn('--force', command)
            self.assertEqual(Path(command[-1]).read_text(), dictionary.read_text())
            self.assertEqual(Path(command[-1]).name, 'candidates.txt')
            run = json.loads(next((base/'data/hashcat').glob('*/run.json')).read_text())
            self.assertEqual(run['returncode'], 1)
            self.assertEqual(run['status'], 'finished')
            self.assertTrue(Path(run['log']).exists())
            self.assertIn('изчерпан', run['message'])

    def test_interrupt_stops_child_and_persists(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            folder = self.dataset(base)
            dictionary = base / 'words.txt'
            dictionary.write_text('test-password\n')
            session = types.SimpleNamespace(destination=base/'captures', uid=os.getuid(), gid=os.getgid())
            proc = Mock(returncode=2)
            proc.poll.return_value = None
            proc.pid = 12345
            screen = Screen([])
            screen.getch = Mock(side_effect=KeyboardInterrupt)
            with patch('wifi_hashcat.subprocess.Popen', return_value=proc), patch('wifi_hashcat.os.killpg') as kill, patch('wifi_hashcat.shutil.which', return_value='/usr/bin/hashcat'):
                with self.assertRaises(KeyboardInterrupt):
                    execute(screen, session, lambda *a: None, folder, dictionary)
                kill.assert_called_once()
            run = json.loads(next((base/'data/hashcat').glob('*/run.json')).read_text())
            self.assertEqual(run['status'], 'interrupted')


if __name__ == '__main__': unittest.main()
