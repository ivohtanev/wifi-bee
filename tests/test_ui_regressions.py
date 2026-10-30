import curses
import json
import itertools
import os
from pathlib import Path
import tempfile
import threading
import types
import unittest
from unittest.mock import patch, Mock

from test_console_features import Screen
import test_console_features as fixtures
import test_wordlists_hashcat as downloads
from wifi_analysis import select, series_ready
from wifi_hashcat import execute, StatusReader, builtin_masks, dataset_checkpoint, mask_details, mask_length
from wifi_wordlists import filter_wpa, transfer


class Regressions(unittest.TestCase):
    def setUp(self):
        patcher = patch('wifi_hashcat.tool_environment', return_value={'hashcat': 'test'})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_prompt_and_ansi_do_not_hide_split_json(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'log'
            path.write_bytes(b'\x1b[2K\r[s]tatus [p]ause [b]ypass => {"progress": [12,')
            reader = StatusReader(path)
            self.assertEqual(reader.update(), {})
            with path.open('ab') as stream:
                stream.write(b' 100]}\n[s]tatus [r]esume => \n')
            self.assertEqual(reader.update()['progress'], [12, 100])
            self.assertEqual(reader.messages, [])

    def test_numbering_back_and_checkpoint_marker(self):
        drawn = []
        result = select(Screen([curses.KEY_DOWN, 10]), 'title', ['★ dataset'],
                        lambda screen, row, value, *args: drawn.append(value))
        self.assertIsNone(result)
        self.assertTrue(any('★ [1] dataset' in line for line in drawn))
        self.assertTrue(any('[2] Назад' in line for line in drawn))

    def test_details_wrap_and_scroll(self):
        drawn = []
        select(Screen([curses.KEY_RIGHT, 27]), 'title', ['Назад'],
               lambda screen, row, value, *args: drawn.append(value),
               ['detail-' + str(i) for i in range(12)])
        self.assertIn('detail-11', drawn)

    def test_wpa_filter_boundaries_and_hex(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'in'; target = Path(temp) / 'out'
            good = [b'12345678', b'x' * 63, b'$HEX[3132333435363738]', 'парола'.encode()]
            source.write_bytes(b'1234567\n' + b'x' * 64 + b'\n$HEX[3132]\n' + b'\r\n'.join(good) + b'\r\n')
            self.assertEqual(filter_wpa(source, target), (4, 3))
            self.assertEqual(target.read_bytes(), b'\n'.join(good) + b'\n')

    def test_download_all_is_verified_then_filtered(self):
        helper = downloads.Downloads()
        data = b'short\npassword\n'
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp); state = {}
            with patch('wifi_wordlists.urllib.request.urlopen', return_value=downloads.Response(data)):
                transfer(helper.entry(data), folder, helper.session(), state, threading.Event())
            self.assertEqual((folder / 'test.txt').read_bytes(), b'password\n')
            self.assertEqual(state['skipped'], 1)
            self.assertEqual(json.loads((folder / 'test.json').read_text())['wpa_lines'], 1)

    def test_builtins_and_mask_lengths(self):
        with tempfile.TemporaryDirectory() as temp:
            session = types.SimpleNamespace(uid=os.getuid(), gid=os.getgid())
            masks = builtin_masks(Path(temp), session)
            self.assertEqual(masks[0][0].read_text().splitlines(), ['?d' * 8])
            self.assertEqual(masks[1][0].read_text().splitlines(), ['?d' * 9, '?d' * 10])
            self.assertIn('?d' * 8, '\n'.join(mask_details(masks[0][0])))
        self.assertEqual(mask_length('?l?d,?1?1?1?1?1?1??x'), 8)
        self.assertEqual(mask_length(r'ab\,cd?d?d?d'), 8)

    def test_checkpoint_marker_requires_actual_restore(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); job = base / 'data/hashcat/job'; job.mkdir(parents=True)
            dataset = base / 'data/ready/example'
            (job / 'run.json').write_text(json.dumps({'dataset': str(dataset), 'checkpoint_available': True}))
            self.assertFalse(dataset_checkpoint(base, dataset))
            (job / 'hashcat.restore').write_bytes(b'checkpoint')
            self.assertTrue(dataset_checkpoint(base, dataset))

    def test_paused_checkpoint_sends_resume_before_checkpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            folder = fixtures.Features().dataset(base)
            dictionary = base / 'words.txt'; dictionary.write_text('password\n')
            session = types.SimpleNamespace(destination=base / 'captures', uid=os.getuid(), gid=os.getgid())
            proc = Mock(pid=12345, returncode=3)
            proc.poll.side_effect = [None, None, None, 3, 3]
            clock = itertools.count(step=2)
            status = lambda state: {'status': state, 'progress': [10, 100]}
            with patch('wifi_hashcat.subprocess.Popen', return_value=proc), \
                 patch('wifi_hashcat.select', return_value=1), \
                 patch('wifi_hashcat.os.write') as send, \
                 patch('wifi_hashcat.time.monotonic', side_effect=lambda: next(clock)), \
                 patch('wifi_hashcat.StatusReader.update', side_effect=[status(3), status(4), status(3), status(3)]):
                execute(Screen([-1, ord('p'), ord('c'), -1]), session, lambda *a: None, folder, dictionary)
            self.assertEqual([call.args[1] for call in send.call_args_list], [b'p', b'r', b'c'])

    def test_series_probe_ready_empty_and_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            capture = Path(temp) / '1_capture.pcapng'; capture.write_bytes(b'fixture')
            def accepted(command, **kwargs):
                Path(command[2]).write_text('WPA*01*fixture\n')
                return types.SimpleNamespace(returncode=0)
            with patch('wifi_analysis.subprocess.run', side_effect=accepted):
                self.assertTrue(series_ready([capture]))
            with patch('wifi_analysis.subprocess.run', return_value=types.SimpleNamespace(returncode=0)):
                self.assertFalse(series_ready([capture]))
            with patch('wifi_analysis.subprocess.run', return_value=types.SimpleNamespace(returncode=1)):
                self.assertIsNone(series_ready([capture]))


if __name__ == '__main__': unittest.main()
