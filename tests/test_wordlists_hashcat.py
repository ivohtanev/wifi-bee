import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import Mock, patch

from wifi_hashcat import StatusReader, display_plain, execute, resume_command, build_command
from wifi_storage import atomic_json
from wifi_wordlists import Cancelled, dictionaries, transfer
import test_console_features as fixtures
from test_console_features import Screen


class Response(io.BytesIO):
    headers = {}
    def geturl(self): return 'https://example.test/words.txt'


class Downloads(unittest.TestCase):
    def entry(self, data, kind='all', output=None):
        output = data if output is None else output
        return dict(id='test', filename='test.txt', url='https://example.test/words.txt',
                    bytes=len(data), installed_bytes=len(output), filter=kind,
                    sha256=hashlib.sha256(data).hexdigest(),
                    installed_sha256=hashlib.sha256(output).hexdigest())

    def session(self): return types.SimpleNamespace(uid=os.getuid(), gid=os.getgid())

    def test_verified_numeric_filter_and_discovery(self):
        data = b'12345678\nwordpass\n1234\n87654321\n'
        entry = self.entry(data, 'digits', b'12345678\n87654321\n')
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / 'wordlists'
            state = {}
            with patch('wifi_wordlists.urllib.request.urlopen', return_value=Response(data)):
                transfer(entry, folder, self.session(), state, threading.Event())
            self.assertEqual((folder / 'test.txt').read_bytes(), b'12345678\n87654321\n')
            self.assertEqual(dictionaries(Path(temp)), [folder / 'test.txt'])
            self.assertEqual((folder / 'test.txt').stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(folder.glob('*.part')), [])

    def test_corruption_preserves_existing_dictionary(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder / 'test.txt').write_bytes(b'original\n')
            with patch('wifi_wordlists.urllib.request.urlopen', return_value=Response(b'badbytes\n')):
                with self.assertRaises(ValueError):
                    transfer(self.entry(b'goodpass\n'), folder, self.session(), {}, threading.Event())
            self.assertEqual((folder / 'test.txt').read_bytes(), b'original\n')
            self.assertEqual(list(folder.glob('*.part')), [])

    def test_cancel_does_not_publish(self):
        cancel = threading.Event(); cancel.set()
        with tempfile.TemporaryDirectory() as temp, patch('wifi_wordlists.urllib.request.urlopen', return_value=Response(b'password\n')):
            with self.assertRaises(Cancelled):
                transfer(self.entry(b'password\n'), Path(temp), self.session(), {}, cancel)
            self.assertFalse((Path(temp) / 'test.txt').exists())

    def test_no_space_before_network(self):
        with tempfile.TemporaryDirectory() as temp, patch('wifi_wordlists.shutil.disk_usage', return_value=types.SimpleNamespace(free=0)), patch('wifi_wordlists.urllib.request.urlopen') as url:
            with self.assertRaises(OSError):
                transfer(self.entry(b'password\n'), Path(temp), self.session(), {}, threading.Event())
            url.assert_not_called()


class TaskStorage(unittest.TestCase):
    def setUp(self):
        patcher = patch('wifi_hashcat.tool_environment', return_value={'hashcat': 'test'})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_split_status_and_non_json_messages(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / 'log'
            log.write_bytes(b'Initializing GPU\n{"progress": [20, 100],')
            reader = StatusReader(log)
            self.assertEqual(reader.update(), {})
            with log.open('ab') as stream: stream.write(b'"devices": [{"device_name": "GPU", "speed": 100}]}\n')
            self.assertEqual(reader.update()['progress'], [20, 100])
            self.assertEqual(reader.messages, ['Initializing GPU'])
            self.assertEqual(reader.update()['devices'][0]['speed'], 100)

    def test_atomic_write_failure_keeps_previous_snapshot(self):
        session = types.SimpleNamespace(uid=os.getuid(), gid=os.getgid())
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'run.json'
            atomic_json(path, {'progress': 10}, session)
            with patch('wifi_storage.os.replace', side_effect=OSError('disk failure')):
                with self.assertRaises(OSError): atomic_json(path, {'progress': 20}, session)
            self.assertEqual(json.loads(path.read_text()), {'progress': 10})
            self.assertEqual(len(list(path.parent.iterdir())), 1)

    def test_resume_validates_dictionary_and_selects_version(self):
        with tempfile.TemporaryDirectory() as temp:
            job = Path(temp)
            dictionary = job / 'words.txt'; dictionary.write_bytes(b'password\n')
            source = job / 'input.22000'; source.write_bytes(b'test-data')
            (job / 'hashcat.restore').write_bytes(b'checkpoint')
            record = dict(id='test', dictionary=str(dictionary),
                          dictionary_sha256=hashlib.sha256(dictionary.read_bytes()).hexdigest(),
                          input_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                          command=['hashcat', '-m', '22000', str(source), str(dictionary)])
            record['command'] = build_command(record, job)
            fixtures.write_restore(job / 'hashcat.restore', job, record['command'])
            with patch('wifi_hashcat.subprocess.run', return_value=types.SimpleNamespace(stdout='--restore')):
                self.assertIn('--restore', resume_command(record, job))
            with patch('wifi_hashcat.subprocess.run', return_value=types.SimpleNamespace(stdout='--restore-position')):
                self.assertEqual(resume_command(record, job), record['command'] + ['--restore-position'])
            dictionary.write_bytes(b'changed\n')
            with self.assertRaises(ValueError): resume_command(record, job)

    def test_hex_and_colon_password_display(self):
        self.assertEqual(display_plain('hash:pass:word'), 'pass:word')
        self.assertEqual(display_plain('hash:$HEX[7061737331323334]'), 'pass1234')
        self.assertNotIn('\x1b', display_plain('hash:abc\x1bxyz'))

    def test_output_failure_prevents_launch(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            folder = fixtures.Features().dataset(base)
            dictionary = base / 'words.txt'; dictionary.write_text('password\n')
            session = types.SimpleNamespace(destination=base / 'captures', uid=os.getuid(), gid=os.getgid())
            with patch('wifi_hashcat.durable_touch', side_effect=PermissionError('read only')), patch('wifi_hashcat.subprocess.Popen') as popen:
                with self.assertRaises(PermissionError): execute(Screen([]), session, lambda *a: None, folder, dictionary)
                popen.assert_not_called()

    def test_status_checkpoint_and_result_survive_process_error(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            folder = fixtures.Features().dataset(base)
            dictionary = base / 'words.txt'; dictionary.write_text('password\n')
            session = types.SimpleNamespace(destination=base / 'captures', uid=os.getuid(), gid=os.getgid())
            proc = Mock(pid=12345, returncode=255)
            proc.poll.side_effect = [None, 255, 255]
            def launch(command, **kwargs):
                job = kwargs['cwd']
                (job / 'recovered.txt').write_text('hash:password\n')
                (job / 'hashcat.restore').write_bytes(b'test-checkpoint')
                kwargs['stdout'].write(json.dumps({'progress': [45, 100], 'restore_point': 30, 'recovered_hashes': [1, 2]}) + '\n')
                kwargs['stdout'].flush()
                return proc
            with patch('wifi_hashcat.subprocess.Popen', side_effect=launch), patch('wifi_hashcat.select'):
                execute(Screen([-1]), session, lambda *a: None, folder, dictionary)
            path = next((base / 'data/hashcat').glob('*/run.json'))
            record = json.loads(path.read_text())
            self.assertEqual(record['progress']['progress'], [45, 100])
            self.assertEqual(record['recovered'], 1)
            self.assertTrue(record['checkpoint_available'])
            self.assertEqual(Path(record['results']).read_text(), 'hash:password\n')


if __name__ == '__main__': unittest.main()
