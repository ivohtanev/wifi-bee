import curses
import errno
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import Mock, patch

import test_console_features as fixtures
from wifi_analysis import browse, select, ARCHIVE_KEYS
from wifi_archive import move_captures, move_dataset, extracted_index, extracted_paths
from wifi_hashcat import ResultReader, resume_command, build_command, choose_dataset, execute
from wifi_process import Processes
from wifi_storage import durable_move, check_space, secure, file_digest
from wifi_ui import ConfirmScreen
from wifi_wordlists import Deadline
from wifi_privilege import broker, drop_privileges

spec = importlib.util.spec_from_file_location('wifi_console', Path(__file__).parents[1] / 'wifi-console.py')
console = importlib.util.module_from_spec(spec)
spec.loader.exec_module(console)


def session(base):
    return types.SimpleNamespace(destination=base / 'captures', uid=os.getuid(), gid=os.getgid())


class Archives(unittest.TestCase):
    def test_capture_archive_restore_and_provenance(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); owner = session(base); owner.destination.mkdir()
            capture = owner.destination / '000001_fixture.pcapng'; capture.write_bytes(b'fixture')
            dataset = fixtures.Features().dataset(base)
            manifest = json.loads((dataset / 'manifest.json').read_text())
            manifest['sources'] = [{'path': str(capture), 'sha256': file_digest(capture)}]
            (dataset / 'manifest.json').write_text(json.dumps(manifest))
            move_captures(base, [capture], owner)
            archived = base / 'archive/captures' / capture.name
            self.assertFalse(capture.exists()); self.assertEqual(archived.read_bytes(), b'fixture')
            move_dataset(base, dataset, owner)
            self.assertEqual(extracted_paths([archived], extracted_index(base), {}), {archived})
            move_captures(base, [archived], owner, restore=True)
            self.assertEqual(capture.read_bytes(), b'fixture')
            capture.write_bytes(b'modified')
            self.assertFalse(extracted_paths([capture], extracted_index(base), {}))

    def test_archived_view_never_probes(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); owner = session(base)
            root = base / 'archive/captures'; root.mkdir(parents=True)
            (root / '000001_fixture.pcapng').write_bytes(b'fixture')
            with patch('wifi_analysis.series_ready') as probe:
                browse(fixtures.Screen([27]), owner, lambda *args: None, archived=True)
            probe.assert_not_called()

    def test_k_opens_archive_without_moving_a_record(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); owner = session(base); owner.destination.mkdir()
            capture = owner.destination / '000001_fixture.pcapng'; capture.write_bytes(b'fixture')
            with patch('wifi_analysis.series_ready', return_value=False), patch('wifi_analysis.move_captures') as move:
                browse(fixtures.Screen([ord('k'), 27, 27]), owner, lambda *args: None)
            move.assert_not_called(); self.assertTrue(capture.exists())

    def test_a_archives_selected_series_immediately(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); owner = session(base); owner.destination.mkdir()
            capture = owner.destination / '000001_fixture.pcapng'; capture.write_bytes(b'fixture')
            with patch('wifi_analysis.series_ready', return_value=False):
                browse(fixtures.Screen([ord('a'), 27]), owner, lambda *args: None)
            self.assertFalse(capture.exists())
            self.assertTrue((base / 'archive/captures' / capture.name).is_file())

    def test_dataset_hotkeys_and_checkpoint_untouched(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); owner = session(base); folder = fixtures.Features().dataset(base)
            job = base / 'data/hashcat/example'; job.mkdir(parents=True)
            (job / 'hashcat.restore').write_bytes(b'checkpoint')
            choose_dataset(fixtures.Screen([ord('a'), ord('k'), ord('a'), 27, 27]), owner, lambda *args: None)
            self.assertTrue(folder.is_dir())
            self.assertEqual((job / 'hashcat.restore').read_bytes(), b'checkpoint')

    def test_archive_collision_keeps_both_files(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); owner = session(base); owner.destination.mkdir()
            source = owner.destination / '000001_test.pcapng'; source.write_bytes(b'first')
            destination = base / 'archive/captures'; destination.mkdir(parents=True)
            (destination / source.name).write_bytes(b'different')
            with self.assertRaises(FileExistsError): move_captures(base, [source], owner)
            self.assertEqual(source.read_bytes(), b'first')
            self.assertEqual((destination / source.name).read_bytes(), b'different')


class Reliability(unittest.TestCase):
    def test_move_failure_and_retry_after_publication(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); owner = session(base)
            source = base / 'source'; source.write_bytes(b'data'); target = base / 'destination/target'
            original = Path.unlink
            def fail_source(path, *args, **kwargs):
                if path == source: raise OSError(errno.EIO, 'injected unlink failure')
                return original(path, *args, **kwargs)
            with patch('pathlib.Path.unlink', fail_source):
                with self.assertRaises(OSError): durable_move(source, target, owner)
            self.assertEqual(source.read_bytes(), target.read_bytes())
            durable_move(source, target, owner)
            self.assertFalse(source.exists()); self.assertEqual(target.read_bytes(), b'data')

    def test_failed_publish_keeps_source_and_removes_partial(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); source = base / 'source'; source.write_bytes(b'data')
            target = base / 'out/target'
            with patch('wifi_storage.os.link', side_effect=OSError(errno.ENOSPC, 'injected')):
                with self.assertRaises(OSError): durable_move(source, target, session(base))
            self.assertTrue(source.exists()); self.assertFalse(target.exists())
            self.assertEqual(list(target.parent.glob('*.part')), [])

    def test_space_and_inode_reserve(self):
        info = types.SimpleNamespace(f_bavail=1024, f_frsize=4096, f_files=1000, f_favail=999)
        with patch('wifi_storage.os.statvfs', return_value=info):
            with self.assertRaises(OSError): check_space(Path('/tmp'))
            info.f_bavail = 10**9; info.f_favail = 1
            with self.assertRaises(OSError): check_space(Path('/tmp'))

    def test_symlink_refused_without_changing_target(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); target = base / 'target'; target.write_bytes(b'data'); target.chmod(0o644)
            link = base / 'link'; link.symlink_to(target)
            with self.assertRaises(ValueError): secure(link, session(base))
            self.assertEqual(target.stat().st_mode & 0o777, 0o644)

    def test_incremental_results_over_64k_and_partial_lines(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'results'
            path.write_bytes(b'hash:password\n' * 10000 + b'hash:par')
            reader = ResultReader(path); reader.update()
            self.assertEqual(reader.count, 10000); self.assertEqual(len(reader.lines), 50)
            self.assertNotIn('hash:par', reader.lines)
            with path.open('ab') as stream: stream.write(b'tial\n')
            reader.update(); self.assertEqual(reader.count, 10001)
            self.assertEqual(reader.lines[-1], 'hash:partial')

    def test_modified_restore_arguments_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            job = Path(temp); dictionary = job / 'words'; dictionary.write_bytes(b'password\n')
            source = job / 'input.22000'; source.write_bytes(b'test')
            metadata = {'id': 'example', 'dictionary': str(dictionary), 'dictionary_sha256': file_digest(dictionary),
                        'input_sha256': file_digest(source), 'attack_mode': 0}
            command = build_command(metadata, job)
            fixtures.write_restore(job / 'hashcat.restore', job, command + ['--outfile', '/tmp/elsewhere'])
            with self.assertRaises(ValueError): resume_command(metadata, job)
            fixtures.write_restore(job / 'hashcat.restore', job, command)
            metadata['command'] = ['/bin/sh', '-c', 'untrusted']
            with patch('wifi_hashcat.subprocess.run', return_value=types.SimpleNamespace(stdout='--restore-position')):
                self.assertEqual(resume_command(metadata, job), command + ['--restore-position'])

    def test_confirmation_keeps_polling_tasks(self):
        raw = fixtures.Screen([3, *([-1] * 110), 27])
        screen = ConfirmScreen(raw); screen.poll_hook = Mock()
        self.assertEqual(screen.getch(), -1)
        # 110 iterations represent >20 s at the normal 200 ms input timeout.
        self.assertGreaterEqual(screen.poll_hook.call_count, 111)

    def test_owned_process_is_reaped_on_close(self):
        processes = Processes()
        proc = processes.popen([sys.executable, '-c', 'import time; time.sleep(60)'])
        processes.close()
        self.assertIsNotNone(proc.poll())
        with self.assertRaises(RuntimeError): processes.popen([sys.executable, '-V'])

    def test_capture_journal_can_be_recovered(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            with patch.object(console, 'BASE', base): owner = console.Session(owner=pwd.getpwuid(os.getuid()).pw_name)
            owner.temp = base / 'staging'; owner.temp.mkdir()
            owner.prefix = '000001_fixture'; owner.capture_state = {'files': []}
            (owner.temp / '000001_fixture.pcapng').write_bytes(b'fixture')
            with patch.object(console, 'durable_move', side_effect=OSError(errno.ENOSPC, 'injected')), self.assertLogs('wifi', level='ERROR'):
                owner.finish()
            self.assertFalse(owner.saved); self.assertTrue((owner.temp / 'session.json').exists())
            owner.finish()
            self.assertTrue(owner.saved); self.assertFalse(owner.temp.exists())
            self.assertEqual((owner.destination / '000001_fixture.pcapng').read_bytes(), b'fixture')

    def test_deadline_raises_even_with_available_network_data(self):
        with patch('wifi_wordlists.time.monotonic', side_effect=[0, 61]):
            deadline = Deadline(threading.Event(), 60)
            with self.assertRaises(TimeoutError): deadline.is_set()

    def test_inherited_job_lock_prevents_second_resume(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); owner = session(base)
            job = base / 'data/hashcat/job'; job.mkdir(parents=True)
            (job / 'run.json').write_text('{}')
            with (job / '.run.lock').open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with patch('wifi_hashcat.subprocess.Popen') as popen:
                    with self.assertRaisesRegex(ValueError, 'вече работи'):
                        execute(fixtures.Screen([]), owner, lambda *a: None, base, base, resume_job=job)
                    popen.assert_not_called()

    def test_final_save_failure_does_not_replace_interrupt(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); owner = session(base); folder = fixtures.Features().dataset(base)
            dictionary = base / 'words.txt'; dictionary.write_text('password\n')
            proc = Mock(pid=12345, returncode=2); proc.poll.return_value = None
            raw = fixtures.Screen([]); raw.getch = Mock(side_effect=KeyboardInterrupt)
            def save(job, metadata, status, owner):
                if 'finished' in metadata:
                    raise OSError(errno.ENOSPC, 'injected final save error')
            with patch('wifi_hashcat.subprocess.Popen', return_value=proc), \
                 patch('wifi_hashcat.os.killpg'), patch('wifi_hashcat.tool_environment', return_value={}), \
                 patch('wifi_hashcat.save_progress', side_effect=save), self.assertLogs('wifi', level='ERROR'):
                with self.assertRaises(KeyboardInterrupt):
                    execute(raw, owner, lambda *a: None, folder, dictionary)

    def test_privilege_drop_order(self):
        account = types.SimpleNamespace(pw_uid=1234, pw_gid=1234, pw_name='fixture', pw_dir='/tmp')
        with patch.dict(os.environ), patch('wifi_privilege.os.initgroups') as groups, \
             patch('wifi_privilege.os.setgid') as gid, patch('wifi_privilege.os.setuid') as uid:
            drop_privileges(account)
            groups.assert_called_once_with('fixture', 1234); gid.assert_called_once_with(1234); uid.assert_called_once_with(1234)

    def test_broker_rejects_paths_outside_staging(self):
        sock = Mock(); sock.recv.side_effect = [json.dumps({'op': 'start', 'path': '/tmp/forbidden.pcapng'}).encode(), b'']
        with patch('wifi_privilege.subprocess.Popen') as popen, patch('wifi_privilege.os.chdir'):
            broker(sock, os.getuid(), os.getgid(), 'wifi_mon')
        popen.assert_not_called()
        self.assertIn('error', json.loads(sock.sendmsg.call_args.args[0][0]))


if __name__ == '__main__': unittest.main()
