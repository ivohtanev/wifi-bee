import curses
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

import test_console_features as fixtures
from test_console_features import Screen
from wifi_ui import ConfirmScreen, footer, help_steps
from wifi_wordlists import dictionary_label
from wifi_hashcat import execute, installed_masks, resume_command, text_input


class HelpAndMasks(unittest.TestCase):
    def test_help_returns_to_original_controls_and_scrolls(self):
        raw = Screen([ord('h'), curses.KEY_NPAGE, curses.KEY_END, curses.KEY_HOME, ord('q'), 10])
        raw.addnstr = Mock()
        screen = ConfirmScreen(raw)
        footer(screen, 'Enter избира')
        with patch('wifi_ui.curses.newwin', side_effect=curses.error):
            self.assertEqual(screen.getch(), -1)
        self.assertEqual(screen.controls, 'Enter избира')
        self.assertEqual(screen.getch(), 10)
        self.assertTrue(any('Помощ' in str(c) for c in raw.addnstr.call_args_list))

    def test_ctrl_c_inside_help_still_confirms_exit(self):
        screen = ConfirmScreen(Screen([ord('H'), 3, curses.KEY_DOWN, 10]))
        with patch('wifi_ui.curses.newwin', side_effect=curses.error):
            with self.assertRaises(KeyboardInterrupt):
                screen.getch()

    def test_path_input_preserves_lowercase_h_and_value_after_help(self):
        screen = ConfirmScreen(Screen([ord('/'), ord('h'), ord('H'), ord('q'), ord('i'), 10]))
        with patch('wifi_ui.curses.newwin', side_effect=curses.error):
            self.assertEqual(text_input(screen, lambda *args: None, 'Път'), '/hi')

    def test_footer_is_last_row_and_help_first_on_small_screen(self):
        raw = Screen([])
        raw.getmaxyx = lambda: (8, 20)
        raw.addnstr = Mock()
        footer(raw, 'Enter избира • Q назад')
        args = raw.addnstr.call_args.args
        self.assertEqual(args[:2], (7, 0))
        self.assertTrue(args[2].startswith('H помощ'))

    def test_help_contains_actual_paths(self):
        session = types.SimpleNamespace(destination=Path('/custom/captures'))
        text = '\n'.join(help_steps(session))
        for path in ('/custom/captures', '/custom/data/ready', '/custom/data/cache', '/custom/wordlists', '/custom/data/hashcat', '/custom/log', '/var/tmp/.recording-'):
            self.assertIn(path, text)

    def test_dictionary_titles_and_unknown_fallback(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'pwdb-1m.txt'; path.write_text('password\n')
            self.assertTrue(dictionary_label(path).startswith('Pwdb — 1 милион (pwdb-1m.txt)'))
            path = Path(temp) / 'my-words.txt'; path.write_text('password\n')
            self.assertTrue(dictionary_label(path).startswith('my words (my-words.txt)'))

    def test_mask_discovery_only_existing_nonempty_files(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            path = folder / 'hashcat-default.hcmask'; path.write_text('?d?d?d?d?d?d?d?d\n')
            (folder / 'empty.hcmask').touch()
            original_glob = Path.glob
            def glob(root, pattern):
                return original_glob(folder, pattern) if root == Path('/usr/share/hashcat/masks') else iter(())
            with patch('wifi_hashcat.Path.glob', glob), patch('wifi_hashcat.shutil.which', return_value=None):
                masks = installed_masks()
            self.assertEqual(len(masks), 1)
            self.assertEqual(masks[0][0], path)
            self.assertIn('(hashcat-default.hcmask)', masks[0][1])

    def test_mask_run_keeps_mode_results_and_validated_resume(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            folder = fixtures.Features().dataset(base)
            mask = base / 'hashcat-default.hcmask'; mask.write_text('?d?d?d?d?d?d?d?d\n')
            session = types.SimpleNamespace(destination=base/'captures', uid=os.getuid(), gid=os.getgid())
            proc = Mock(returncode=1, pid=12345); proc.poll.return_value = 1
            with patch('wifi_hashcat.subprocess.Popen', return_value=proc) as popen, patch('wifi_hashcat.select'), patch('wifi_hashcat.shutil.which', return_value='/usr/bin/hashcat'):
                execute(Screen([]), session, lambda *a: None, folder, mask, attack_mode=3)
            command = popen.call_args.args[0]
            self.assertEqual(command[command.index('-a') + 1], '3')
            self.assertIn('--increment', command)
            self.assertEqual(command[command.index('--increment-min') + 1], '8')
            self.assertEqual(command[command.index('--increment-max') + 1], '15')
            metadata_path = next((base/'data/hashcat').glob('*/run.json'))
            record = json.loads(metadata_path.read_text())
            self.assertEqual(record['attack_mode'], 3)
            (metadata_path.parent/'hashcat.restore').write_bytes(b'checkpoint')
            with patch('wifi_hashcat.subprocess.run', return_value=types.SimpleNamespace(stdout='--restore-position')):
                self.assertEqual(resume_command(record, metadata_path.parent), command + ['--restore-position'])
                mask.write_text('changed')
                with self.assertRaises(ValueError): resume_command(record, metadata_path.parent)


if __name__ == '__main__': unittest.main()
