import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('wifi_console_radio_test', Path(__file__).resolve().parents[1] / 'wifi-console.py')
console = importlib.util.module_from_spec(spec)
spec.loader.exec_module(console)


class RadioStartupTests(unittest.TestCase):
    def test_unprivileged_start_reenters_broker_startup(self):
        with patch.object(console.os, 'geteuid', return_value=1000), patch.object(console.os, 'getuid', return_value=1000), patch.object(console.shutil, 'which', return_value='/usr/bin/sudo'), patch.object(console.os, 'execv') as execute, patch('builtins.print'):
            console.ensure_radio_privileges(SimpleNamespace(uid=1000, owner='tester'))
        args = execute.call_args.args[1]
        self.assertEqual(args[-2:], ['--owner', 'tester'])
        self.assertEqual(args[:2], ['/usr/bin/sudo', '--'])

    def test_offline_and_root_do_not_relaunch(self):
        for uid, offline in [(0, False), (1000, True)]:
            with patch.object(console.os, 'geteuid', return_value=uid), patch.object(console.os, 'getuid', return_value=uid), patch.object(console.os, 'execv') as execute:
                console.ensure_radio_privileges(SimpleNamespace(uid=uid, owner='tester'), offline)
                execute.assert_not_called()
