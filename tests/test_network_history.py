import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from wifi_network_history import inventory, previous, records, synchronize


class NetworkHistoryTests(unittest.TestCase):
    def test_history_and_distinct_records(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            session = SimpleNamespace(uid=os.getuid(), gid=os.getgid())
            line = 'WPA*01*' + 'a' * 32 + '*001122334455*aabbccddeeff*54657374***'
            source = base / 'data/ready/set/wpa.22000'
            source.parent.mkdir(parents=True)
            source.write_text(line + '\n' + line + '\ninvalid\n')
            self.assertEqual(len(inventory(source)), 1)
            self.assertIn('1 WPA записа', inventory(source)[0])
            job = base / 'data/hashcat/run1'
            job.mkdir(parents=True)
            (job / 'input.22000').write_text(line + '\n')
            (job / 'run.json').write_text(json.dumps(dict(id='run1', status='finished', returncode=1, dictionary='digits.hcmask')))
            self.assertIn('има същия WPA запис', previous(base, session, source)[0])
            source.write_text(line.replace('a' * 32, 'b' * 32) + '\n')
            self.assertIn('различни WPA записи', previous(base, session, source)[0])
            self.assertIn('изчерпана', previous(base, session, source)[0])
            archived = base / 'archive/ready/set'
            archived.mkdir(parents=True)
            source.rename(archived / source.name)
            db = synchronize(base, session)
            self.assertEqual(db.execute('SELECT COUNT(DISTINCT ap) FROM evidence').fetchone()[0], 1)
            db.close()
            self.assertEqual((base / 'data/network-history.sqlite3').stat().st_mode & 0o777, 0o600)

    def test_invalid_addresses_are_ignored(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'hashes'
            path.write_text('WPA*01*hash*bad*bad*zz***\n')
            self.assertEqual(records(path), [])
