import unittest
from wifi_capture_info import parse_frames


class CaptureInfoTests(unittest.TestCase):
    def test_times_devices_multicast_and_names(self):
        first, last, packets, frequencies, devices = parse_frames([
            '20\t00:11:22:33:44:55\taa:bb:cc:dd:ee:ff\t2412\t54657374\tRouter\n',
            '10\taa:bb:cc:dd:ee:ff\tff:ff:ff:ff:ff:ff\t2412\t\t\n'])
        self.assertEqual((first, last, packets), (10, 20, 2))
        self.assertEqual(len(devices), 2)
        self.assertEqual(frequencies['2412'], 2)
        self.assertIn('име: Router', devices['00:11:22:33:44:55'])
        self.assertNotIn('име: Router', devices['aa:bb:cc:dd:ee:ff'])

    def test_empty(self):
        self.assertEqual(parse_frames([])[:3], (None, None, 0))
