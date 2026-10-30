import unittest
from pathlib import Path
from wifi_ui import breadcrumb, navigation, capture_location


class NavigationTests(unittest.TestCase):
    def test_nested_navigation_restored_after_error(self):
        @navigation('Анализ')
        def outer():
            @navigation(lambda a: capture_location(a))
            def inner(paths):
                self.assertEqual(breadcrumb('Статистика'), 'Главно меню › Анализ › Сесия 000052 › Статистика')
                raise ValueError('cancel')
            with self.assertRaises(ValueError):
                inner([Path('000052_ch-11_test.pcapng')])
            self.assertEqual(breadcrumb('Файлове'), 'Главно меню › Анализ › Файлове')
        outer()
        self.assertEqual(breadcrumb('Hashcat'), 'Главно меню › Hashcat')

    def test_full_header_is_not_duplicated(self):
        self.assertEqual(breadcrumb(breadcrumb('Меню')), 'Главно меню › Меню')

    def test_archive_and_multiple_files(self):
        self.assertEqual(capture_location({'paths': [Path('000052_a'), Path('000052_b')], 'archived': True}),
                         'Сесия 000052 • архив')
