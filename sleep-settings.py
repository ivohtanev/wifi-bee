#!/usr/bin/python3
"""Меню за автоматично заспиване в GNOME. Стартира се без sudo."""

import argparse
from contextlib import contextmanager
import curses
import json
import locale
import os
from pathlib import Path
import shlex
import subprocess
import sys
import textwrap

try:
    from gi.repository import Gio, GLib
except ImportError:
    sys.exit('Грешка: липсва python3-gi.\nПрепоръка: sudo apt install python3-gi\n'
             'После стартирай скрипта отново без sudo.')


SCHEMA = 'org.gnome.settings-daemon.plugins.power'
OPTIONS = [(60, '1 минута (тест)'), (900, '15 минути'), (1800, '30 минути'),
           (3600, '1 час'), (7200, '2 часа'), (None, 'Никога')]
SCOPES = [('battery', 'На батерия (Battery)'), ('ac', 'На ток (Plugged in)')]


class SettingsError(RuntimeError):
    def __init__(self, message, advice, details=''):
        self.message, self.advice, self.details = message, advice, str(details)
        super().__init__(self.message)

    def __str__(self):
        result = f'Грешка: {self.message}\nПрепоръка: {self.advice}'
        if self.details:
            result += '\nПодробности: ' + self.details
        return result


def launch_command():
    return '/usr/bin/python3 ' + shlex.quote(str(Path(__file__).resolve()))


def explain(exc, operation='работа с настройките'):
    if isinstance(exc, SettingsError):
        return exc
    detail = str(exc)
    lowered = detail.lower()
    if isinstance(exc, PermissionError) or any(word in lowered for word in
            ('permission denied', 'access denied', 'read-only', 'not permitted')):
        config = Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config')))
        command = 'ls -ld ' + ' '.join(shlex.quote(str(path)) for path in
                                      (config, config / 'dconf', config / 'dconf/user'))
        return SettingsError(f'Няма нужните права при {operation}.',
                             'Стартирай без sudo от своя GNOME потребител. '
                             'Провери собствеността и правата с: ' + command +
                             '. Ако файловете са на друг потребител, '
                             'администратор трябва да поправи собствеността.', detail)
    if any(word in lowered for word in ('dbus', 'd-bus', 'bus address', 'autolaunch',
                                        'cannot connect', 'connection refused')):
        return SettingsError('Няма връзка с потребителската D-Bus сесия.',
                             'Отвори Terminal в своята GNOME сесия и изпълни без sudo: '
                             + launch_command() +
                             '. Ако проблемът остава, излез от профила и влез отново.', detail)
    if isinstance(exc, subprocess.TimeoutExpired):
        return SettingsError(f'Изтече времето за {operation}.',
                             'Опитай отново. Ако проблемът остава, '
                             'излез от GNOME профила и влез отново.', detail)
    if isinstance(exc, curses.error):
        return SettingsError('Терминалът не поддържа менюто или е преоразмерен.',
                             'Отвори Terminal, увеличи прозореца и изпълни: '
                             + launch_command() + '. Само проверка: '
                             + launch_command() + ' --status', detail)
    if isinstance(exc, (locale.Error, UnicodeError)):
        return SettingsError('Проблем с езиковата настройка на терминала.',
                             'Стартирай с UTF-8: LC_ALL=C.UTF-8 ' + launch_command(), detail)
    return SettingsError(f'Неуспешна {operation}.',
                         'Опитай отново от Terminal в GNOME без sudo. '
                         'Ако проблемът се повтори, изпрати съобщението с подробностите.',
                         f'{type(exc).__name__}: {detail}')


@contextmanager
def backend_errors():
    """dconf reports some failures as GLib warnings instead of exceptions."""
    messages = []
    handler = GLib.log_set_handler(
        'dconf', GLib.LogLevelFlags.LEVEL_WARNING | GLib.LogLevelFlags.LEVEL_CRITICAL,
        lambda domain, level, message, data: messages.append(message), None)
    try:
        yield
        if messages:
            raise RuntimeError('\n'.join(messages))
    finally:
        GLib.log_remove_handler('dconf', handler)


def read_persisted():
    """Use a separate process so verification does not read Gio's local cache."""
    code = ('import json; from gi.repository import Gio; '
            f's = Gio.Settings.new({SCHEMA!r}); '
            'print(json.dumps({source: '
            '[s.get_string("sleep-inactive-" + source + "-type"), '
            's.get_int("sleep-inactive-" + source + "-timeout")] '
            'for source in ("ac", "battery")}))')
    try:
        result = subprocess.run(['/usr/bin/python3', '-c', code],
                                capture_output=True, text=True, timeout=8)
        if result.returncode or result.stderr.strip():
            raise RuntimeError(result.stderr.strip() or
                               f'Процесът за четене завърши с код {result.returncode}.')
        values = json.loads(result.stdout)
        for source in ('ac', 'battery'):
            action, seconds = values[source]
            if not isinstance(action, str) or type(seconds) is not int:
                raise ValueError('Невалиден формат на прочетената настройка.')
        return values
    except Exception as exc:
        raise explain(exc, 'четене на записаните настройки') from exc


def current(settings, source):
    try:
        with backend_errors():
            action = settings.get_string(f'sleep-inactive-{source}-type')
            seconds = settings.get_int(f'sleep-inactive-{source}-timeout')
        return action, seconds
    except Exception as exc:
        raise explain(exc, 'четене на настройката за ' + source) from exc


def describe(value):
    action, seconds = value
    if action == 'nothing' or seconds <= 0:
        return 'Никога'
    duration = next((label for sec, label in OPTIONS if sec == seconds),
                    f'{seconds} секунди')
    if action == 'suspend':
        return duration
    return f'{duration} (действие: {action})'


def matches(value, seconds):
    action, timeout = value
    if seconds is None:
        return action == 'nothing' or timeout <= 0
    return action == 'suspend' and timeout == seconds


def allowed(settings, scope, seconds):
    if scope == 'ac':
        return True
    action, limit = current(settings, 'ac')
    if action == 'nothing' or limit <= 0:
        return True
    return seconds is not None and seconds <= limit


def save(settings, scope, seconds):
    if scope not in ('ac', 'battery'):
        raise ValueError('Непознат режим на захранване.')
    if not allowed(settings, scope, seconds):
        raise SettingsError('На батерия времето не може да надвишава това на ток.',
                            'Избери по-кратко време за батерията или първо увеличи времето на ток.')
    targets = (scope,)
    keys = [f'sleep-inactive-{source}-{part}'
            for source in targets for part in ('type', 'timeout')]
    locked = [key for key in keys if not settings.is_writable(key)]
    if locked:
        raise SettingsError('Настройката е заключена от системна политика.',
                            'Помоли администратора да премахне съответното dconf заключване. '
                            'Стартиране със sudo няма да отключи настройката за твоя профил.',
                            ', '.join(locked))
    if os.environ.get('GSETTINGS_BACKEND', 'dconf') == 'dconf':
        try:
            Gio.bus_get_sync(Gio.BusType.SESSION, None)
        except Exception as exc:
            raise explain(RuntimeError('D-Bus: ' + str(exc)), 'свързване с GNOME') from exc
    settings.delay()
    try:
        for source in targets:
            if not settings.set_string(f'sleep-inactive-{source}-type',
                                       'nothing' if seconds is None else 'suspend'):
                raise RuntimeError('Неуспешно задаване на действието.')
            if not settings.set_int(f'sleep-inactive-{source}-timeout', seconds or 0):
                raise RuntimeError('Неуспешно задаване на времето.')
        with backend_errors():
            settings.apply()
            Gio.Settings.sync()
    except Exception as exc:
        settings.revert()
        raise explain(exc, 'запис на настройката') from exc
    persisted = read_persisted()
    if not all(matches(persisted[source], seconds) for source in targets):
        raise SettingsError('Промяната не е потвърдена като записана.',
                            'Провери с ' + launch_command() + ' --status. '
                            'Стартирай от GNOME без sudo; ако проблемът остава, '
                            'провери правата за ~/.config/dconf и системните dconf политики.',
                            'Поискано: ' + str(seconds) + '; прочетено: ' + str(persisted))


def selected_index(settings, scope):
    return next((i for i, (seconds, _) in enumerate(OPTIONS)
                 if matches(current(settings, scope), seconds)), 0)


def show_error(screen, exc):
    """Keep the full diagnostic readable, including in a narrow terminal."""
    error = str(explain(exc))
    offset = 0
    while True:
        screen.erase()
        height, width = screen.getmaxyx()
        wrap_width = max(1, width - 4)
        lines = [line for paragraph in error.splitlines()
                 for line in (textwrap.wrap(paragraph, wrap_width) or [''])]
        available = max(1, height - 4)
        offset = min(offset, max(0, len(lines) - available))
        for row, line in enumerate(lines[offset:offset + available], 1):
            if row < height - 1 and width > 4:
                screen.addnstr(row, 2, line, wrap_width)
        if height >= 3 and width > 4:
            screen.addnstr(height - 2, 2, '↑/↓: преглед · Enter/Esc/Q: затвори', wrap_width,
                           curses.A_BOLD)
        screen.refresh()
        key = screen.getch()
        if key in (10, 13, curses.KEY_ENTER, 27, ord('q'), ord('Q')):
            return
        if key in (curses.KEY_DOWN, curses.KEY_NPAGE):
            offset = min(max(0, len(lines) - available), offset +
                         (available if key == curses.KEY_NPAGE else 1))
        elif key in (curses.KEY_UP, curses.KEY_PPAGE):
            offset = max(0, offset - (available if key == curses.KEY_PPAGE else 1))


def menu(screen, settings):
    try:
        curses.curs_set(0)
    except curses.error:
        pass  # Some terminals cannot hide the cursor.
    screen.keypad(True)
    scope_index = 0
    cursor = 0
    page = 'sources'
    message = ''

    def line(row, text, attr=0):
        height, width = screen.getmaxyx()
        if row < height - 1:
            screen.addnstr(row, 2, text, max(0, width - 4), attr)

    while True:
        screen.erase()
        height, width = screen.getmaxyx()
        if height < 22 or width < 66:
            line(0, 'Увеличи терминала до поне 66 × 22. Q — изход.')
            screen.refresh()
            if screen.getch() in (ord('q'), ord('Q'), 27):
                return
            continue
        scope, _ = SCOPES[scope_index]
        values = {source: current(settings, source) for source in ('ac', 'battery')}
        line(0, 'АВТОМАТИЧНО ЗАСПИВАНЕ', curses.A_BOLD)
        line(2, 'Текущо на ток:     ' + describe(values['ac']))
        line(3, 'Текущо на батерия: ' + describe(values['battery']))
        if page == 'sources':
            line(5, 'Кое захранване искаш да настроиш?', curses.A_BOLD)
            for i, (_, label) in enumerate(SCOPES):
                line(7 + i, f'{"▶" if cursor == i else " "}  {label}',
                     curses.A_REVERSE if cursor == i else 0)
            line(14, '↑/↓ избор · Enter или →: отвори')
            line(15, 'Q или Esc: изход')
        else:
            line(5, SCOPES[scope_index][1], curses.A_BOLD)
            for i, (seconds, label) in enumerate(OPTIONS):
                enabled = allowed(settings, scope, seconds)
                text = f'{"▶" if cursor == i else " "}  {label}'
                if matches(values[scope], seconds):
                    text += '  ✓ избрано'
                if not enabled:
                    text += '  (недостъпно)'
                attr = curses.A_REVERSE if cursor == i else 0
                if not enabled:
                    attr |= curses.A_DIM
                line(7 + i, text, attr)
            line(13, f'{"▶" if cursor == len(OPTIONS) else " "}  ← Назад',
                 curses.A_REVERSE if cursor == len(OPTIONS) else 0)
            line(14, '↑/↓ избор · Enter: запази · ←/Esc: назад · Q: изход')
            if scope == 'battery':
                line(15, 'Лимит според настройката на ток: ' + describe(values['ac']))
        if (page == 'options' and scope == 'battery'
                and not allowed(settings, scope,
                                None if matches(values[scope], None) else values[scope][1])):
            line(16, 'Текущото време е над лимита. Избери по-ниска стойност.')
        line(17, 'Времето е след неактивност, не обратно броене от сега.')
        line(18, 'Настройката остава в сила и след затваряне на скрипта.')
        line(20, message, curses.A_BOLD)
        screen.refresh()
        key = screen.getch()
        if key in (ord('q'), ord('Q')):
            return
        if key in (27, curses.KEY_LEFT):
            if page == 'sources':
                if key == 27:
                    return
            else:
                page, cursor, message = 'sources', scope_index, ''
            continue
        if key in (curses.KEY_UP, curses.KEY_DOWN):
            count = len(SCOPES) if page == 'sources' else len(OPTIONS) + 1
            step = 1 if key == curses.KEY_DOWN else -1
            cursor = (cursor + step) % count
            while (page == 'options' and cursor < len(OPTIONS)
                   and not allowed(settings, scope, OPTIONS[cursor][0])):
                cursor = (cursor + step) % count
            message = ''
        elif key in (10, 13, curses.KEY_ENTER, curses.KEY_RIGHT):
            if page == 'sources':
                scope_index = cursor
                scope = SCOPES[scope_index][0]
                cursor = selected_index(settings, scope)
                if not allowed(settings, scope, OPTIONS[cursor][0]):
                    cursor = next((i for i, (seconds, _) in enumerate(OPTIONS)
                                   if allowed(settings, scope, seconds)), len(OPTIONS))
                page, message = 'options', ''
                continue
            if key == curses.KEY_RIGHT:
                continue
            if cursor == len(OPTIONS):
                page, cursor, message = 'sources', scope_index, ''
                continue
            try:
                save(settings, scope, OPTIONS[cursor][0])
                message = 'Запазено: ' + SCOPES[scope_index][1] + ' — ' + OPTIONS[cursor][1]
            except Exception as exc:
                show_error(screen, exc)
                message = 'Промяната не е потвърдена. Провери текущата стойност.'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--status', action='store_true', help='Показва настройките без промяна.')
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise SettingsError('Скриптът е стартиран като root.',
                            'Изпълни от Terminal в своя GNOME профил без sudo: '
                            + launch_command())
    schema_source = Gio.SettingsSchemaSource.get_default()
    schema = schema_source.lookup(SCHEMA, True) if schema_source else None
    if schema is None:
        raise SettingsError('Не е намерена схемата за захранване на GNOME.',
                            'В Ubuntu/GNOME изпълни: '
                            'sudo apt install --reinstall gsettings-desktop-schemas '
                            'gnome-settings-daemon-common. После стартирай скрипта без sudo.',
                            SCHEMA)
    missing = [f'sleep-inactive-{source}-{part}' for source in ('ac', 'battery')
               for part in ('type', 'timeout')
               if not schema.has_key(f'sleep-inactive-{source}-{part}')]
    if missing:
        raise SettingsError('Версията на GNOME няма всички необходими настройки.',
                            'Обнови пакетите на GNOME чрез Software Updater '
                            'и стартирай скрипта отново.', ', '.join(missing))
    with backend_errors():
        settings = Gio.Settings.new(SCHEMA)
    values = read_persisted()
    if args.status:
        for source, label in SCOPES:
            print(f'{label}: {describe(values[source])}')
        return
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise SettingsError('Менюто изисква интерактивен терминал.',
                            'Отвори Terminal и изпълни: ' + launch_command() +
                            '. За проверка без меню: ' + launch_command() + ' --status')
    locale.setlocale(locale.LC_ALL, '')
    if os.environ.get('TERM', '') in ('', 'dumb', 'unknown'):
        raise SettingsError('Терминалът няма подходяща TERM настройка.',
                            'Отвори GNOME Terminal и изпълни: ' + launch_command() +
                            '. За проверка без меню добави --status.')
    curses.wrapper(menu, settings)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:
        print(explain(exc), file=sys.stderr)
        sys.exit(1)
