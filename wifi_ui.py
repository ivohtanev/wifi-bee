"""Shared interruption guard for every curses screen."""
import curses
import signal
import textwrap
from pathlib import Path


class ConfirmScreen:
    def __init__(self, screen, session=None):
        self.screen = screen
        self.pending = False
        self.session = session
        self.controls = '↑/↓ избор • Enter избира • Q/Esc назад'
        self.poll_hook = None
        self.polling = False

    def __getattr__(self, name):
        return getattr(self.screen, name)

    def interrupt(self, signum, frame):
        self.pending = True

    def refresh(self):
        footer(self.screen, self.controls)
        self.screen.refresh()

    def read_text_key(self):
        return self.getch(text_input=True)

    def poll_tasks(self):
        if self.poll_hook is not None and not self.polling:
            self.polling = True
            try:
                self.poll_hook()
            finally:
                self.polling = False

    def getch(self, text_input=False):
        self.poll_tasks()
        key = self.screen.getch()
        if self.pending or key == 3:
            self.pending = False
            if self.confirm():
                raise KeyboardInterrupt
            return -1
        if key in (ord('H'), curses.KEY_F1) or (key == ord('h') and not text_input):
            self.help()
            return -1
        return key

    def help(self):
        previous = self.controls
        offset = 0
        # Restore input dialogs too: they do not redraw their whole screen per key.
        saved = None
        try:
            saved = curses.newwin(*self.screen.getmaxyx())
            self.screen.overwrite(saved)
        except (curses.error, AttributeError):
            saved = None
        try:
            self.screen.timeout(200)
            while True:
                self.screen.erase()
                height, width = self.screen.getmaxyx()
                lines = []
                for paragraph in help_steps(self.session):
                    lines.extend(textwrap.wrap(paragraph, max(1, width - 3)) or [''])
                    lines.append('')
                visible = max(1, height - 3)
                offset = min(offset, max(0, len(lines) - visible))
                if width > 2 and height > 1:
                    self.screen.addnstr(0, 1, breadcrumb('Помощ • възстановяване на Wi-Fi парола'), width - 2, curses.A_BOLD)
                for row, line in enumerate(lines[offset:offset + visible], 1):
                    if row < height - 1 and width > 2:
                        self.screen.addnstr(row, 1, line, width - 2)
                footer(self.screen, '↑/↓ PgUp/PgDn скрол • Q/Esc/Enter/H затваря', help_label=False)
                self.screen.refresh()
                # Keep Ctrl+C confirmation active, without opening help recursively.
                self.poll_tasks()
                key = self.screen.getch()
                if self.pending or key == 3:
                    self.pending = False
                    if self.confirm():
                        raise KeyboardInterrupt
                elif key in (27, 10, 13, curses.KEY_ENTER, ord('q'), ord('Q'), ord('h'), ord('H'), curses.KEY_F1):
                    return
                elif key in (curses.KEY_UP, curses.KEY_PPAGE):
                    offset = max(0, offset - (visible if key == curses.KEY_PPAGE else 1))
                elif key in (curses.KEY_DOWN, curses.KEY_NPAGE):
                    offset += visible if key == curses.KEY_NPAGE else 1
                elif key == curses.KEY_HOME:
                    offset = 0
                elif key == curses.KEY_END:
                    offset = max(0, len(lines) - visible)
        finally:
            self.controls = previous
            if saved is not None:
                try:
                    saved.overwrite(self.screen)
                    self.refresh()
                except curses.error:
                    pass

    def getstr(self, row, column, limit):
        # Use the guarded key reader even in the manual-channel input dialog.
        value = bytearray()
        self.screen.timeout(200)
        curses.noecho()
        while True:
            key = self.getch()
            if key in (10, 13, curses.KEY_ENTER):
                return bytes(value)
            if key == 27:
                return b''
            if key in (curses.KEY_BACKSPACE, 8, 127):
                value = value[:-1]
            elif 32 <= key < 127 and len(value) < limit:
                value.append(key)
            height, width = self.screen.getmaxyx()
            if row < height - 1 and column < width - 1:
                self.screen.addnstr(row, column, value.decode().ljust(limit), width - column - 1)
            self.refresh()

    def confirm(self):
        selected = 0
        screen = self.screen
        screen.timeout(200)
        while True:
            screen.erase()
            height, width = screen.getmaxyx()
            lines = [breadcrumb('Да спра ли програмата?'),
                     'Активните задачи ще бъдат спрени, записите ще се запазят.',
                     'Enter потвърждава избора • Esc / Ctrl+C = Не',
                     ('▶ ' if selected == 0 else '  ') + '[1] Не — продължи',
                     ('▶ ' if selected == 1 else '  ') + '[2] Да — спри и запази']
            for row, line in enumerate(lines):
                if row < height - 1 and width > 2:
                    screen.addnstr(row, 1, line, width - 2,
                                   curses.A_REVERSE if row == selected + 3 else 0)
            footer(screen, '←/→ ↑/↓ избор • Enter потвърждава • Esc/Ctrl+C отказ')
            screen.refresh()
            self.poll_tasks()
            key = screen.getch()
            if key in (ord('h'), ord('H'), curses.KEY_F1):
                self.help()
                continue
            if self.pending or key in (3, 27, ord('q'), ord('Q')):
                self.pending = False
                return False
            if key in (curses.KEY_UP, curses.KEY_DOWN, curses.KEY_LEFT, curses.KEY_RIGHT):
                selected = 1 - selected
            elif key in (10, 13, curses.KEY_ENTER):
                return selected == 1


def guarded_ui(screen, session, ui):
    wrapped = ConfirmScreen(screen, session)
    signal.signal(signal.SIGINT, wrapped.interrupt)
    try:
        return ui(wrapped, session)
    finally:
        # Final cleanup must not be interrupted by another accidental Ctrl+C.
        signal.signal(signal.SIGINT, signal.SIG_IGN)


def footer(screen, controls, help_label=True):
    """Reserve the last terminal row; keep help visible even in narrow windows."""
    if isinstance(screen, ConfirmScreen):
        screen.controls = controls
        screen = screen.screen
    height, width = screen.getmaxyx()
    if height < 1 or width < 2:
        return
    text = ('H помощ • ' if help_label else '') + controls
    try:
        screen.addnstr(height - 1, 0, text.ljust(width - 1), width - 1, curses.A_REVERSE)
    except curses.error:
        pass


def help_steps(session=None):
    base = session.destination.parent if session is not None else Path(__file__).resolve().parent
    return [
        'Използвай за собствена мрежа или с разрешение от собственика. Парола може да се намери само ако проверените кандидати я включват.',
        '1. Стартирай мониторинг. От главното меню избери „Всички пакети (dumpcap)“. В „Канал“ избери канала на твоята мрежа, след това „Старт“. Записва се само избраният канал.',
        'Остави записването да работи, докато твое устройство се свърже нормално към Wi-Fi. Следи за „ГОТОВ (hcx)“; това означава приети данни, а не намерена парола.',
        'По време на мониторинга файловете са във временна папка /var/tmp/.recording-…; точният път е на екрана. Натисни „Стоп“, за да се приберат .pcapng файловете в: ' + str(base / 'captures'),
        '2. Анализирай. Върни се в главното меню → „Анализ на записи“ → избери серията → „Всички от серията“ или отделен файл. Изчакай анализа.',
        'Архив: в Анализ и Готови набори K отваря архива, A мести избраното веднага. В архива A възстановява. Редът Архив е най-долу. Архивираните записи не се проверяват автоматично за готовност. [Извлечени] показва вече извлечени данни; при частична серия се вижда броят.',
        '3. Извлечи готовите данни. В резултата избери „Готови за hashcat 22000 … • извлечи“. Те се записват в ' + str(base / 'data/ready') + '/<набор>/wpa.22000. Ако готовите записи са 0, направи нов мониторинг на правилния канал; речникът няма да поправи липсващ запис.',
        '„Кеш / частични данни“ записва оригинали и таблици в ' + str(base / 'data/cache') + '. Кешът е за преглед и не се избира като готов набор за hashcat.',
        '4. Подготви речник. От „Речници — изтегляне“ избери списък и изчакай проверката SHA-256. Готовите текстови файлове са в ' + str(base / 'wordlists') + '. Може да използваш и свой файл с една възможна парола на ред.',
        '5. Пусни проверката. Главно меню → „Hashcat“ → „Нова проверка“ → готов набор → речник или налична маска → „Старт“. Речникът проверява само своите думи. Маските генерират комбинации по шаблон, без речник; големите пространства могат да отнемат много дълго време.',
        '6. Виж резултата. Намерената парола се показва на екрана. Пълните резултати са в ' + str(base / 'data/hashcat') + '/<задача>/recovered.txt, а логовете в ' + str(base / 'log') + '. „Изчерпан“ означава, че избраните кандидати са проверени, не че има повреда.',
        'Hashcat: S обновява статистиката; P пауза; R продължи; B пропусни текущия шаблон след потвърждение. C/Q/Esc запазва и спира при следващия checkpoint. Изчакай потвърждението за край. V показва/скрива намерената парола; преди старт има настройка Без заспиване.',
        'Отхвърлени са кандидати, които не отговарят на ограниченията (например дължина); това не е броят на грешните пароли. Новите речникови задачи използват отделно копие с 8–63 байта на кандидат.',
        '7. При нужда продължи. „Hashcat“ → „Предишни задачи / резултати / възобновяване“ → задача → „Покажи намерени пароли“ или „Възобнови от checkpoint“. Възобновяване е възможно само при наличен checkpoint и непроменени входни файлове.',
        'H/h отваря тази помощ. В полето за път използвай главно H или F1 за помощ; малко h се въвежда като текст. Помощта не спира текущото записване, анализ, изтегляне или hashcat. Q/Esc затваря помощта и връща към същия екран.'
    ]


# Context-local navigation is restored even when a dialog fails or is cancelled.
from contextvars import ContextVar
from functools import wraps
from inspect import signature

_navigation = ContextVar('wifi_navigation', default=())


def breadcrumb(title):
    parts = ['Главно меню', *_navigation.get()]
    title = ''.join(c if c.isprintable() else ' ' for c in str(title))
    if title.startswith('Главно меню'):
        return title
    if title and title != parts[-1]:
        parts.append(title)
    return ' › '.join(parts)


def navigation(label):
    """Scope a screen's location; callable labels receive bound arguments."""
    def decorate(function):
        sig = signature(function)
        @wraps(function)
        def wrapped(*args, **kwargs):
            arguments = sig.bind(*args, **kwargs)
            arguments.apply_defaults()
            value = label(arguments.arguments) if callable(label) else label
            token = _navigation.set((*_navigation.get(), str(value)))
            try:
                return function(*args, **kwargs)
            finally:
                _navigation.reset(token)
        return wrapped
    return decorate


def capture_location(arguments):
    paths = arguments['paths']
    numbers = sorted({p.name.split('_')[0] for p in paths})
    return 'Сесия ' + ', '.join(numbers) + (' • архив' if arguments.get('archived') else '')
