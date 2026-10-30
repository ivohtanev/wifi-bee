"""Shared interruption guard for every curses screen."""
import curses
import signal


class ConfirmScreen:
    def __init__(self, screen):
        self.screen = screen
        self.pending = False

    def __getattr__(self, name):
        return getattr(self.screen, name)

    def interrupt(self, signum, frame):
        self.pending = True

    def getch(self):
        key = self.screen.getch()
        if self.pending or key == 3:
            self.pending = False
            if self.confirm():
                raise KeyboardInterrupt
            return -1
        return key

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
            self.screen.refresh()

    def confirm(self):
        selected = 0
        screen = self.screen
        screen.timeout(200)
        while True:
            screen.erase()
            height, width = screen.getmaxyx()
            lines = ['Да спра ли програмата?',
                     'Активните задачи ще бъдат спрени, записите ще се запазят.',
                     'Enter потвърждава избора • Esc / Ctrl+C = Не',
                     ('▶ ' if selected == 0 else '  ') + 'Не — продължи',
                     ('▶ ' if selected == 1 else '  ') + 'Да — спри и запази']
            for row, line in enumerate(lines):
                if row < height - 1 and width > 2:
                    screen.addnstr(row, 1, line, width - 2,
                                   curses.A_REVERSE if row == selected + 3 else 0)
            screen.refresh()
            key = screen.getch()
            if self.pending or key in (3, 27, ord('q'), ord('Q')):
                self.pending = False
                return False
            if key in (curses.KEY_UP, curses.KEY_DOWN, curses.KEY_LEFT, curses.KEY_RIGHT):
                selected = 1 - selected
            elif key in (10, 13, curses.KEY_ENTER):
                return selected == 1


def guarded_ui(screen, session, ui):
    wrapped = ConfirmScreen(screen)
    signal.signal(signal.SIGINT, wrapped.interrupt)
    try:
        return ui(wrapped, session)
    finally:
        # Final cleanup must not be interrupted by another accidental Ctrl+C.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
