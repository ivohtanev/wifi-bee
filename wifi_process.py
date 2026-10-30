"""Owned subprocesses with cancellation and bounded, reaped shutdown."""
import os
import signal
import subprocess
import threading


def terminate(proc):
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()


class Processes:
    def __init__(self):
        self.cancelled = threading.Event()
        self.lock = threading.Lock()
        self.children = set()

    def popen(self, args, **kwargs):
        with self.lock:
            if self.cancelled.is_set():
                raise RuntimeError('Анализът е отменен.')
            proc = subprocess.Popen(args, start_new_session=True, **kwargs)
            self.children.add(proc)
            return proc

    def release(self, proc):
        with self.lock:
            self.children.discard(proc)

    def run(self, args, timeout=90, **kwargs):
        if kwargs.pop('capture_output', False):
            kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc = self.popen(args, **kwargs)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            return subprocess.CompletedProcess(args, proc.returncode, stdout, stderr)
        finally:
            terminate(proc)
            self.release(proc)

    def close(self):
        with self.lock:
            self.cancelled.set()
            children = list(self.children)
        for proc in children:
            terminate(proc)
