"""Small root broker: fixed radio commands, no analysis or user-file writes."""
import array
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess

from wifi_storage import no_symlinks


def drop_privileges(account):
    if account.pw_uid == 0:
        raise ValueError('Избери обикновен потребител чрез --owner USER.')
    os.initgroups(account.pw_name, account.pw_gid)
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)
    os.environ.update(HOME=account.pw_dir, USER=account.pw_name, LOGNAME=account.pw_name)
    for name in ('SUDO_UID', 'SUDO_GID', 'SUDO_USER', 'SUDO_COMMAND'):
        os.environ.pop(name, None)


def stop_child(proc):
    if proc is None or proc.poll() is not None:
        return
    for sig, wait in ((signal.SIGINT, 8), (signal.SIGTERM, 2), (signal.SIGKILL, 2)):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            break
        try:
            proc.wait(timeout=wait)
            break
        except subprocess.TimeoutExpired:
            continue
    proc.wait()


def broker(sock, uid, gid, interface):
    proc = None
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': '/'}
    os.chdir('/')
    try:
        while True:
            raw = sock.recv(16384)
            if not raw:
                break
            fd = None
            try:
                request = json.loads(raw)
                operation = request['op']
                if operation == 'start':
                    if proc is not None and proc.poll() is None:
                        raise ValueError('Вече има активен запис.')
                    path = no_symlinks(request['path'])
                    if (path.parent.parent != Path('/var/tmp') or
                        not path.parent.name.startswith('.recording-') or
                        path.parent.stat().st_uid != uid or path.suffix != '.pcapng' or
                        not re.fullmatch(r'[A-Za-z0-9_.-]+', path.name)):
                        raise ValueError('Невалидна capture папка.')
                    # Only dumpcap receives network capabilities; it runs as the owner.
                    command = ['/usr/bin/setpriv', '--reuid', str(uid), '--regid', str(gid),
                               '--clear-groups', '--inh-caps', '+net_raw,+net_admin',
                               '--ambient-caps', '+net_raw,+net_admin', '--',
                               '/usr/bin/dumpcap', '-i', interface, '-s', '0',
                               '-b', 'filesize:50000', '-b', 'duration:2000', '-w', str(path)]
                    if request.get('filtered'):
                        command += ['-f', 'not (type ctl subtype ack or type ctl subtype cts or type ctl subtype rts or type ctl subtype 0x90 or type ctl subtype 0x80 or type data subtype null or type data subtype qos)']
                    command = ['/usr/bin/systemd-inhibit', '--what=idle:sleep', '--mode=block',
                               '--who=Wi-Fi console', '--why=Active recording', '--no-ask-password', '--', *command]
                    if proc is not None and proc.stderr:
                        proc.stderr.close()
                    proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                            stderr=subprocess.PIPE, start_new_session=True, env=env)
                    fd = proc.stderr.fileno()
                    result = {'pid': proc.pid}
                elif operation == 'poll':
                    result = {'returncode': proc.poll() if proc else 0}
                elif operation == 'stop':
                    stop_child(proc)
                    result = {'returncode': proc.returncode if proc else 0}
                elif operation == 'channel':
                    if proc is not None and proc.poll() is None:
                        raise ValueError('Спри записа преди смяна на канала.')
                    frequency = int(request['frequency'])
                    if not 2000 <= frequency <= 8000:
                        raise ValueError('Невалидна честота.')
                    result = subprocess.run(['/usr/sbin/iw', 'dev', interface, 'set', 'freq', str(frequency)],
                                            capture_output=True, text=True, timeout=5, env=env)
                    if result.returncode:
                        raise RuntimeError(result.stderr.strip())
                    result = {}
                else:
                    raise ValueError('Непозната привилегирована операция.')
                payload = {'ok': result}
            except Exception as exc:
                payload = {'error': str(exc)}
            ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))] if fd is not None else []
            sock.sendmsg([json.dumps(payload).encode()], ancillary)
    finally:
        stop_child(proc)
        if proc is not None and proc.stderr:
            proc.stderr.close()
        sock.close()


class Radio:
    def __init__(self, account, interface):
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', interface):
            raise ValueError('Невалиден интерфейс.')
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        pid = os.fork()
        if pid == 0:
            parent.close()
            # The helper must survive terminal Ctrl+C; socket EOF performs cleanup.
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                broker(child, account.pw_uid, account.pw_gid, interface)
            finally:
                os._exit(0)
        child.close()
        self.sock, self.pid = parent, pid

    def request(self, operation, **kwargs):
        self.sock.send(json.dumps({'op': operation, **kwargs}).encode())
        data, ancillary, flags, address = self.sock.recvmsg(16384, socket.CMSG_SPACE(array.array('i').itemsize))
        if not data:
            raise RuntimeError('Привилегированият помощник е спрял.')
        reply = json.loads(data)
        if 'error' in reply:
            raise RuntimeError(reply['error'])
        fd = None
        for level, kind, content in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                received = array.array('i'); received.frombytes(content[:received.itemsize])
                fd = received[0]
        return reply['ok'], fd

    def start(self, path, filtered):
        result, fd = self.request('start', path=str(path), filtered=bool(filtered))
        return Capture(self, result['pid'], os.fdopen(fd, 'rb'))

    def close(self):
        self.sock.close()
        os.waitpid(self.pid, 0)


class Capture:
    def __init__(self, radio, pid, stderr):
        self.radio, self.pid, self.stderr = radio, pid, stderr
        self.returncode = None

    def poll(self):
        self.returncode = self.radio.request('poll')[0]['returncode']
        return self.returncode

    def stop(self):
        self.returncode = self.radio.request('stop')[0]['returncode']
