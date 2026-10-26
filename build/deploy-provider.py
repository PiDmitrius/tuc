"""Memory-only provider fixture, isolated from the TUC container."""
import ctypes
import os
import resource
import socket
import sys

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
if ctypes.CDLL(None).prctl(4, 0, 0, 0, 0) != 0:
    raise RuntimeError("cannot disable provider dumps")
path = "/run/provider.sock"
if sys.argv[1] == "hold":
    secret = bytearray()
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(path)
    os.chmod(path, 0o600)
    listener.listen()
    try:
        while True:
            connection, _ = listener.accept()
            with connection:
                operation = connection.recv(1)
                if operation == b"I" and not secret:
                    candidate = bytearray()
                    while data := connection.recv(45):
                        candidate.extend(data)
                        if len(candidate) > 44:
                            break
                    if len(candidate) == 44 and candidate[-1] == 10:
                        secret.extend(candidate)
                        connection.sendall(b"ready")
                    candidate[:] = bytes(len(candidate))
                elif operation == b"G" and secret:
                    connection.sendall(secret)
    finally:
        secret[:] = bytes(len(secret))
else:
    with socket.socket(socket.AF_UNIX) as connection:
        connection.connect(path)
        if sys.argv[1] == "put":
            candidate = bytearray(sys.stdin.buffer.read(45))
            connection.sendall(b"I" + candidate)
            candidate[:] = bytes(len(candidate))
            connection.shutdown(socket.SHUT_WR)
        else:
            connection.sendall(b"G")
        while data := connection.recv(128):
            sys.stdout.buffer.write(data)
