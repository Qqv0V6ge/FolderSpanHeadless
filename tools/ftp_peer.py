"""Isolated stdlib FTP/explicit-FTPS peer for host conformance tests."""
import argparse
import hashlib
import json
import posixpath
import socket
import socketserver
import ssl
import threading
import traceback
from pathlib import Path

DATA = bytes(range(256)) * 8192 + b"tail"

class Peer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    def __init__(self, encoding="utf-8", cert=None, key=None, record=None):
        self.encoding = encoding
        self.context = None
        if cert:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain(cert, key)
        self.record_path = Path(record) if record else None
        self.lock = threading.Lock()
        self.records = []
        self.files = {"/data.bin": DATA, "/中文 &.txt": b"unicode", "/existing": b"keep", "/.hidden": b"hidden"}
        self.directories = {"/", "/child"}
        super().__init__(("127.0.0.1", 0), Handler)
    def record(self, **entry):
        with self.lock:
            self.records.append(entry)
            if self.record_path:
                with self.record_path.open("a", encoding="utf-8") as output:
                    output.write(json.dumps(entry, ensure_ascii=False) + "\n")

class Handler(socketserver.StreamRequestHandler):
    def line(self, text):
        self.wfile.write((text + "\r\n").encode(self.server.encoding))
        self.wfile.flush()
    def path(self, value):
        return posixpath.normpath("/" + value.lstrip("/"))
    def data_connection(self):
        if self.passive:
            conn, _ = self.passive.accept()
            self.passive.close()
            self.passive = None
        else:
            conn = socket.create_connection(self.active, timeout=10)
        conn.settimeout(10)
        if self.private:
            conn = self.server.context.wrap_socket(conn, server_side=True, suppress_ragged_eofs=False)
        return conn
    def close_tls(self, conn):
        try:
            conn.unwrap().close()
        except (ConnectionError, ssl.SSLEOFError):
            # Java may close TCP after close_notify without reading the server's TLS 1.3 tickets.
            pass
    def transfer(self, command, arg):
        target = self.path(arg.removeprefix("-a "))
        if command == "RETR" and target not in self.server.files and target != "/slow":
            self.line("550 Not found")
            return
        if command == "LIST" and target == "/bad-list":
            body = b"not a supported directory entry\r\n"
        elif command == "LIST":
            lines = []
            if target == "/":
                with self.server.lock:
                    for directory in sorted(self.server.directories - {"/"}):
                        if posixpath.dirname(directory) == "/":
                            lines.append(f"drwxr-xr-x 1 user group 0 Jan 1 2020 {directory[1:]}")
                    for name, data in sorted(self.server.files.items()):
                        if posixpath.dirname(name) == "/":
                            lines.append(f"-rw-r--r-- 1 user group {len(data)} Jan 1 2020 {name[1:]}")
                lines.append("lrwxrwxrwx 1 user group 4 Jan 1 2020 link -> /outside")
                lines.append("-rw-r--r-- 1 user group 0 Jan 1 2020 ..")
            elif target == "/paged":
                lines = [f"-rw-r--r-- 1 user group 0 Jan 1 2020 f{i:03}.txt" for i in range(300)]
            body = ("\r\n".join(lines) + "\r\n").encode(self.server.encoding, errors="replace")
        else:
            body = self.server.files.get(target, b"")
        self.line("150 Opening data connection")
        with self.data_connection() as conn:
            self.server.record(operation="DATA_TLS", secure=isinstance(conn, ssl.SSLSocket), path=target)
            if command == "STOR":
                received = bytearray()
                while True:
                    try:
                        part = conn.recv(65536)
                    except ssl.SSLEOFError:
                        # The fixture checks committed payload hashes; Java FTPS may end TLS without close_notify.
                        self.server.record(operation="TLS_RAGGED_EOF", path=target)
                        break
                    if not part:
                        break
                    received.extend(part)
                    if len(received) > 16 * 1024 * 1024:
                        raise ValueError("fixture upload limit")
                self.server.files[target] = bytes(received)
                self.server.record(operation="STOR_COMPLETE", path=target, size=len(received),
                                   sha256=hashlib.sha256(received).hexdigest())
                if isinstance(conn, ssl.SSLSocket):
                    self.close_tls(conn)
            elif target == "/slow":
                while conn.recv(1):
                    pass
            else:
                conn.sendall(body)
                if isinstance(conn, ssl.SSLSocket):
                    self.close_tls(conn)
        self.line("426 Uncertain write" if target == "/uncertain" else "226 Transfer complete")
    def handle(self):
        self.passive = None
        self.active = None
        self.private = False
        self.renaming = None
        self.copying = None
        self.line("220-Local conformance peer")
        self.line("220 Ready")
        try:
            while True:
                raw = self.rfile.readline(65537)
                if not raw:
                    break
                if len(raw) > 65536:
                    break
                line = raw.rstrip(b"\r\n").replace(b"\xff\xff", b"\xff").decode(self.server.encoding, errors="replace")
                command, _, arg = line.partition(" ")
                command = command.upper()
                self.server.record(operation=command, argument="[redacted]" if command == "PASS" else arg)
                if command == "AUTH":
                    if not self.server.context:
                        self.line("502 TLS unavailable")
                        continue
                    self.line("234 Start TLS")
                    self.rfile.close()
                    self.wfile.close()
                    self.connection = self.server.context.wrap_socket(self.connection, server_side=True)
                    self.rfile = self.connection.makefile("rb")
                    self.wfile = self.connection.makefile("wb")
                elif command == "USER":
                    self.line("331 Password required")
                elif command == "PASS":
                    self.line("230 Logged in" if arg == "secret" or arg == "" else "530 Login rejected")
                elif command == "FEAT":
                    self.line("211-Features")
                    self.line(" UTF8")
                    self.line("211 End")
                elif command == "SYST":
                    self.line("215 UNIX Type: L8")
                elif command == "PBSZ":
                    self.line("200 Buffer size accepted")
                elif command == "PROT":
                    self.private = arg == "P"
                    self.line("200 Protection enabled")
                elif command in ("TYPE", "OPTS", "NOOP", "CWD"):
                    self.line("200 OK")
                elif command in ("PASV", "EPSV"):
                    if self.passive:
                        self.passive.close()
                    self.passive = socket.socket()
                    self.passive.bind(("127.0.0.1", 0))
                    self.passive.listen()
                    self.passive.settimeout(10)
                    port = self.passive.getsockname()[1]
                    self.line(f"227 Entering Passive Mode (127,0,0,1,{port//256},{port%256})" if command == "PASV" else f"229 Entering Extended Passive Mode (|||{port}|)")
                elif command in ("PORT", "EPRT"):
                    if command == "PORT":
                        parts = list(map(int, arg.split(",")))
                        self.active = (".".join(map(str, parts[:4])), parts[4]*256 + parts[5])
                    else:
                        _, family, host, port, _ = arg.split(arg[0])
                        self.active = (host, int(port))
                    self.line("200 Active data endpoint")
                elif command in ("LIST", "RETR", "STOR"):
                    self.transfer(command, arg)
                elif command == "MKD":
                    self.server.directories.add(self.path(arg))
                    self.line('257 "directory" created')
                elif command == "RMD":
                    path = self.path(arg)
                    if path in self.server.directories and path != "/":
                        self.server.directories.remove(path)
                        self.line("250 Removed")
                    else:
                        self.line("550 Cannot remove directory")
                elif command == "DELE":
                    path = self.path(arg)
                    if path in self.server.files:
                        del self.server.files[path]
                        self.line("250 Deleted")
                    else:
                        self.line("550 Not found")
                elif command == "RNFR":
                    self.renaming = self.path(arg)
                    self.line("350 Rename destination required")
                elif command == "RNTO":
                    self.server.files[self.path(arg)] = self.server.files.pop(self.renaming, b"")
                    self.line("250 Renamed")
                elif command == "SITE" and arg.startswith("CPFR "):
                    self.copying = self.path(arg[5:])
                    self.line("502 Server copy unsupported" if self.copying == "/unsupported-copy" else "350 Copy destination required")
                elif command == "SITE" and arg.startswith("CPTO "):
                    self.server.files[self.path(arg[5:])] = self.server.files.get(self.copying, b"")
                    self.line("250 Copied")
                elif command == "QUIT":
                    self.line("221 Bye")
                    break
                else:
                    self.line("502 Unsupported")
        except (ConnectionError, OSError, ssl.SSLError) as error:
            self.server.record(operation="PEER_ERROR", error=repr(error), trace=traceback.format_exc())
        finally:
            if self.passive:
                self.passive.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--encoding", default="utf-8")
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--record")
    args = parser.parse_args()
    with Peer(args.encoding, args.cert, args.key, args.record) as server:
        print(json.dumps({"port": server.server_address[1]}), flush=True)
        server.serve_forever()
