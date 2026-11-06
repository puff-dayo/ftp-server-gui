import asyncio
import errno
import ipaddress
import logging
import os
import ssl
import stat
import time
from pathlib import Path, PurePosixPath

import aioftp
from aioftp import errors
from aioftp.server import ConnectionConditions, PathConditions, PathPermissions, worker

from vfs import normalize_mappings

LOG = logging.getLogger(__name__)


def _under(path, root):
    try:
        return os.path.commonpath((os.path.normcase(path), os.path.normcase(root))) == os.path.normcase(root)
    except ValueError:
        return False


class MountTable:
    def __init__(self, mappings, namespace):
        self.mappings = normalize_mappings(mappings, require_existing=True)
        self.namespace = Path(namespace).resolve()
        self.created_at = time.time()

    def virtual(self, pseudo):
        p = Path(pseudo).resolve(strict=False)
        if not _under(str(p), str(self.namespace)):
            raise PermissionError("Outside FTP namespace")
        rel = p.relative_to(self.namespace)
        return PurePosixPath("/", *rel.parts)

    def children(self, virtual):
        prefix = str(virtual).rstrip("/") + "/"
        names = {}
        for mount in self.mappings:
            p = mount.virtual_path
            if p.startswith(prefix) and p != str(virtual):
                name = p[len(prefix):].split("/", 1)[0]
                names.setdefault(name.casefold(), name)
        return list(names.values())

    def resolve(self, pseudo):
        virtual = self.virtual(pseudo)
        v = str(virtual)
        for mount in self.mappings:
            base = mount.virtual_path
            if base == "/" or v == base or v.startswith(base + "/"):
                suffix = v[len(base):].lstrip("/") if base != "/" else v.lstrip("/")
                local = os.path.abspath(
                    os.path.join(mount.local_path, *suffix.split("/"))) if suffix else os.path.abspath(mount.local_path)
                if not _under(os.path.realpath(local), os.path.realpath(mount.local_path)):
                    raise PermissionError("Path escapes virtual mount")
                return virtual, local, mount
        return virtual, None, None

    def synthetic_stat(self):
        mode = stat.S_IFDIR | 0o555
        return os.stat_result((mode, 0, 0, 1, 0, 0, 0, self.created_at, self.created_at, self.created_at))

    def info(self, pseudo):
        virtual, local, mount = self.resolve(pseudo)
        children = self.children(virtual)
        if children and (not local or not os.path.isdir(local)):
            return self.synthetic_stat()
        if local and os.path.exists(local):
            return os.stat(local)
        if children or virtual == PurePosixPath("/"):
            return self.synthetic_stat()
        raise FileNotFoundError(str(virtual))

    def list(self, pseudo):
        virtual, local, mount = self.resolve(pseudo)
        children = self.children(virtual)
        if not children and not local:
            raise FileNotFoundError(str(virtual))
        if local and os.path.isfile(local) and not children:
            raise NotADirectoryError(str(virtual))
        names = {n.casefold(): n for n in children}
        if local and os.path.isdir(local):
            for n in os.listdir(local):
                names.setdefault(n.casefold(), n)
        return [Path(pseudo) / name for name in names.values()]

    def writable(self, pseudo, *, source=False):
        virtual, local, mount = self.resolve(pseudo)
        if not mount or virtual == PurePosixPath(mount.virtual_path) or self.children(virtual):
            raise PermissionError("Virtual mount roots and containers are protected")
        return local, mount


class MappedPathIO(aioftp.PathIO):
    table = None

    def _table(self):
        return type(self).table

    async def exists(self, path):
        try:
            self._table().info(path)
            return True
        except (FileNotFoundError, NotADirectoryError):
            return False

    async def is_dir(self, path):
        try:
            return stat.S_ISDIR(self._table().info(path).st_mode)
        except (FileNotFoundError, NotADirectoryError):
            return False

    async def is_file(self, path):
        try:
            return stat.S_ISREG(self._table().info(path).st_mode)
        except (FileNotFoundError, NotADirectoryError):
            return False

    async def stat(self, path):
        return self._table().info(path)

    async def list(self, path):
        for entry in self._table().list(path):
            yield entry

    async def _open(self, path, mode="rb", **kwargs):
        table = self._table()
        if any(x in mode for x in "wa+"):
            local, _ = table.writable(path)
        else:
            virtual, local, _ = table.resolve(path)
            if not local or table.children(virtual) and not os.path.isfile(local):
                raise IsADirectoryError(str(virtual))
        return open(local, mode, **kwargs)

    async def mkdir(self, path, *, parents=False, exist_ok=False):
        local, _ = self._table().writable(path)
        os.makedirs(local, exist_ok=exist_ok) if parents else os.mkdir(local)

    async def rmdir(self, path):
        local, _ = self._table().writable(path)
        os.rmdir(local)

    async def unlink(self, path):
        local, _ = self._table().writable(path)
        os.unlink(local)

    async def rename(self, source, destination):
        src, mount_a = self._table().writable(source)
        dst, mount_b = self._table().writable(destination)
        if mount_a != mount_b:
            raise OSError(errno.EXDEV, "Cannot rename across virtual mounts")
        os.rename(src, dst)
        return destination


class _ActivePlaceholder:
    sockets = ()

    def close(self):
        pass


class LANFTPServer(aioftp.Server):
    def __init__(self, *args, tls_context=None, tls_require_ctrl=True, tls_require_data=True,
                 allowed_networks=None, log_callback=None, **kwargs):
        super().__init__(*args, ssl=None, **kwargs)
        self.tls_context = tls_context
        self.tls_require_ctrl = tls_require_ctrl
        self.tls_require_data = tls_require_data
        self.allowed_networks = allowed_networks
        self.log_callback = log_callback or (lambda message: None)
        self._clients = {}
        self.commands_mapping.update({
            "feat": self.feat, "opts": self.opts, "noop": self.noop,
            "size": self.size, "mdtm": self.mdtm, "clnt": self.clnt,
            "port": self.port, "eprt": self.eprt, "nlst": self.nlst,
        })

    async def dispatcher(self, reader, writer):
        peer = writer.get_extra_info("peername")
        host = peer[0] if peer else ""
        try:
            ip = ipaddress.ip_address(host)
            if self.allowed_networks and not any(ip in n for n in self.allowed_networks):
                writer.write(b"421 Access denied\r\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return
        except ValueError:
            writer.close()
            return
        count = self._clients.get(host, 0)
        if count >= 5:
            writer.write(b"421 Too many connections from your IP\r\n")
            await writer.drain()
            writer.close()
            return
        self._clients[host] = count + 1
        self.log_callback(f"Connected: {host}")
        try:
            await super().dispatcher(reader, writer)
        finally:
            self._clients[host] -= 1
            if not self._clients[host]:
                del self._clients[host]
            self.log_callback(f"Disconnected: {host}")

    async def parse_command(self, stream, censor_commands=("pass",)):
        while True:
            command, rest = await super().parse_command(stream, censor_commands)
            encrypted = stream.writer.get_extra_info("ssl_object") is not None
            if command == "auth":
                if self.tls_context is None:
                    await stream.write(b"502 TLS disabled\r\n")
                elif encrypted:
                    await stream.write(b"503 Already using TLS\r\n")
                elif rest.upper() not in ("TLS", "SSL"):
                    await stream.write(b"504 Unsupported AUTH mechanism\r\n")
                else:
                    await stream.write(b"234 Proceed with TLS negotiation\r\n")
                    await stream.start_tls(self.tls_context, None)
                continue
            if command in ("pbsz", "prot") and not encrypted:
                await stream.write(b"503 AUTH TLS required\r\n")
                continue
            if self.tls_context and self.tls_require_ctrl and not encrypted and command not in ("quit", "feat", "noop",
                                                                                                "syst"):
                await stream.write(b"534 TLS required for control channel\r\n")
                continue
            connection = self.connections.get(stream)
            if connection is not None and self.tls_context and self.tls_require_data and command in (
                    "pasv", "epsv", "port", "eprt", "retr", "stor", "appe", "list", "mlsd", "nlst"
            ) and not ("prot_private" in connection and connection.prot_private):
                await stream.write(b"534 PROT P required for data channel\r\n")
                continue
            if connection is not None and command in ("retr", "stor", "appe", "list", "mlsd", "nlst"):
                if "active_target" in connection:
                    try:
                        await self._connect_active(connection)
                    except (OSError, asyncio.TimeoutError, ssl.SSLError):
                        await stream.write(b"425 Active data connection failed\r\n")
                        continue
            if connection is not None and command in ("retr", "stor", "appe", "list", "mlsd", "nlst", "dele", "mkd",
                                                      "rmd", "rnfr", "rnto"):
                self.log_callback(f"FTP {command.upper()} {rest}")
            return command, rest

    async def user(self, connection, rest):
        result = await super().user(connection, rest)
        if "user" not in connection:
            count = connection.login_failures + 1 if "login_failures" in connection else 1
            connection.login_failures = count
            if count >= 3:
                connection.response("421", "Too many login attempts")
                return False
        return result

    async def pass_(self, connection, rest):
        result = await super().pass_(connection, rest)
        if "logged" not in connection or not connection.logged:
            count = connection.login_failures + 1 if "login_failures" in connection else 1
            connection.login_failures = count
            if count >= 3:
                connection.response("421", "Too many login attempts")
                return False
        return result

    async def _connect_active(self, connection):
        host, port = connection.active_target
        if "data_connection" in connection:
            connection.data_connection.close()
            del connection.data_connection
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10)
        try:
            if self.tls_context and "prot_private" in connection and connection.prot_private:
                loop = asyncio.get_running_loop()
                transport = await asyncio.wait_for(
                    loop.start_tls(writer.transport, writer._protocol, self.tls_context, server_side=True),
                    timeout=10,
                )
                writer._transport = transport
            connection.data_connection = aioftp.ThrottleStreamIO(
                reader, writer, throttles=connection.command_connection.throttles,
                timeout=connection.socket_timeout,
            )
        except Exception:
            writer.close()
            raise

    async def port(self, connection, rest):
        if "logged" not in connection or not connection.logged:
            connection.response("530", "Login required")
            return True
        try:
            parts = [int(n) for n in str(rest).split(",")]
            if len(parts) != 6 or any(n < 0 or n > 255 for n in parts):
                raise ValueError
            ip = str(ipaddress.IPv4Address(bytes(parts[:4])))
            port = parts[4] * 256 + parts[5]
        except (ValueError, ipaddress.AddressValueError):
            connection.response("501", "Invalid PORT address")
            return True
        return await self._set_active(connection, ip, port)

    async def eprt(self, connection, rest):
        if "logged" not in connection or not connection.logged:
            connection.response("530", "Login required")
            return True
        try:
            arg = str(rest)
            sep = arg[0]
            fields = arg.split(sep)
            if len(fields) != 5 or fields[0] or fields[-1] or fields[1] not in ("1", "2"):
                raise ValueError
            addr = ipaddress.ip_address(fields[2])
            if addr.version != int(fields[1]):
                raise ValueError
            port = int(fields[3])
        except (ValueError, IndexError):
            connection.response("501", "Invalid EPRT address")
            return True
        return await self._set_active(connection, str(addr), port)

    @staticmethod
    async def _set_active(self, connection, host, port):
        if host != connection.client_host or not 1024 <= port <= 65535:
            connection.response("501", "PORT/EPRT target must be the client address")
            return True
        if "passive_server" in connection:
            connection.passive_server.close()
            del connection.passive_server
        if "data_connection" in connection:
            connection.data_connection.close()
            del connection.data_connection
        connection.passive_server = _ActivePlaceholder()
        connection.active_target = (host, port)
        connection.response("200", "Active connection configured")
        return True

    async def pasv(self, connection, rest):
        if "active_target" in connection:
            del connection.active_target
            if "passive_server" in connection:
                del connection.passive_server
        return await super().pasv(connection, rest)

    async def epsv(self, connection, rest):
        if "active_target" in connection:
            del connection.active_target
            if "passive_server" in connection:
                del connection.passive_server
        return await super().epsv(connection, rest)

    async def pbsz(self, connection, rest):
        if str(rest).strip() != "0":
            connection.response("501", "PBSZ must be 0")
        else:
            connection.pbsz_seen = True
            connection.response("200", "PBSZ=0")
        return True

    async def prot(self, connection, rest):
        if "pbsz_seen" not in connection or not connection.pbsz_seen:
            connection.response("503", "PBSZ 0 required first")
        elif str(rest).upper() == "P":
            connection.prot_private = True
            connection.response("200", "Data channel protected")
        elif str(rest).upper() == "C" and not self.tls_require_data:
            connection.prot_private = False
            connection.response("200", "Data channel clear")
        else:
            connection.response("534", "Requested protection unavailable")
        return True

    async def _start_passive_server(self, connection, handler_callback):
        tls = self.tls_context if "prot_private" in connection and connection.prot_private else None
        if self.available_data_ports is not None:
            viewed = set()
            while True:
                try:
                    priority, port = self.available_data_ports.get_nowait()
                    if port in viewed:
                        raise errors.NoAvailablePort
                    viewed.add(port)
                    try:
                        server = await asyncio.start_server(handler_callback, connection.server_host, port, ssl=tls)
                    except OSError as exc:
                        self.available_data_ports.put_nowait((priority + 1, port))
                        if exc.errno == errno.EADDRINUSE:
                            continue
                        raise
                    connection.passive_server_port = port
                    return server
                except asyncio.QueueEmpty:
                    raise errors.NoAvailablePort
        return await asyncio.start_server(handler_callback, connection.server_host, connection.passive_server_port,
                                          ssl=tls)

    @ConnectionConditions(
        ConnectionConditions.login_required,
        ConnectionConditions.passive_server_started,
    )
    @PathConditions(PathConditions.path_must_exists)
    @PathPermissions(PathPermissions.readable)
    async def nlst(self, connection, rest):
        real_path, _ = self.get_paths(connection, rest or ".")

        @ConnectionConditions(
            ConnectionConditions.data_connection_made,
            wait=True,
            fail_code="425",
            fail_info="Cannot open data connection",
        )
        @worker
        async def transfer(server, conn, ignored):
            stream = conn.data_connection
            del conn.data_connection
            async with stream:
                if await conn.path_io.is_dir(real_path):
                    async for item in conn.path_io.list(real_path):
                        await stream.write((item.name + "\r\n").encode(server.encoding))
                else:
                    await stream.write((real_path.name + "\r\n").encode(server.encoding))
            conn.response("226", "Transfer complete")
            return True

        task = asyncio.create_task(transfer(self, connection, rest))
        connection.extra_workers.add(task)
        connection.response("150", "Opening data connection")
        return True

    async def feat(self, connection, rest):
        features = ["UTF8", "EPSV", "PASV", "EPRT", "PORT", "NLST", "MLST Type*;Size*;Modify*;", "MLSD", "REST STREAM",
                    "SIZE", "MDTM"]
        if self.tls_context:
            features.extend(("AUTH TLS", "PBSZ", "PROT"))
        connection.response("211", ["Features", *features, "End"], True)
        return True

    async def opts(self, connection, rest):
        if str(rest).upper().strip() == "UTF8 ON":
            connection.response("200", "UTF8 enabled")
        else:
            connection.response("501", "Unsupported option")
        return True

    async def noop(self, connection, rest):
        connection.response("200", "OK")
        return True

    async def clnt(self, connection, rest):
        connection.response("200", "OK")
        return True

    async def size(self, connection, rest):
        if not ("logged" in connection and connection.logged):
            connection.response("530", "Login required")
            return True
        path, _ = self.get_paths(connection, rest)
        if await connection.path_io.is_file(path):
            info = await connection.path_io.stat(path)
            connection.response("213", str(info.st_size))
        else:
            connection.response("550", "Not a file")
        return True

    async def mdtm(self, connection, rest):
        if not ("logged" in connection and connection.logged):
            connection.response("530", "Login required")
            return True
        path, _ = self.get_paths(connection, rest)
        if await connection.path_io.exists(path):
            info = await connection.path_io.stat(path)
            connection.response("213", time.strftime("%Y%m%d%H%M%S", time.gmtime(info.st_mtime)))
        else:
            connection.response("550", "Path missing")
        return True


def make_server(*, username, password, mappings, namespace, read_only, ftps_enabled,
                cert_file, key_file, tls_require_ctrl, tls_require_data,
                allowed_networks, log_callback):
    table = MountTable(mappings, namespace)

    class ConfiguredPathIO(MappedPathIO):
        pass

    ConfiguredPathIO.table = table
    user = aioftp.User(
        username, password, base_path=table.namespace, home_path="/",
        permissions=(aioftp.Permission("/", readable=True, writable=not read_only),),
        maximum_connections=5,
    )
    tls = None
    if ftps_enabled:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return LANFTPServer(
        [user], block_size=128 * 1024, path_io_factory=ConfiguredPathIO,
        maximum_connections=64, tls_context=tls,
        tls_require_ctrl=tls_require_ctrl, tls_require_data=tls_require_data,
        allowed_networks=allowed_networks, log_callback=log_callback,
    )
