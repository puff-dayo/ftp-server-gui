import errno
import json
import os
import stat
import tempfile
import time
from dataclasses import dataclass
from typing import Iterable, Optional, Union, List, Set

from pyftpdlib.filesystems import AbstractedFS, FilesystemError


@dataclass(frozen=True)
class VirtualMapping:
    virtual_path: str
    local_path: str

    def to_dict(self):
        return {"virtual": self.virtual_path, "local": self.local_path}


_INVALID_VIRTUAL_CHARS = set('<>:"\\|?*')


def normalize_virtual_path(path: str) -> str:
    """Normalize a server-side path to an absolute FTP path."""
    text = (path or "/").strip().replace("\\", "/")
    if not text.startswith("/"):
        text = "/" + text

    parts = []
    for part in text.split("/"):
        if not part or part == ".":
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        if any(ord(ch) < 32 for ch in part) or any(ch in _INVALID_VIRTUAL_CHARS for ch in part):
            raise ValueError(f"Invalid character in server path segment: {part!r}")
        if part.endswith(" ") or part.endswith("."):
            raise ValueError("Server path segments cannot end with a space or dot.")
        parts.append(part)
    return "/" + "/".join(parts) if parts else "/"


def normalize_mappings(items: Iterable[Union[dict, VirtualMapping]], require_existing=True) -> List[VirtualMapping]:
    result: List[VirtualMapping] = []
    seen_virtual: Set[str] = set()

    for item in items or []:
        if isinstance(item, VirtualMapping):
            virtual = item.virtual_path
            local = item.local_path
        else:
            virtual = item.get("virtual", item.get("virtual_path", "/"))
            local = item.get("local", item.get("local_path", ""))

        virtual = normalize_virtual_path(virtual)
        local_text = str(local).strip()
        if not local_text:
            raise ValueError(f"Local path for {virtual} is empty.")
        local = os.path.abspath(os.path.expandvars(os.path.expanduser(local_text)))
        if virtual in seen_virtual:
            raise ValueError(f"Duplicate server path: {virtual}")
        if require_existing and not os.path.isdir(local):
            raise ValueError(f"Local directory does not exist: {local}")

        seen_virtual.add(virtual)
        result.append(VirtualMapping(virtual, local))

    # Longest virtual mount first makes nested mounts override parent mounts.
    result.sort(key=lambda m: (len(m.virtual_path), m.virtual_path), reverse=True)
    return result


def mappings_to_json(items: Iterable[Union[dict, VirtualMapping]]) -> str:
    mappings = normalize_mappings(items, require_existing=False)
    mappings.sort(key=lambda m: m.virtual_path)
    return json.dumps([m.to_dict() for m in mappings], ensure_ascii=False, separators=(",", ":"))


def mappings_from_json(raw: str, fallback_local: str = "") -> List[VirtualMapping]:
    raw = (raw or "").strip()
    if raw:
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return normalize_mappings(data, require_existing=False)
        except (TypeError, ValueError, json.JSONDecodeError):
            pass

    if fallback_local:
        return normalize_mappings([{"virtual": "/", "local": fallback_local}], require_existing=False)
    return []


class MappedVirtualFS(AbstractedFS):
    """pyftpdlib filesystem exposing multiple local directories as one FTP tree.

    The FTP namespace is represented by harmless pseudo paths underneath the
    authorizer home directory. Every filesystem operation is translated back
    to the configured mount before touching the real disk.
    """

    configured_mappings = []

    def __init__(self, root, cmd_channel):
        super().__init__(root, cmd_channel)
        self._namespace_root = os.path.abspath(root)
        self._mounts = normalize_mappings(self.configured_mappings, require_existing=True)
        self._created_at = time.time()

    # ---------- path conversion ----------
    def ftp2fs(self, ftppath):
        vpath = normalize_virtual_path(self.ftpnorm(ftppath))
        if vpath == "/":
            return self._namespace_root
        return os.path.normpath(os.path.join(self._namespace_root, vpath.lstrip("/").replace("/", os.sep)))

    def fs2ftp(self, fspath):
        path = os.path.abspath(fspath)
        vpath = self._virtual_from_pseudo(path)
        if vpath is not None:
            return vpath

        # Real file handles can expose their actual local path (e.g. transfers).
        # Reverse-map those paths to the most specific matching mount.
        matches = []
        for mount in self._mounts:
            if self._is_subpath(path, mount.local_path):
                matches.append(mount)
        if matches:
            mount = max(matches, key=lambda m: len(os.path.normcase(os.path.abspath(m.local_path))))
            rel = os.path.relpath(path, mount.local_path)
            if rel == ".":
                return mount.virtual_path
            suffix = rel.replace(os.sep, "/")
            return normalize_virtual_path(mount.virtual_path.rstrip("/") + "/" + suffix)
        return "/"

    def validpath(self, path):
        vpath = self._virtual_from_pseudo(path)
        if vpath is not None:
            kind, _, _ = self._resolve_virtual(vpath)
            return kind != "missing"
        return any(self._is_subpath(path, mount.local_path) for mount in self._mounts)

    def realpath(self, path):
        vpath = self._virtual_from_pseudo(path)
        if vpath is None:
            return os.path.realpath(path)
        kind, local, _ = self._resolve_virtual(vpath)
        if kind == "physical" and local:
            return os.path.realpath(local)
        return os.path.normpath(path)

    # ---------- AbstractedFS wrappers ----------
    def chdir(self, path):
        if not self.isdir(path):
            raise OSError(errno.ENOTDIR, "Not a directory", path)
        self.cwd = self.fs2ftp(path)

    def open(self, filename, mode):
        local, _ = self._require_physical(filename)
        if self._has_virtual_children(self.fs2ftp(filename)) and not os.path.isdir(local):
            raise OSError(errno.EISDIR, "Virtual container is a directory", filename)
        return open(local, mode)

    def mkstemp(self, suffix="", prefix="", dir=None, mode="wb"):
        pseudo_dir = dir if dir is not None else self.ftp2fs(self.cwd)
        local_dir, _ = self._require_physical(pseudo_dir)
        if not os.path.isdir(local_dir):
            raise OSError(errno.ENOTDIR, "Not a directory", pseudo_dir)

        text = "b" not in mode
        fd, local_name = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=local_dir, text=text)
        file_obj = os.fdopen(fd, mode)
        virtual_name = normalize_virtual_path(
            self.fs2ftp(pseudo_dir).rstrip("/") + "/" + os.path.basename(local_name)
        )
        pseudo_name = self.ftp2fs(virtual_name)

        class FileWrapper:
            def __init__(self, file_handle, exposed_name):
                self.file = file_handle
                self.name = exposed_name

            def __getattr__(self, attr):
                return getattr(self.file, attr)

            def __enter__(self):
                self.file.__enter__()
                return self

            def __exit__(self, exc_type, exc, tb):
                return self.file.__exit__(exc_type, exc, tb)

        return FileWrapper(file_obj, pseudo_name)

    def mkdir(self, path):
        self._reject_mount_root(path)
        local, _ = self._require_physical(path)
        os.mkdir(local)

    def listdir(self, path):
        vpath = self.fs2ftp(path)
        kind, local, _ = self._resolve_virtual(vpath)
        children = self._virtual_child_names(vpath)
        names: List[str] = []

        if kind == "physical" and local and os.path.isdir(local):
            names.extend(os.listdir(local))
        elif kind == "missing" and not children:
            raise OSError(errno.ENOENT, "No such file or directory", path)
        elif kind == "physical" and local and not os.path.isdir(local) and not children:
            raise OSError(errno.ENOTDIR, "Not a directory", path)

        # Virtual mount points shadow same-named physical entries.
        seen = set()
        merged = []
        child_set = set(children)
        for name in children + names:
            key = os.path.normcase(name)
            if key in seen:
                continue
            if name in names and any(os.path.normcase(name) == os.path.normcase(c) for c in child_set):
                if name not in child_set:
                    continue
            seen.add(key)
            merged.append(name)
        return merged

    def listdirinfo(self, path):
        return self.listdir(path)

    def rmdir(self, path):
        self._reject_mount_root(path)
        if self._has_virtual_children(self.fs2ftp(path)):
            raise OSError(errno.EACCES, "Directory contains virtual mount points", path)
        local, _ = self._require_physical(path)
        os.rmdir(local)

    def remove(self, path):
        self._reject_mount_root(path)
        if self._has_virtual_children(self.fs2ftp(path)):
            raise OSError(errno.EACCES, "Virtual container cannot be removed", path)
        local, _ = self._require_physical(path)
        os.remove(local)

    def rename(self, src, dst):
        self._reject_mount_root(src)
        if self._has_virtual_children(self.fs2ftp(src)):
            raise OSError(errno.EACCES, "Virtual container cannot be renamed", src)
        src_local, src_mount = self._require_physical(src)
        dst_local, dst_mount = self._require_physical(dst)
        if src_mount.virtual_path != dst_mount.virtual_path or os.path.normcase(src_mount.local_path) != os.path.normcase(dst_mount.local_path):
            raise OSError(errno.EXDEV, "Cannot rename across virtual mounts")
        os.rename(src_local, dst_local)

    def chmod(self, path, mode):
        local, _ = self._require_physical(path)
        if not hasattr(os, "chmod"):
            raise NotImplementedError
        return os.chmod(local, mode)

    def stat(self, path):
        return self._stat(path, follow_symlinks=True)

    def lstat(self, path):
        return self._stat(path, follow_symlinks=False)

    def utime(self, path, timeval):
        local, _ = self._require_physical(path)
        return os.utime(local, (timeval, timeval))

    def readlink(self, path):
        local, _ = self._require_physical(path)
        target = os.readlink(local)
        if os.path.isabs(target):
            mapped = self.fs2ftp(target)
            if mapped != "/" or any(os.path.normcase(target) == os.path.normcase(m.local_path) for m in self._mounts):
                return mapped
            return os.path.basename(target)
        return target.replace(os.sep, "/")

    def isfile(self, path):
        vpath = self.fs2ftp(path)
        if self._has_virtual_children(vpath):
            return False
        kind, local, _ = self._resolve_virtual(vpath)
        return kind == "physical" and bool(local) and os.path.isfile(local)

    def islink(self, path):
        vpath = self.fs2ftp(path)
        if self._has_virtual_children(vpath):
            return False
        kind, local, _ = self._resolve_virtual(vpath)
        return kind == "physical" and bool(local) and os.path.islink(local)

    def isdir(self, path):
        vpath = self.fs2ftp(path)
        children = self._virtual_child_names(vpath)
        kind, local, _ = self._resolve_virtual(vpath)
        if children:
            return True
        if kind == "synthetic":
            return True
        return kind == "physical" and bool(local) and os.path.isdir(local)

    def getsize(self, path):
        vpath = self.fs2ftp(path)
        kind, local, _ = self._resolve_virtual(vpath)
        if kind == "synthetic" or self._has_virtual_children(vpath) and (not local or not os.path.isfile(local)):
            return 0
        if kind != "physical" or not local:
            raise OSError(errno.ENOENT, "No such file or directory", path)
        return os.path.getsize(local)

    def getmtime(self, path):
        vpath = self.fs2ftp(path)
        kind, local, _ = self._resolve_virtual(vpath)
        if kind == "synthetic" or self._has_virtual_children(vpath) and (not local or not os.path.exists(local)):
            return self._created_at
        if kind != "physical" or not local:
            raise OSError(errno.ENOENT, "No such file or directory", path)
        return os.path.getmtime(local)

    def lexists(self, path):
        vpath = self.fs2ftp(path)
        kind, local, _ = self._resolve_virtual(vpath)
        if kind == "synthetic" or self._has_virtual_children(vpath):
            return True
        return kind == "physical" and bool(local) and os.path.lexists(local)

    # ---------- internal helpers ----------
    def _stat(self, path, follow_symlinks=True):
        vpath = self.fs2ftp(path)
        kind, local, _ = self._resolve_virtual(vpath)
        children = self._virtual_child_names(vpath)

        if kind == "physical" and local:
            if children and not os.path.isdir(local):
                return self._synthetic_dir_stat()
            try:
                return os.stat(local) if follow_symlinks else os.lstat(local)
            except FileNotFoundError:
                if children:
                    return self._synthetic_dir_stat()
                raise
        if kind == "synthetic" or children:
            return self._synthetic_dir_stat()
        raise OSError(errno.ENOENT, "No such file or directory", path)

    def _synthetic_dir_stat(self):
        mode = stat.S_IFDIR | 0o555
        return os.stat_result((mode, 0, 0, 1, 0, 0, 0, self._created_at, self._created_at, self._created_at))

    def _virtual_from_pseudo(self, path) -> Optional[str]:
        try:
            absolute = os.path.abspath(path)
        except TypeError:
            return None
        if not self._is_subpath(absolute, self._namespace_root):
            return None
        rel = os.path.relpath(absolute, self._namespace_root)
        if rel == ".":
            return "/"
        return normalize_virtual_path("/" + rel.replace(os.sep, "/"))

    def _resolve_virtual(self, vpath):
        vpath = normalize_virtual_path(vpath)
        mount = self._matching_mount(vpath)
        if mount is not None:
            rel = self._relative_virtual(vpath, mount.virtual_path)
            local = mount.local_path if not rel else os.path.join(mount.local_path, *rel.split("/"))
            local = self._safe_local(local, mount.local_path)
            return "physical", local, mount

        if vpath == "/" or self._has_virtual_children(vpath):
            return "synthetic", None, None
        return "missing", None, None

    def _matching_mount(self, vpath) -> Optional[VirtualMapping]:
        for mount in self._mounts:
            base = mount.virtual_path
            if base == "/":
                return mount
            if vpath == base or vpath.startswith(base + "/"):
                return mount
        return None

    def _relative_virtual(self, vpath, base):
        if base == "/":
            return vpath.lstrip("/")
        if vpath == base:
            return ""
        return vpath[len(base) + 1:]

    def _virtual_child_names(self, vpath) -> List[str]:
        vpath = normalize_virtual_path(vpath)
        names = []
        seen = set()
        for mount in self._mounts:
            mp = mount.virtual_path
            if mp == vpath:
                continue
            if vpath == "/":
                if mp == "/":
                    continue
                remainder = mp.lstrip("/")
            else:
                prefix = vpath + "/"
                if not mp.startswith(prefix):
                    continue
                remainder = mp[len(prefix):]
            if not remainder:
                continue
            name = remainder.split("/", 1)[0]
            key = os.path.normcase(name)
            if key not in seen:
                seen.add(key)
                names.append(name)
        names.sort(key=str.casefold)
        return names

    def _has_virtual_children(self, vpath) -> bool:
        return bool(self._virtual_child_names(vpath))

    def _require_physical(self, pseudo_or_real):
        vpath = self._virtual_from_pseudo(pseudo_or_real)
        if vpath is None:
            # Some pyftpdlib code paths hand back a real file object's .name.
            for mount in self._mounts:
                if self._is_subpath(pseudo_or_real, mount.local_path):
                    return self._safe_local(pseudo_or_real, mount.local_path), mount
            raise FilesystemError("Path is outside configured virtual directories")

        mount = self._matching_mount(vpath)
        if mount is None:
            raise FilesystemError("This virtual directory is only a container; no local directory is mounted here")
        rel = self._relative_virtual(vpath, mount.virtual_path)
        local = mount.local_path if not rel else os.path.join(mount.local_path, *rel.split("/"))
        return self._safe_local(local, mount.local_path), mount

    def _reject_mount_root(self, path):
        vpath = self.fs2ftp(path)
        if any(vpath == mount.virtual_path for mount in self._mounts):
            raise OSError(errno.EACCES, "Virtual mount points cannot be modified", path)

    @staticmethod
    def _is_subpath(path, root):
        try:
            path_abs = os.path.normcase(os.path.abspath(path))
            root_abs = os.path.normcase(os.path.abspath(root))
            return os.path.commonpath([path_abs, root_abs]) == root_abs
        except (ValueError, OSError, TypeError):
            return False

    @staticmethod
    def _safe_local(path, root):
        root_real = os.path.normcase(os.path.realpath(root))
        path_real = os.path.normcase(os.path.realpath(path))
        try:
            if os.path.commonpath([path_real, root_real]) != root_real:
                raise FilesystemError("Resolved path escapes the configured local directory")
        except ValueError as exc:
            raise FilesystemError("Resolved path is on a different filesystem root") from exc
        return os.path.abspath(path)
