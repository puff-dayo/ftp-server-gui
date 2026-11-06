import json
import os
from dataclasses import dataclass
from typing import Iterable, Union, List, Set


@dataclass(frozen=True)
class VirtualMapping:
    virtual_path: str
    local_path: str

    def to_dict(self):
        return {"virtual": self.virtual_path, "local": self.local_path}


_INVALID_VIRTUAL_CHARS = set('<>:"\\|?*')


def normalize_virtual_path(path: str) -> str:
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
