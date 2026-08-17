"""Dependency-free, immutable local generation capsules for attorney evaluation."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path, PurePosixPath
from typing import cast

GENERATION_SCHEMA_VERSION = "1.0"
GENERATION_STORAGE_PLATFORM_UNSUPPORTED = "GENERATION_STORAGE_PLATFORM_UNSUPPORTED"
GENERATION_INTEGRITY_INVALID = "GENERATION_INTEGRITY_INVALID"

_MANIFEST_PATH = "generation-manifest.json"
_INPUT_PATH = "generation-input.json"
_REQUEST_PATH = "generation-request.json"
_RESPONSE_PATH = "generation-response.json"
_REPORT_PATH = "report.md"
_RECORD_PATH = "generation-record.json"
_MAX_JSON_BYTES = 16 * 1024 * 1024
_MAX_JSON_DEPTH = 64
_MAX_CAPTURE_BYTES = 64 * 1024 * 1024
_MAX_CAPTURE_ITEMS = 128
_MAX_IDENTIFIER_BYTES = 100
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_WINDOWS_FORBIDDEN_PATH_CHARS = frozenset('<>:"|?*')
_WINDOWS_RESERVED_DEVICE_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "COM2",
        "COM3",
        "COM4",
        "COM5",
        "COM6",
        "COM7",
        "COM8",
        "COM9",
        "LPT1",
        "LPT2",
        "LPT3",
        "LPT4",
        "LPT5",
        "LPT6",
        "LPT7",
        "LPT8",
        "LPT9",
    }
)
_ISOLATION_VALUES = frozenset({"fresh_context", "sequential_same_context", "scripted_fixture"})

JsonObject = dict[str, object]


class GenerationInputError(ValueError):
    """The caller supplied an invalid generation input or response."""


class GenerationIntegrityError(ValueError):
    """The capsule storage or immutable artifact graph failed verification."""


class _ArtifactTooLarge(GenerationIntegrityError):
    """A bounded descriptor read exceeded the public input limit."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ordinary(value: object, *, location: str) -> None:
    pending: list[tuple[object, int]] = [(value, 1)]
    while pending:
        current, depth = pending.pop()
        if depth > _MAX_JSON_DEPTH:
            raise GenerationInputError(f"{location} exceeds the nesting-depth limit")
        if type(current) is dict:
            mapping = cast(dict[object, object], current)
            if any(type(key) is not str for key in mapping):
                raise GenerationInputError(f"{location} contains a non-string object key")
            pending.extend((child, depth + 1) for child in mapping.values())
        elif type(current) is list:
            pending.extend((child, depth + 1) for child in cast(list[object], current))
        elif current is None or type(current) in {str, bool, int, float}:
            continue
        else:
            raise GenerationInputError(f"{location} contains a non-JSON value")


def canonical_json_bytes(value: object) -> bytes:
    """Return the one canonical UTF-8 encoding used by capsule artifacts."""
    _ordinary(value, location="JSON value")
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise GenerationInputError("JSON value is not canonicalizable") from error


def _canonical_object(data: bytes, *, location: str) -> JsonObject:
    if len(data) > _MAX_JSON_BYTES:
        raise GenerationInputError(f"{location} exceeds the size limit")
    try:
        value = json.loads(data.decode("utf-8"))
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GenerationInputError(f"{location} is not canonical JSON") from error
    if type(value) is not dict or canonical_json_bytes(value) != data:
        raise GenerationInputError(f"{location} is not canonical JSON")
    return cast(JsonObject, value)


def _object(value: object, *, location: str) -> JsonObject:
    if type(value) is not dict:
        raise GenerationInputError(f"{location} must be an object")
    return cast(JsonObject, value)


def _array(value: object, *, location: str) -> list[object]:
    if type(value) is not list:
        raise GenerationInputError(f"{location} must be an array")
    return cast(list[object], value)


def _shape(value: object, *, required: set[str], location: str) -> JsonObject:
    result = _object(value, location=location)
    if set(result) != required:
        raise GenerationInputError(f"{location} has an unexpected shape")
    return result


def _string(value: object, *, location: str, nonblank: bool = False) -> str:
    if type(value) is not str:
        raise GenerationInputError(f"{location} must be a string")
    result = value
    if nonblank and (not result.strip() or result != result.strip()):
        raise GenerationInputError(f"{location} must be nonblank without surrounding whitespace")
    return result


def _identifier(value: object, *, location: str) -> str:
    result = _string(value, location=location, nonblank=True)
    device = result.split(".", maxsplit=1)[0].rstrip(" .").upper()
    if (
        len(result.encode("utf-8")) > _MAX_IDENTIFIER_BYTES
        or result in {".", ".."}
        or not _IDENTIFIER_RE.fullmatch(result)
        or device in _WINDOWS_RESERVED_DEVICE_NAMES
    ):
        raise GenerationInputError(f"{location} is not a safe identifier")
    return result


def _digest(value: object, *, location: str) -> str:
    result = _string(value, location=location)
    if not _HASH_RE.fullmatch(result):
        raise GenerationInputError(f"{location} must be a lowercase SHA-256 digest")
    return result


def _exact_text(data: bytes, *, location: str) -> str:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GenerationInputError(f"{location} is not UTF-8") from error
    if not text.replace("\ufeff", "").strip():
        raise GenerationInputError(f"{location} is blank")
    return text


def _relative_path(value: object, *, location: str) -> str:
    result = _string(value, location=location, nonblank=True)
    try:
        _validate_relative_path(result)
    except GenerationIntegrityError as error:
        raise GenerationInputError(f"{location} is unsafe") from error
    return result


def _validate_relative_path(artifact_path: str) -> PurePosixPath:
    if not artifact_path or artifact_path != artifact_path.strip() or "\\" in artifact_path:
        raise GenerationIntegrityError("unsafe artifact path")
    if artifact_path.startswith("/"):
        raise GenerationIntegrityError("unsafe artifact path")
    segments = artifact_path.split("/")
    for segment in segments:
        device = segment.split(".", maxsplit=1)[0].rstrip(" .").upper()
        if (
            segment in {"", ".", ".."}
            or any(ord(character) <= 0x1F or ord(character) == 0x7F for character in segment)
            or any(character in _WINDOWS_FORBIDDEN_PATH_CHARS for character in segment)
            or segment.endswith((" ", "."))
            or device in _WINDOWS_RESERVED_DEVICE_NAMES
        ):
            raise GenerationIntegrityError("unsafe artifact path")
    return PurePosixPath(artifact_path)


class _NodeIdentity:
    __slots__ = ("changed_ns", "device", "inode", "link_count", "mode", "modified_ns", "size")

    def __init__(self, metadata: os.stat_result) -> None:
        self.device = metadata.st_dev
        self.inode = metadata.st_ino
        self.mode = metadata.st_mode
        self.link_count = metadata.st_nlink
        self.size = metadata.st_size
        self.modified_ns = metadata.st_mtime_ns
        self.changed_ns = metadata.st_ctime_ns

    def same_snapshot(self, other: _NodeIdentity) -> bool:
        return (
            self.device,
            self.inode,
            self.mode,
            self.link_count,
            self.size,
            self.modified_ns,
            self.changed_ns,
        ) == (
            other.device,
            other.inode,
            other.mode,
            other.link_count,
            other.size,
            other.modified_ns,
            other.changed_ns,
        )


class _Anchor:
    __slots__ = ("descriptor", "identity", "name")

    def __init__(self, name: str | None, descriptor: int) -> None:
        self.name = name
        self.descriptor = descriptor
        self.identity = _NodeIdentity(os.fstat(descriptor))


def _storage_platform() -> str:
    return os.name


def _require_posix_capabilities() -> None:
    if _storage_platform() != "posix":
        raise GenerationIntegrityError(
            f"{GENERATION_STORAGE_PLATFORM_UNSUPPORTED}: secure generation storage requires POSIX"
        )
    missing = [name for name in ("O_DIRECTORY", "O_NOFOLLOW") if not hasattr(os, name)]
    if os.scandir not in os.supports_fd:
        missing.append("scandir(fd)")
    if missing:
        raise GenerationIntegrityError(
            f"{GENERATION_STORAGE_PLATFORM_UNSUPPORTED}: missing " + ", ".join(missing)
        )


def _directory_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _file_flags() -> int:
    return os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _open_directory(parent: int | None, name: str) -> int:
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise GenerationIntegrityError(
                f"storage path contains a symlink or non-directory component: {name}"
            ) from error
        raise
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise GenerationIntegrityError(f"storage path is not a directory: {name}")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise OSError("artifact write made no progress")
        offset += written


def _read_all(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > _MAX_JSON_BYTES:
            raise _ArtifactTooLarge("artifact exceeds the size limit")
        chunks.append(chunk)


def _lock_descriptor(descriptor: int, *, exclusive: bool) -> None:
    try:
        import fcntl

        operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        fcntl.flock(descriptor, operation)
    except (ImportError, NotImplementedError, OSError) as error:
        raise GenerationIntegrityError(
            f"{GENERATION_STORAGE_PLATFORM_UNSUPPORTED}: file locking is unavailable"
        ) from error


def _validate_regular(metadata: os.stat_result, artifact_path: str) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise GenerationIntegrityError(f"artifact is not a regular file: {artifact_path}")
    if metadata.st_nlink != 1:
        raise GenerationIntegrityError(f"artifact has multiple hard links: {artifact_path}")


def _probe_posix_capabilities(directory_descriptor: int) -> None:
    os.fsync(directory_descriptor)
    with tempfile.TemporaryDirectory(prefix="regulatory-harvest-generation-probe-") as probe:
        root = _open_directory(None, probe)
        try:
            descriptor = os.open(
                "probe",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=root,
            )
            try:
                _write_all(descriptor, b"probe")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            _validate_regular(os.stat("probe", dir_fd=root, follow_symlinks=False), "probe")
            os.unlink("probe", dir_fd=root)
            os.fsync(root)
        except (NotImplementedError, OSError, TypeError) as error:
            raise GenerationIntegrityError(
                f"{GENERATION_STORAGE_PLATFORM_UNSUPPORTED}: capability probe failed"
            ) from error
        finally:
            os.close(root)


class _PosixStorage:
    def __init__(self, root_path: Path, anchors: list[_Anchor]) -> None:
        self.root_path = root_path
        self.failure_stage = "operation"
        self._anchors = anchors
        self._root_descriptor = anchors[-1].descriptor
        self._closed = False

    @classmethod
    def open(
        cls,
        root_dir: Path,
        *,
        initialize: bool,
        exclusive: bool,
    ) -> _PosixStorage:
        _require_posix_capabilities()
        try:
            root_path = Path(os.path.abspath(root_dir.expanduser()))
        except (OSError, RuntimeError, TypeError, ValueError) as error:
            raise GenerationIntegrityError("storage path cannot be normalized safely") from error
        anchors: list[_Anchor] = []
        try:
            descriptor = _open_directory(None, root_path.anchor)
            anchors.append(_Anchor(None, descriptor))
            parts = list(root_path.parts[1:])
            missing_at: int | None = None
            for index, segment in enumerate(parts):
                try:
                    descriptor = _open_directory(descriptor, segment)
                except FileNotFoundError:
                    missing_at = index
                    break
                anchors.append(_Anchor(segment, descriptor))
            if missing_at is not None and not initialize:
                raise GenerationIntegrityError("storage directory does not exist")
            if initialize:
                _lock_descriptor(anchors[-1].descriptor, exclusive=True)
                _probe_posix_capabilities(anchors[-1].descriptor)
                if missing_at is None:
                    raise GenerationIntegrityError("capsule directory already exists")
                missing_parts = parts[missing_at:]
                for offset, segment in enumerate(missing_parts):
                    parent = anchors[-1].descriptor
                    if offset == len(missing_parts) - 1:
                        os.mkdir(segment, mode=0o700, dir_fd=parent)
                    else:
                        with suppress(FileExistsError):
                            os.mkdir(segment, mode=0o700, dir_fd=parent)
                    descriptor = _open_directory(parent, segment)
                    anchors.append(_Anchor(segment, descriptor))
                    os.fchmod(descriptor, 0o700)
                    os.fsync(parent)
                os.fchmod(anchors[-1].descriptor, 0o700)
            else:
                _lock_descriptor(anchors[-1].descriptor, exclusive=exclusive)
            storage = cls(root_path, anchors)
            storage.assert_root_identity()
            return storage
        except BaseException:
            for anchor in reversed(anchors):
                with suppress(OSError):
                    os.close(anchor.descriptor)
            raise

    def _ensure_open(self) -> None:
        if self._closed:
            raise GenerationIntegrityError("storage is closed")

    def assert_root_identity(self) -> None:
        self._ensure_open()
        for index, anchor in enumerate(self._anchors):
            opened = os.fstat(anchor.descriptor)
            if not stat.S_ISDIR(opened.st_mode) or (
                opened.st_dev,
                opened.st_ino,
            ) != (anchor.identity.device, anchor.identity.inode):
                raise GenerationIntegrityError("storage directory identity changed")
            if index == 0:
                continue
            parent = self._anchors[index - 1]
            if anchor.name is None:
                raise GenerationIntegrityError("storage anchor is invalid")
            named = os.stat(anchor.name, dir_fd=parent.descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(named.st_mode) or (
                named.st_dev,
                named.st_ino,
            ) != (anchor.identity.device, anchor.identity.inode):
                raise GenerationIntegrityError("storage directory path identity changed")

    @contextmanager
    def _artifact_parent(self, artifact_path: str, *, create: bool) -> Iterator[tuple[int, str]]:
        relative = _validate_relative_path(artifact_path)
        descriptors: list[int] = []
        current = self._root_descriptor
        try:
            for segment in relative.parts[:-1]:
                created = False
                try:
                    descriptor = _open_directory(current, segment)
                except FileNotFoundError:
                    if not create:
                        raise
                    with suppress(FileExistsError):
                        os.mkdir(segment, mode=0o700, dir_fd=current)
                    descriptor = _open_directory(current, segment)
                    created = True
                descriptors.append(descriptor)
                if created:
                    os.fchmod(descriptor, 0o700)
                    os.fsync(current)
                current = descriptor
            yield current, relative.name
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def _read_leaf(self, parent: int, name: str, artifact_path: str) -> bytes:
        try:
            descriptor = os.open(name, _file_flags(), dir_fd=parent)
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise GenerationIntegrityError(
                    f"artifact path contains a symlink: {artifact_path}"
                ) from error
            raise
        try:
            before = os.fstat(descriptor)
            _validate_regular(before, artifact_path)
            data = _read_all(descriptor)
            after = os.fstat(descriptor)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not _NodeIdentity(before).same_snapshot(_NodeIdentity(after)) or (
                before.st_dev,
                before.st_ino,
            ) != (named.st_dev, named.st_ino):
                raise GenerationIntegrityError(f"artifact changed while reading: {artifact_path}")
            return data
        finally:
            os.close(descriptor)

    def read_artifact(self, artifact_path: str) -> bytes:
        self.failure_stage = f"artifact read ({artifact_path})"
        self.assert_root_identity()
        try:
            with self._artifact_parent(artifact_path, create=False) as (parent, name):
                data = self._read_leaf(parent, name, artifact_path)
        except FileNotFoundError as error:
            raise GenerationIntegrityError(f"artifact is missing: {artifact_path}") from error
        self.assert_root_identity()
        return data

    def atomic_write(self, artifact_path: str, data: bytes, *, mutable: bool) -> None:
        self.failure_stage = f"artifact write ({artifact_path})"
        self.assert_root_identity()
        with self._artifact_parent(artifact_path, create=True) as (parent, name):
            try:
                existing = self._read_leaf(parent, name, artifact_path)
            except FileNotFoundError:
                existing = None
            if existing is not None:
                if existing == data:
                    return
                if not mutable:
                    raise GenerationIntegrityError(f"immutable artifact differs: {artifact_path}")
            temporary_name = f".{name}.{uuid.uuid4().hex}.tmp"
            descriptor: int | None = None
            try:
                descriptor = os.open(
                    temporary_name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_NOFOLLOW
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=parent,
                )
                os.fchmod(descriptor, 0o600)
                _write_all(descriptor, data)
                os.fsync(descriptor)
                self.assert_root_identity()
                os.replace(temporary_name, name, src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
                self.assert_root_identity()
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                with suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=parent)

    def _scan_directory(self, descriptor: int, prefix: PurePosixPath) -> set[str]:
        inventory: set[str] = set()
        with os.scandir(descriptor) as entries:
            names = sorted(entry.name for entry in entries)
        for name in names:
            relative = prefix / name
            relative_text = relative.as_posix()
            _validate_relative_path(relative_text)
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise GenerationIntegrityError(
                    f"capsule inventory contains a symlink: {relative_text}"
                )
            if stat.S_ISDIR(metadata.st_mode):
                child = _open_directory(descriptor, name)
                try:
                    opened = os.fstat(child)
                    if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                        raise GenerationIntegrityError("capsule inventory directory changed")
                    inventory.update(self._scan_directory(child, relative))
                finally:
                    os.close(child)
                continue
            _validate_regular(metadata, relative_text)
            descriptor_child = os.open(name, _file_flags(), dir_fd=descriptor)
            try:
                opened = os.fstat(descriptor_child)
                _validate_regular(opened, relative_text)
                if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise GenerationIntegrityError("capsule inventory artifact changed")
            finally:
                os.close(descriptor_child)
            inventory.add(relative_text)
        return inventory

    def scan_files(self) -> set[str]:
        self.assert_root_identity()
        result = self._scan_directory(self._root_descriptor, PurePosixPath())
        self.assert_root_identity()
        return result

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for anchor in reversed(self._anchors):
            with suppress(OSError):
                os.close(anchor.descriptor)


@contextmanager
def _open_storage(
    root_dir: Path,
    *,
    initialize: bool = False,
    exclusive: bool = False,
) -> Iterator[_PosixStorage]:
    storage: _PosixStorage | None = None
    try:
        storage = _PosixStorage.open(
            root_dir,
            initialize=initialize,
            exclusive=exclusive,
        )
        yield storage
    except GenerationIntegrityError:
        raise
    except (NotImplementedError, OSError, TypeError) as error:
        stage = "open" if storage is None else storage.failure_stage
        raise GenerationIntegrityError(f"generation storage {stage} failed") from error
    finally:
        if storage is not None:
            storage.close()


def _absolute_file_parts(path: Path) -> tuple[Path, str]:
    try:
        absolute = Path(os.path.abspath(path.expanduser()))
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise GenerationIntegrityError("input path cannot be normalized safely") from error
    if not absolute.name:
        raise GenerationInputError("input path must identify a file")
    return absolute.parent, absolute.name


def _same_or_descendant(path: Path, directory: Path) -> bool:
    return path == directory or directory in path.parents


def _validate_generation_input(value: object) -> JsonObject:
    result = _shape(
        value,
        required={
            "schema_version",
            "candidate_id",
            "question",
            "generation_instructions",
            "sources",
            "client_facts_path",
            "generator_artifacts",
        },
        location="generation input",
    )
    if _string(result["schema_version"], location="schema_version") != "1.0":
        raise GenerationInputError("generation input schema version is unsupported")
    _identifier(result["candidate_id"], location="candidate_id")
    _string(result["question"], location="question", nonblank=True)
    _string(
        result["generation_instructions"],
        location="generation_instructions",
        nonblank=True,
    )
    sources = _array(result["sources"], location="sources")
    artifacts = _array(result["generator_artifacts"], location="generator_artifacts")
    if not sources or not artifacts:
        raise GenerationInputError("sources and generator_artifacts must not be empty")
    if len(sources) > _MAX_CAPTURE_ITEMS or len(artifacts) > _MAX_CAPTURE_ITEMS:
        raise GenerationInputError("generation input contains too many capture items")
    source_ids: list[str] = []
    input_paths: list[str] = []
    for index, raw in enumerate(sources):
        item = _shape(
            raw,
            required={"source_id", "path"},
            location=f"sources[{index}]",
        )
        source_ids.append(_identifier(item["source_id"], location=f"sources[{index}].source_id"))
        input_paths.append(_relative_path(item["path"], location=f"sources[{index}].path"))
    artifact_ids: list[str] = []
    for index, raw in enumerate(artifacts):
        item = _shape(
            raw,
            required={"artifact_id", "path"},
            location=f"generator_artifacts[{index}]",
        )
        artifact_ids.append(
            _identifier(item["artifact_id"], location=f"generator_artifacts[{index}].artifact_id")
        )
        input_paths.append(
            _relative_path(item["path"], location=f"generator_artifacts[{index}].path")
        )
    if len({identifier.casefold() for identifier in source_ids}) != len(source_ids) or len(
        {identifier.casefold() for identifier in artifact_ids}
    ) != len(artifact_ids):
        raise GenerationInputError("source and generator artifact identifiers must be unique")
    facts = result["client_facts_path"]
    if facts is not None:
        input_paths.append(_relative_path(facts, location="client_facts_path"))
    if len(input_paths) != len(set(input_paths)):
        raise GenerationInputError("generation input paths must be unique")
    return result


def _capture_from_storage(
    storage: _PosixStorage,
    value: JsonObject,
) -> tuple[JsonObject, JsonObject, dict[str, bytes]]:
    source_commitments: list[JsonObject] = []
    request_sources: list[JsonObject] = []
    files: dict[str, bytes] = {}
    total_bytes = 0
    for raw in cast(list[object], value["sources"]):
        item = cast(JsonObject, raw)
        source_id = cast(str, item["source_id"])
        data = storage.read_artifact(cast(str, item["path"]))
        total_bytes += len(data)
        text = _exact_text(data, location=f"source {source_id}")
        content_hash = _sha256(data)
        source_commitments.append({"content_hash": content_hash, "source_id": source_id})
        request_sources.append({"content_hash": content_hash, "source_id": source_id, "text": text})
        files[f"captured/sources/{source_id}.txt"] = data
    client_facts: str | None = None
    client_facts_hash: str | None = None
    facts_path = value["client_facts_path"]
    if facts_path is not None:
        data = storage.read_artifact(cast(str, facts_path))
        total_bytes += len(data)
        client_facts = _exact_text(data, location="client facts")
        client_facts_hash = _sha256(data)
        files["captured/client-facts.txt"] = data
    artifact_commitments: list[JsonObject] = []
    for raw in cast(list[object], value["generator_artifacts"]):
        item = cast(JsonObject, raw)
        artifact_id = cast(str, item["artifact_id"])
        data = storage.read_artifact(cast(str, item["path"]))
        total_bytes += len(data)
        content_hash = _sha256(data)
        artifact_commitments.append({"artifact_id": artifact_id, "content_hash": content_hash})
        files[f"captured/generator/{artifact_id}.bin"] = data
    if total_bytes > _MAX_CAPTURE_BYTES:
        raise GenerationInputError("captured inputs exceed the total size limit")
    capture: JsonObject = {
        "candidate_id": value["candidate_id"],
        "client_facts_hash": client_facts_hash,
        "generation_instructions": value["generation_instructions"],
        "generator_artifacts": artifact_commitments,
        "question": value["question"],
        "schema_version": "1.0",
        "sources": source_commitments,
    }
    capture["capture_fingerprint"] = _sha256(canonical_json_bytes(capture))
    request_base: JsonObject = {
        "candidate_id": value["candidate_id"],
        "capture_fingerprint": capture["capture_fingerprint"],
        "client_facts": client_facts,
        "client_facts_hash": client_facts_hash,
        "generation_instructions": value["generation_instructions"],
        "generator_artifacts": artifact_commitments,
        "operation": "generate_report",
        "question": value["question"],
        "schema_version": "1.0",
        "sources": request_sources,
    }
    return capture, request_base, files


def _artifact_records(files: dict[str, bytes]) -> list[JsonObject]:
    return [
        {"artifact_hash": _sha256(data), "artifact_path": path}
        for path, data in sorted(files.items())
    ]


def _manifest(
    *,
    candidate_id: str,
    capture_fingerprint: str,
    request_fingerprint: str,
    nonce_fingerprint: str,
    state: str,
    response_fingerprint: str | None,
    report_hash: str | None,
    files: dict[str, bytes],
) -> JsonObject:
    records = _artifact_records(files)
    result: JsonObject = {
        "artifact_inventory_fingerprint": _sha256(canonical_json_bytes(records)),
        "artifacts": records,
        "candidate_id": candidate_id,
        "capture_fingerprint": capture_fingerprint,
        "manifest_fingerprint": "0" * 64,
        "nonce_fingerprint": nonce_fingerprint,
        "report_hash": report_hash,
        "request_fingerprint": request_fingerprint,
        "response_fingerprint": response_fingerprint,
        "schema_version": "1.0",
        "state": state,
    }
    fingerprint_value = dict(result)
    fingerprint_value.pop("manifest_fingerprint")
    result["manifest_fingerprint"] = _sha256(canonical_json_bytes(fingerprint_value))
    return result


def _state(manifest: JsonObject) -> JsonObject:
    return {
        "candidate_id": manifest["candidate_id"],
        "capture_fingerprint": manifest["capture_fingerprint"],
        "manifest_root": manifest["manifest_fingerprint"],
        "report_hash": manifest["report_hash"],
        "request_fingerprint": manifest["request_fingerprint"],
        "response_fingerprint": manifest["response_fingerprint"],
        "schema_version": "1.0",
        "state": manifest["state"],
    }


def _write_initial_capsule(
    run_dir: Path,
    *,
    files: dict[str, bytes],
    manifest: JsonObject,
) -> None:
    with _open_storage(run_dir, initialize=True) as storage:
        for artifact_path, data in sorted(files.items()):
            storage.atomic_write(artifact_path, data, mutable=False)
        storage.atomic_write(_MANIFEST_PATH, canonical_json_bytes(manifest), mutable=False)
        storage.assert_root_identity()
        _verify_in_storage(storage)


def initialize_generation(input_path: Path, run_dir: Path, *, nonce_hex: str) -> JsonObject:
    """Capture exact inputs and freeze one nonce-bound generation request."""
    _require_posix_capabilities()
    if type(nonce_hex) is not str or not _HASH_RE.fullmatch(nonce_hex):
        raise GenerationInputError("nonce_hex must be exactly 64 lowercase hexadecimal characters")
    input_root, input_name = _absolute_file_parts(input_path)
    run_root = Path(os.path.abspath(run_dir.expanduser()))
    if _same_or_descendant(run_root, input_root):
        raise GenerationInputError("generation capsule must be outside the input root")
    with _open_storage(input_root) as storage:
        try:
            value = _validate_generation_input(
                _canonical_object(storage.read_artifact(input_name), location="generation input")
            )
            capture, request, captured_files = _capture_from_storage(storage, value)
        except _ArtifactTooLarge as error:
            raise GenerationInputError("generation input exceeds the size limit") from error
        storage.assert_root_identity()
    nonce_fingerprint = _sha256(nonce_hex.encode("ascii"))
    request["nonce_fingerprint"] = nonce_fingerprint
    request["request_fingerprint"] = _sha256(canonical_json_bytes(request))
    files = {
        **captured_files,
        _INPUT_PATH: canonical_json_bytes(capture),
        _REQUEST_PATH: canonical_json_bytes(request),
    }
    manifest = _manifest(
        candidate_id=cast(str, capture["candidate_id"]),
        capture_fingerprint=cast(str, capture["capture_fingerprint"]),
        request_fingerprint=cast(str, request["request_fingerprint"]),
        nonce_fingerprint=nonce_fingerprint,
        state="awaiting-report",
        response_fingerprint=None,
        report_hash=None,
        files=files,
    )
    _write_initial_capsule(run_root, files=files, manifest=manifest)
    return _state(manifest)


def _validate_capture(value: object) -> JsonObject:
    result = _shape(
        value,
        required={
            "schema_version",
            "candidate_id",
            "question",
            "generation_instructions",
            "sources",
            "client_facts_hash",
            "generator_artifacts",
            "capture_fingerprint",
        },
        location="generation-input.json",
    )
    if _string(result["schema_version"], location="capture schema") != "1.0":
        raise GenerationIntegrityError("capture schema version is unsupported")
    _identifier(result["candidate_id"], location="capture candidate_id")
    _string(result["question"], location="capture question", nonblank=True)
    _string(
        result["generation_instructions"],
        location="capture generation_instructions",
        nonblank=True,
    )
    sources = _array(result["sources"], location="capture sources")
    artifacts = _array(result["generator_artifacts"], location="capture generator_artifacts")
    if not sources or not artifacts:
        raise GenerationIntegrityError("capture commitments are empty")
    source_ids: list[str] = []
    for index, raw in enumerate(sources):
        item = _shape(
            raw,
            required={"source_id", "content_hash"},
            location=f"capture sources[{index}]",
        )
        source_ids.append(_identifier(item["source_id"], location="captured source_id"))
        _digest(item["content_hash"], location="captured source hash")
    artifact_ids: list[str] = []
    for index, raw in enumerate(artifacts):
        item = _shape(
            raw,
            required={"artifact_id", "content_hash"},
            location=f"capture generator_artifacts[{index}]",
        )
        artifact_ids.append(_identifier(item["artifact_id"], location="captured artifact_id"))
        _digest(item["content_hash"], location="captured artifact hash")
    if len(source_ids) != len(set(source_ids)) or len(artifact_ids) != len(set(artifact_ids)):
        raise GenerationIntegrityError("capture identifiers are not unique")
    facts_hash = result["client_facts_hash"]
    if facts_hash is not None:
        _digest(facts_hash, location="captured client facts hash")
    fingerprint = _digest(result["capture_fingerprint"], location="capture fingerprint")
    fingerprint_value = dict(result)
    fingerprint_value.pop("capture_fingerprint")
    if fingerprint != _sha256(canonical_json_bytes(fingerprint_value)):
        raise GenerationIntegrityError("capture fingerprint mismatch")
    return result


def _validate_request(value: object) -> JsonObject:
    result = _shape(
        value,
        required={
            "schema_version",
            "operation",
            "request_fingerprint",
            "nonce_fingerprint",
            "candidate_id",
            "capture_fingerprint",
            "question",
            "generation_instructions",
            "sources",
            "client_facts",
            "client_facts_hash",
            "generator_artifacts",
        },
        location="generation-request.json",
    )
    if (
        _string(result["schema_version"], location="request schema") != "1.0"
        or _string(result["operation"], location="request operation") != "generate_report"
    ):
        raise GenerationIntegrityError("generation request contract is unsupported")
    _identifier(result["candidate_id"], location="request candidate_id")
    _digest(result["capture_fingerprint"], location="request capture fingerprint")
    _digest(result["nonce_fingerprint"], location="request nonce fingerprint")
    fingerprint = _digest(result["request_fingerprint"], location="request fingerprint")
    _string(result["question"], location="request question", nonblank=True)
    _string(
        result["generation_instructions"],
        location="request generation_instructions",
        nonblank=True,
    )
    for index, raw in enumerate(_array(result["sources"], location="request sources")):
        item = _shape(
            raw,
            required={"source_id", "content_hash", "text"},
            location=f"request sources[{index}]",
        )
        _identifier(item["source_id"], location="request source_id")
        _digest(item["content_hash"], location="request source hash")
        text = _string(item["text"], location="request source text")
        if not text.replace("\ufeff", "").strip():
            raise GenerationIntegrityError("request source text is blank")
    facts = result["client_facts"]
    facts_hash = result["client_facts_hash"]
    if (facts is None) != (facts_hash is None):
        raise GenerationIntegrityError("request client facts commitment mismatch")
    if facts is not None:
        text = _string(facts, location="request client facts")
        if not text.replace("\ufeff", "").strip():
            raise GenerationIntegrityError("request client facts are blank")
        _digest(facts_hash, location="request client facts hash")
    for index, raw in enumerate(
        _array(result["generator_artifacts"], location="request generator_artifacts")
    ):
        item = _shape(
            raw,
            required={"artifact_id", "content_hash"},
            location=f"request generator_artifacts[{index}]",
        )
        _identifier(item["artifact_id"], location="request artifact_id")
        _digest(item["content_hash"], location="request artifact hash")
    fingerprint_value = dict(result)
    fingerprint_value.pop("request_fingerprint")
    if fingerprint != _sha256(canonical_json_bytes(fingerprint_value)):
        raise GenerationIntegrityError("request fingerprint mismatch")
    return result


def _validate_response(value: object) -> JsonObject:
    result = _shape(
        value,
        required={
            "schema_version",
            "operation",
            "request_fingerprint",
            "provider_name",
            "model_name",
            "generation_isolation",
            "response_id",
            "usage",
            "payload",
        },
        location="generation response",
    )
    if (
        _string(result["schema_version"], location="response schema_version") != "1.0"
        or _string(result["operation"], location="response operation") != "generate_report"
    ):
        raise GenerationInputError("generation response contract is unsupported")
    _digest(result["request_fingerprint"], location="response request_fingerprint")
    _string(result["provider_name"], location="provider_name", nonblank=True)
    _string(result["model_name"], location="model_name", nonblank=True)
    isolation = _string(result["generation_isolation"], location="generation_isolation")
    if isolation not in _ISOLATION_VALUES:
        raise GenerationInputError("generation_isolation has an unsupported value")
    if result["response_id"] is not None:
        _string(result["response_id"], location="response_id", nonblank=True)
    usage = _object(result["usage"], location="usage")
    for key, amount in usage.items():
        _identifier(key, location="usage key")
        if type(amount) is not int or amount < 0:
            raise GenerationInputError("usage values must be nonnegative integers")
    payload = _shape(
        result["payload"],
        required={"report_text"},
        location="generation response payload",
    )
    report_text = _string(payload["report_text"], location="report_text")
    if not report_text.replace("\ufeff", "").strip():
        raise GenerationInputError("report_text is blank")
    return result


def _validate_manifest(value: object) -> JsonObject:
    result = _shape(
        value,
        required={
            "schema_version",
            "candidate_id",
            "capture_fingerprint",
            "nonce_fingerprint",
            "request_fingerprint",
            "response_fingerprint",
            "report_hash",
            "artifacts",
            "artifact_inventory_fingerprint",
            "state",
            "manifest_fingerprint",
        },
        location="generation-manifest.json",
    )
    if _string(result["schema_version"], location="manifest schema") != "1.0":
        raise GenerationIntegrityError("generation manifest schema is unsupported")
    _identifier(result["candidate_id"], location="manifest candidate_id")
    for field in (
        "capture_fingerprint",
        "nonce_fingerprint",
        "request_fingerprint",
        "artifact_inventory_fingerprint",
        "manifest_fingerprint",
    ):
        _digest(result[field], location=f"manifest {field}")
    state = _string(result["state"], location="manifest state")
    if state not in {"awaiting-report", "completed"}:
        raise GenerationIntegrityError("generation manifest state is unsupported")
    for field in ("response_fingerprint", "report_hash"):
        if result[field] is not None:
            _digest(result[field], location=f"manifest {field}")
    records: list[JsonObject] = []
    for index, raw in enumerate(_array(result["artifacts"], location="manifest artifacts")):
        item = _shape(
            raw,
            required={"artifact_path", "artifact_hash"},
            location=f"manifest artifacts[{index}]",
        )
        path = _relative_path(item["artifact_path"], location="manifest artifact_path")
        if path == _MANIFEST_PATH:
            raise GenerationIntegrityError("manifest must not inventory itself")
        _digest(item["artifact_hash"], location="manifest artifact_hash")
        records.append(item)
    paths = [cast(str, item["artifact_path"]) for item in records]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise GenerationIntegrityError("manifest artifact paths are not sorted and unique")
    if result["artifact_inventory_fingerprint"] != _sha256(canonical_json_bytes(records)):
        raise GenerationIntegrityError("manifest artifact inventory fingerprint mismatch")
    fingerprint_value = dict(result)
    fingerprint_value.pop("manifest_fingerprint")
    if result["manifest_fingerprint"] != _sha256(canonical_json_bytes(fingerprint_value)):
        raise GenerationIntegrityError("manifest fingerprint mismatch")
    if state == "awaiting-report" and (
        result["response_fingerprint"] is not None or result["report_hash"] is not None
    ):
        raise GenerationIntegrityError("awaiting capsule contains response provenance")
    if state == "completed" and (
        result["response_fingerprint"] is None or result["report_hash"] is None
    ):
        raise GenerationIntegrityError("completed capsule lacks response provenance")
    return result


def _integrity_object(data: bytes, *, location: str) -> JsonObject:
    try:
        return _canonical_object(data, location=location)
    except GenerationInputError as error:
        raise GenerationIntegrityError(f"{location} failed canonical validation") from error


def _expected_capture_files(capture: JsonObject) -> set[str]:
    result = {
        _INPUT_PATH,
        _REQUEST_PATH,
        *{
            f"captured/sources/{cast(JsonObject, raw)['source_id']}.txt"
            for raw in cast(list[object], capture["sources"])
        },
        *{
            f"captured/generator/{cast(JsonObject, raw)['artifact_id']}.bin"
            for raw in cast(list[object], capture["generator_artifacts"])
        },
    }
    if capture["client_facts_hash"] is not None:
        result.add("captured/client-facts.txt")
    return result


def _verify_capture_and_request(
    storage: _PosixStorage,
    capture: JsonObject,
    request: JsonObject,
) -> None:
    if (
        request["candidate_id"] != capture["candidate_id"]
        or request["capture_fingerprint"] != capture["capture_fingerprint"]
        or request["question"] != capture["question"]
        or request["generation_instructions"] != capture["generation_instructions"]
        or request["client_facts_hash"] != capture["client_facts_hash"]
        or request["generator_artifacts"] != capture["generator_artifacts"]
    ):
        raise GenerationIntegrityError("request does not bind the captured input")
    request_sources = cast(list[object], request["sources"])
    capture_sources = cast(list[object], capture["sources"])
    if len(request_sources) != len(capture_sources):
        raise GenerationIntegrityError("request source commitments differ")
    for captured_raw, requested_raw in zip(capture_sources, request_sources, strict=True):
        captured = cast(JsonObject, captured_raw)
        requested = cast(JsonObject, requested_raw)
        source_id = cast(str, captured["source_id"])
        data = storage.read_artifact(f"captured/sources/{source_id}.txt")
        text = _exact_text(data, location=f"captured source {source_id}")
        if (
            requested["source_id"] != source_id
            or requested["content_hash"] != captured["content_hash"]
            or requested["text"] != text
            or captured["content_hash"] != _sha256(data)
        ):
            raise GenerationIntegrityError("captured source commitment mismatch")
    if capture["client_facts_hash"] is None:
        if request["client_facts"] is not None:
            raise GenerationIntegrityError("unexpected request client facts")
    else:
        data = storage.read_artifact("captured/client-facts.txt")
        text = _exact_text(data, location="captured client facts")
        if capture["client_facts_hash"] != _sha256(data) or request["client_facts"] != text:
            raise GenerationIntegrityError("captured client facts commitment mismatch")
    for raw in cast(list[object], capture["generator_artifacts"]):
        item = cast(JsonObject, raw)
        artifact_id = cast(str, item["artifact_id"])
        data = storage.read_artifact(f"captured/generator/{artifact_id}.bin")
        if item["content_hash"] != _sha256(data):
            raise GenerationIntegrityError("captured generator artifact commitment mismatch")


def _generation_record(
    capture: JsonObject,
    request: JsonObject,
    response: JsonObject,
    *,
    response_fingerprint: str,
    report_hash: str,
) -> JsonObject:
    return {
        "candidate_id": capture["candidate_id"],
        "capture_fingerprint": capture["capture_fingerprint"],
        "client_facts_hash": capture["client_facts_hash"],
        "generation_isolation": response["generation_isolation"],
        "generator_artifact_hashes": {
            cast(str, cast(JsonObject, raw)["artifact_id"]): cast(JsonObject, raw)["content_hash"]
            for raw in cast(list[object], capture["generator_artifacts"])
        },
        "model_name": response["model_name"],
        "nonce_fingerprint": request["nonce_fingerprint"],
        "provider_name": response["provider_name"],
        "report_hash": report_hash,
        "request_fingerprint": request["request_fingerprint"],
        "response_fingerprint": response_fingerprint,
        "response_id": response["response_id"],
        "schema_version": "1.0",
        "source_hashes": {
            cast(str, cast(JsonObject, raw)["source_id"]): cast(JsonObject, raw)["content_hash"]
            for raw in cast(list[object], capture["sources"])
        },
        "usage": response["usage"],
    }


def _verify_in_storage(storage: _PosixStorage) -> tuple[JsonObject, JsonObject, JsonObject]:
    manifest = _validate_manifest(
        _integrity_object(storage.read_artifact(_MANIFEST_PATH), location=_MANIFEST_PATH)
    )
    records = cast(list[object], manifest["artifacts"])
    expected = {cast(str, cast(JsonObject, raw)["artifact_path"]) for raw in records}
    actual = storage.scan_files()
    if actual != expected | {_MANIFEST_PATH}:
        raise GenerationIntegrityError("capsule inventory does not match manifest")
    for raw in records:
        item = cast(JsonObject, raw)
        data = storage.read_artifact(cast(str, item["artifact_path"]))
        if item["artifact_hash"] != _sha256(data):
            raise GenerationIntegrityError("capsule artifact hash mismatch")
    capture = _validate_capture(
        _integrity_object(storage.read_artifact(_INPUT_PATH), location=_INPUT_PATH)
    )
    request = _validate_request(
        _integrity_object(storage.read_artifact(_REQUEST_PATH), location=_REQUEST_PATH)
    )
    _verify_capture_and_request(storage, capture, request)
    if (
        manifest["candidate_id"] != capture["candidate_id"]
        or manifest["capture_fingerprint"] != capture["capture_fingerprint"]
        or manifest["nonce_fingerprint"] != request["nonce_fingerprint"]
        or manifest["request_fingerprint"] != request["request_fingerprint"]
    ):
        raise GenerationIntegrityError("manifest does not bind capture and request")
    expected_paths = _expected_capture_files(capture)
    if manifest["state"] == "awaiting-report":
        if expected != expected_paths:
            raise GenerationIntegrityError("awaiting capsule artifact set is invalid")
        return manifest, capture, request
    completed_paths = expected_paths | {_RESPONSE_PATH, _REPORT_PATH, _RECORD_PATH}
    if expected != completed_paths:
        raise GenerationIntegrityError("completed capsule artifact set is invalid")
    response_bytes = storage.read_artifact(_RESPONSE_PATH)
    try:
        response = _validate_response(_canonical_object(response_bytes, location=_RESPONSE_PATH))
    except GenerationInputError as error:
        raise GenerationIntegrityError("generation response failed verification") from error
    if response["request_fingerprint"] != request["request_fingerprint"]:
        raise GenerationIntegrityError("generation response request binding mismatch")
    response_fingerprint = _sha256(response_bytes)
    report = storage.read_artifact(_REPORT_PATH)
    report_text = cast(str, cast(JsonObject, response["payload"])["report_text"])
    if report != report_text.encode("utf-8"):
        raise GenerationIntegrityError("report bytes do not match response")
    report_hash = _sha256(report)
    record = _integrity_object(storage.read_artifact(_RECORD_PATH), location=_RECORD_PATH)
    if record != _generation_record(
        capture,
        request,
        response,
        response_fingerprint=response_fingerprint,
        report_hash=report_hash,
    ):
        raise GenerationIntegrityError("generation record does not replay")
    if (
        manifest["response_fingerprint"] != response_fingerprint
        or manifest["report_hash"] != report_hash
    ):
        raise GenerationIntegrityError("manifest response provenance mismatch")
    return manifest, capture, request


def next_generation_request(run_dir: Path) -> JsonObject | None:
    """Return the one pending request after complete read-only verification."""
    with _open_storage(run_dir) as storage:
        manifest, _, request = _verify_in_storage(storage)
        storage.assert_root_identity()
        return request if manifest["state"] == "awaiting-report" else None


def generation_status(run_dir: Path) -> JsonObject:
    """Return verified capsule state without mutating any artifact."""
    with _open_storage(run_dir) as storage:
        manifest, _, _ = _verify_in_storage(storage)
        storage.assert_root_identity()
        return _state(manifest)


def _read_external_file(path: Path, *, location: str) -> bytes:
    root, name = _absolute_file_parts(path)
    with _open_storage(root) as storage:
        try:
            data = storage.read_artifact(name)
        except _ArtifactTooLarge as error:
            raise GenerationInputError(f"{location} exceeds the size limit") from error
        storage.assert_root_identity()
        return data


def submit_generation_response(
    run_dir: Path,
    response_path: Path,
) -> JsonObject:
    """Accept exactly one canonical, request-bound response and seal its report."""
    run_root = Path(os.path.abspath(run_dir.expanduser()))
    response_root, response_name = _absolute_file_parts(response_path)
    if _same_or_descendant(response_root / response_name, run_root):
        raise GenerationInputError("generation response path must be outside the capsule")
    with _open_storage(run_root) as preflight:
        preflight_manifest, _, _ = _verify_in_storage(preflight)
        if preflight_manifest["state"] != "awaiting-report":
            raise GenerationInputError("generation capsule already has a response")
    response_bytes = _read_external_file(response_path, location="generation response")
    response = _validate_response(_canonical_object(response_bytes, location="generation response"))
    with _open_storage(run_root, exclusive=True) as storage:
        manifest, capture, request = _verify_in_storage(storage)
        if manifest["state"] != "awaiting-report":
            raise GenerationInputError("generation capsule already has a response")
        if response["request_fingerprint"] != request["request_fingerprint"]:
            raise GenerationInputError("generation response does not bind the pending request")
        report_text = cast(str, cast(JsonObject, response["payload"])["report_text"])
        report_bytes = report_text.encode("utf-8")
        response_fingerprint = _sha256(response_bytes)
        report_hash = _sha256(report_bytes)
        record_bytes = canonical_json_bytes(
            _generation_record(
                capture,
                request,
                response,
                response_fingerprint=response_fingerprint,
                report_hash=report_hash,
            )
        )
        old_files = {
            cast(str, cast(JsonObject, raw)["artifact_path"]): storage.read_artifact(
                cast(str, cast(JsonObject, raw)["artifact_path"])
            )
            for raw in cast(list[object], manifest["artifacts"])
        }
        new_files = {
            _RESPONSE_PATH: response_bytes,
            _REPORT_PATH: report_bytes,
            _RECORD_PATH: record_bytes,
        }
        all_files = {**old_files, **new_files}
        completed_manifest = _manifest(
            candidate_id=cast(str, manifest["candidate_id"]),
            capture_fingerprint=cast(str, manifest["capture_fingerprint"]),
            request_fingerprint=cast(str, manifest["request_fingerprint"]),
            nonce_fingerprint=cast(str, manifest["nonce_fingerprint"]),
            state="completed",
            response_fingerprint=response_fingerprint,
            report_hash=report_hash,
            files=all_files,
        )
        for artifact_path, data in sorted(new_files.items()):
            storage.atomic_write(artifact_path, data, mutable=False)
        storage.atomic_write(
            _MANIFEST_PATH,
            canonical_json_bytes(completed_manifest),
            mutable=True,
        )
        verified, _, _ = _verify_in_storage(storage)
        storage.assert_root_identity()
        return _state(verified)


def verify_generation_capsule(run_dir: Path) -> JsonObject:
    """Verify the complete capsule graph and return its immutable manifest root."""
    with _open_storage(run_dir) as storage:
        manifest, _, _ = _verify_in_storage(storage)
        storage.assert_root_identity()
        return {
            "manifest_root": manifest["manifest_fingerprint"],
            "ok": True,
            "schema_version": "1.0",
            "state": _state(manifest),
        }


def load_completed_generation_capsule_context(
    run_dir: Path,
) -> tuple[JsonObject, bytes, JsonObject]:
    """Return provenance, exact report bytes, and the verified generation request."""
    with _open_storage(run_dir) as storage:
        manifest, _, request = _verify_in_storage(storage)
        if manifest["state"] != "completed":
            raise GenerationInputError("generation capsule is not completed")
        record = _integrity_object(
            storage.read_artifact(_RECORD_PATH), location=_RECORD_PATH
        )
        report = storage.read_artifact(_REPORT_PATH)
        storage.assert_root_identity()
        return (
            {
                "capsule_root": manifest["manifest_fingerprint"],
                "generation_record": record,
                "generation_question": request["question"],
                "kind": "capsule",
            },
            report,
            request,
        )


def load_completed_generation_capsule(run_dir: Path) -> tuple[JsonObject, bytes]:
    """Return replayable provenance and exact report bytes from a verified capsule."""
    provenance, report, _ = load_completed_generation_capsule_context(run_dir)
    return provenance, report
