from __future__ import annotations

import hashlib
import json
import ntpath
import os
import shutil
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_attorney_workflow import (
    DefaultOmittingRepairAndRefereeJudge,
    MultiDisputeRefereeJudge,
    RepairAndRefereeJudge,
    ScriptedJudge,
    synthetic_case,
)

import regulatory_harvest.evaluation.attorney_artifacts as attorney_artifacts
import regulatory_harvest.evaluation.attorney_workflow as attorney_workflow
from regulatory_harvest.evaluation.attorney_artifacts import (
    EvaluationIntegrityError,
    render_evaluation_report,
    verify_evaluation_run,
)
from regulatory_harvest.evaluation.attorney_models import (
    AttorneyEvaluationCase,
    JudgeOperation,
    JudgeRequest,
    ReadinessStatus,
)
from regulatory_harvest.evaluation.attorney_workflow import (
    initialize_evaluation,
    next_judge_request,
    resume_evaluation,
    run_evaluation,
    submit_judge_response,
)
from regulatory_harvest.storage import canonical_json_bytes

_WIN_FILE_ATTRIBUTE_DIRECTORY = 0x10
_WIN_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_WIN_DELETE = 0x00010000
_WIN_FILE_READ_DATA = 0x00000001
_WIN_FILE_WRITE_DATA = 0x00000002
_WIN_FILE_READ_ATTRIBUTES = 0x00000080
_WIN_FILE_TRAVERSE = 0x00000020
_WIN_FILE_SHARE_READ = 0x1
_WIN_FILE_SHARE_WRITE = 0x2
_WIN_FILE_SHARE_DELETE = 0x4
_WIN_CREATE_NEW = 1
_WIN_OPEN_EXISTING = 3


class _FakeWin32API:
    def __init__(self, *, probe_error: OSError | None = None) -> None:
        self.nodes: dict[str, SimpleNamespace] = {}
        self.contents: dict[str, bytes] = {}
        self.handles: dict[int, SimpleNamespace] = {}
        self.handle_access: dict[int, int] = {}
        self.handle_shares: dict[int, int] = {}
        self.temporary_handles: list[int] = []
        self.open_calls: list[tuple[str, int, int, int, int]] = []
        self.root_open_calls: list[tuple[str, int, int, int]] = []
        self.relative_open_calls: list[tuple[int, str, int, int, int, int, int]] = []
        self.created_directories: list[str] = []
        self.rename_calls: list[tuple[int, int, str, bool]] = []
        self.rename_root_paths: list[str] = []
        self.flushed_handles: list[int] = []
        self.closed_handles: list[int] = []
        self.deleted_handles: list[int] = []
        self.delete_attempt_names: list[str] = []
        self.deleted_names: list[str] = []
        self.cleanup_events: list[tuple[str, str, int]] = []
        self.read_parent_paths: list[str] = []
        self.write_parent_paths: list[str] = []
        self.path_child_calls = 0
        self.before_path_open: object | None = None
        self.before_relative_open: object | None = None
        self.after_relative_open: object | None = None
        self.before_file_info: object | None = None
        self.before_query_names: object | None = None
        self.after_query_names: object | None = None
        self.before_rename: object | None = None
        self.after_rename: object | None = None
        self.before_delete_handle: object | None = None
        self.before_close_handle: object | None = None
        self.delete_errors_by_name: dict[str, OSError] = {}
        self.probe_error = probe_error
        self.probe_calls = 0
        self._next_handle = 100
        self._next_file_index = 1000
        self._roots: dict[str, SimpleNamespace] = {}

    @staticmethod
    def _key(path: str) -> str:
        return ntpath.normcase(ntpath.normpath(path))

    @staticmethod
    def _split(path: str) -> tuple[str, list[str]]:
        normalized = ntpath.normpath(path)
        drive, tail = ntpath.splitdrive(normalized)
        root = f"{drive}\\"
        return _FakeWin32API._key(root), [
            part for part in tail.replace("/", "\\").split("\\") if part
        ]

    def _new_node(
        self,
        *,
        name: str,
        parent: SimpleNamespace | None,
        attributes: int,
        content: bytes,
        redirect: SimpleNamespace | None = None,
    ) -> SimpleNamespace:
        self._next_file_index += 1
        return SimpleNamespace(
            name=name,
            parent=parent,
            children={},
            content=content,
            redirect=redirect,
            attributes=attributes,
            reparse_tag=0xA0000003 if attributes & _WIN_FILE_ATTRIBUTE_REPARSE_POINT else 0,
            volume_serial=7,
            file_index=self._next_file_index,
            link_count=1,
            size=len(content),
            write_time=self._next_file_index,
            file_type=1,
            delete_pending=False,
        )

    def _rebuild_indexes(self) -> None:
        self.nodes.clear()
        self.contents.clear()

        def visit(node: SimpleNamespace, path: str) -> None:
            key = self._key(path)
            self.nodes[key] = node
            self.contents[key] = node.content
            for child in node.children.values():
                visit(child, ntpath.join(path, child.name))

        for root_path, root in self._roots.items():
            visit(root, root_path)

    def _node_path(self, node: SimpleNamespace) -> str:
        parts: list[str] = []
        current = node
        while current.parent is not None:
            parts.append(current.name)
            current = current.parent
        root_path = next(path for path, candidate in self._roots.items() if candidate is current)
        return ntpath.join(root_path, *reversed(parts))

    def _resolve_absolute(
        self,
        path: str,
        *,
        follow_final_reparse: bool,
    ) -> SimpleNamespace:
        root_path, parts = self._split(path)
        try:
            node = self._roots[root_path]
        except KeyError as error:
            raise FileNotFoundError(path) from error
        for index, part in enumerate(parts):
            try:
                node = node.children[ntpath.normcase(part)]
            except KeyError as error:
                raise FileNotFoundError(path) from error
            final = index == len(parts) - 1
            if node.redirect is not None and (follow_final_reparse or not final):
                node = node.redirect
        return node

    @staticmethod
    def _access_categories(desired_access: int) -> tuple[bool, bool, bool]:
        read_access = bool(
            desired_access & (_WIN_FILE_READ_DATA | _WIN_FILE_READ_ATTRIBUTES | _WIN_FILE_TRAVERSE)
        )
        write_access = bool(desired_access & _WIN_FILE_WRITE_DATA)
        delete_access = bool(desired_access & _WIN_DELETE)
        return read_access, write_access, delete_access

    def _assert_open_sharing(
        self,
        node: SimpleNamespace,
        desired_access: int,
        share_mode: int,
    ) -> None:
        requested = self._access_categories(desired_access)
        for handle, opened_node in self.handles.items():
            if opened_node is not node:
                continue
            opened = self._access_categories(self.handle_access[handle])
            opened_share = self.handle_shares[handle]
            for needed, share_flag in zip(
                requested,
                (_WIN_FILE_SHARE_READ, _WIN_FILE_SHARE_WRITE, _WIN_FILE_SHARE_DELETE),
                strict=True,
            ):
                if needed and not opened_share & share_flag:
                    raise PermissionError("injected Windows sharing violation")
            for needed, share_flag in zip(
                opened,
                (_WIN_FILE_SHARE_READ, _WIN_FILE_SHARE_WRITE, _WIN_FILE_SHARE_DELETE),
                strict=True,
            ):
                if needed and not share_mode & share_flag:
                    raise PermissionError("injected Windows sharing violation")

    def _new_handle(
        self,
        node: SimpleNamespace,
        desired_access: int,
        share_mode: int,
    ) -> int:
        self._assert_open_sharing(node, desired_access, share_mode)
        handle = self._next_handle
        self._next_handle += 1
        self.handles[handle] = node
        self.handle_access[handle] = desired_access
        self.handle_shares[handle] = share_mode
        return handle

    def _call_hook(self, hook: object | None, *args: object) -> None:
        if callable(hook):
            hook(*args)

    def add_directory(self, path: str, *, reparse: bool = False) -> None:
        attributes = _WIN_FILE_ATTRIBUTE_DIRECTORY
        if reparse:
            attributes |= _WIN_FILE_ATTRIBUTE_REPARSE_POINT
        self._add_node(path, attributes=attributes, content=b"")

    def add_file(self, path: str, content: bytes, *, reparse: bool = False) -> None:
        attributes = _WIN_FILE_ATTRIBUTE_REPARSE_POINT if reparse else 0
        self._add_node(path, attributes=attributes, content=content)

    def _add_node(self, path: str, *, attributes: int, content: bytes) -> None:
        root_path, parts = self._split(path)
        if not parts:
            if root_path in self._roots:
                raise FileExistsError(path)
            self._roots[root_path] = self._new_node(
                name=root_path,
                parent=None,
                attributes=attributes,
                content=content,
            )
            self._rebuild_indexes()
            return
        parent_path = ntpath.join(root_path, *parts[:-1])
        parent = self._resolve_absolute(parent_path, follow_final_reparse=True)
        key = ntpath.normcase(parts[-1])
        if key in parent.children:
            raise FileExistsError(path)
        parent.children[key] = self._new_node(
            name=parts[-1],
            parent=parent,
            attributes=attributes,
            content=content,
        )
        self._rebuild_indexes()

    def replace_directory_with_reparse(self, path: str, redirect_path: str) -> None:
        original = self._resolve_absolute(path, follow_final_reparse=False)
        if original.parent is None:
            raise AssertionError("cannot replace a filesystem root")
        redirect = self._resolve_absolute(redirect_path, follow_final_reparse=True)
        replacement = self._new_node(
            name=original.name,
            parent=original.parent,
            attributes=_WIN_FILE_ATTRIBUTE_DIRECTORY | _WIN_FILE_ATTRIBUTE_REPARSE_POINT,
            content=b"",
            redirect=redirect,
        )
        original.parent.children[ntpath.normcase(original.name)] = replacement
        self._rebuild_indexes()

    def probe(self) -> None:
        self.probe_calls += 1
        if self.probe_error is not None:
            raise self.probe_error

    def open_root(
        self,
        path: str,
        desired_access: int,
        share_mode: int,
        flags: int,
    ) -> int:
        key = self._key(path)
        self.root_open_calls.append((key, desired_access, share_mode, flags))
        node = self._resolve_absolute(path, follow_final_reparse=False)
        return self._new_handle(node, desired_access, share_mode)

    def open_relative(
        self,
        parent_handle: int,
        name: str,
        desired_access: int,
        share_mode: int,
        create_disposition: int,
        create_options: int,
        file_attributes: int,
    ) -> int:
        self.relative_open_calls.append(
            (
                parent_handle,
                name,
                desired_access,
                share_mode,
                create_disposition,
                create_options,
                file_attributes,
            )
        )
        self._call_hook(self.before_relative_open, parent_handle, name)
        if ntpath.basename(name) != name or name in {"", ".", ".."}:
            raise ValueError("relative opens require one child name")
        parent = self.handles[parent_handle]
        key = ntpath.normcase(name)
        node = parent.children.get(key)
        if create_disposition == 2:
            if node is not None:
                raise FileExistsError(name)
            attributes = file_attributes
            if file_attributes & _WIN_FILE_ATTRIBUTE_DIRECTORY:
                attributes |= _WIN_FILE_ATTRIBUTE_DIRECTORY
            node = self._new_node(
                name=name,
                parent=parent,
                attributes=attributes,
                content=b"",
            )
            parent.children[key] = node
            if attributes & _WIN_FILE_ATTRIBUTE_DIRECTORY:
                self.created_directories.append(self._key(self._node_path(node)))
            self._rebuild_indexes()
        elif create_disposition == 1 and node is None:
            raise FileNotFoundError(name)
        assert node is not None
        handle = self._new_handle(node, desired_access, share_mode)
        try:
            self._call_hook(self.after_relative_open, parent_handle, name, handle)
        except BaseException:
            self.close_handle(handle)
            raise
        if name.startswith(".rh-"):
            self.temporary_handles.append(handle)
        return handle

    def query_names(self, directory_handle: int) -> list[str]:
        self._call_hook(self.before_query_names, directory_handle)
        names = sorted(child.name for child in self.handles[directory_handle].children.values())
        self._call_hook(self.after_query_names, directory_handle)
        return names

    def create_file(
        self,
        path: str,
        desired_access: int,
        share_mode: int,
        creation_disposition: int,
        flags: int,
    ) -> int:
        key = self._key(path)
        self.open_calls.append((key, desired_access, share_mode, creation_disposition, flags))
        self.path_child_calls += 1
        self._call_hook(self.before_path_open, path)
        if creation_disposition == _WIN_CREATE_NEW:
            root_path, parts = self._split(path)
            parent_path = ntpath.join(root_path, *parts[:-1])
            parent = self._resolve_absolute(parent_path, follow_final_reparse=True)
            child_key = ntpath.normcase(parts[-1])
            if child_key in parent.children:
                raise FileExistsError(path)
            node = self._new_node(
                name=parts[-1],
                parent=parent,
                attributes=0,
                content=b"",
            )
            parent.children[child_key] = node
            self._rebuild_indexes()
        else:
            node = self._resolve_absolute(
                path,
                follow_final_reparse=not bool(flags & 0x00200000),
            )
        return self._new_handle(node, desired_access, share_mode)

    def create_directory(self, path: str) -> None:
        key = self._key(path)
        self.created_directories.append(key)
        self.path_child_calls += 1
        self.add_directory(path)

    def file_info(self, handle: int) -> SimpleNamespace:
        self._call_hook(self.before_file_info, handle)
        return self.handles[handle]

    def list_names(self, path: str) -> list[str]:
        self.path_child_calls += 1
        parent = self._resolve_absolute(path, follow_final_reparse=True)
        return sorted(child.name for child in parent.children.values())

    def read_file(self, handle: int) -> bytes:
        node = self.handles[handle]
        if node.parent is not None:
            self.read_parent_paths.append(self._key(self._node_path(node.parent)))
        return node.content

    def write_file(self, handle: int, data: bytes) -> None:
        node = self.handles[handle]
        if node.parent is not None:
            self.write_parent_paths.append(self._key(self._node_path(node.parent)))
        node.content = data
        node.size = len(data)
        node.write_time += 1
        self._rebuild_indexes()

    def flush_file(self, handle: int) -> None:
        self.flushed_handles.append(handle)

    def rename_file(
        self,
        handle: int,
        *,
        root_directory: int,
        new_name: str,
        replace: bool,
    ) -> None:
        self._call_hook(self.before_rename, handle, root_directory, new_name)
        self.rename_calls.append((handle, root_directory, new_name, replace))
        node = self.handles[handle]
        parent = self.handles[root_directory]
        for opened_handle, opened_node in self.handles.items():
            if (
                opened_node is parent
                and not self.handle_shares[opened_handle] & _WIN_FILE_SHARE_WRITE
            ):
                raise PermissionError("injected rooted rename sharing violation")
        self.rename_root_paths.append(self._key(self._node_path(parent)))
        key = ntpath.normcase(new_name)
        existing = parent.children.get(key)
        if existing is not None and existing is not node and not replace:
            raise FileExistsError(new_name)
        if node.parent is not None:
            node.parent.children.pop(ntpath.normcase(node.name), None)
        if existing is not None and existing is not node:
            existing.parent = None
        node.name = new_name
        node.parent = parent
        parent.children[key] = node
        self._rebuild_indexes()
        self._call_hook(self.after_rename, handle, root_directory, new_name)

    def delete_handle(self, handle: int) -> None:
        self._call_hook(self.before_delete_handle, handle)
        self.deleted_handles.append(handle)
        node = self.handles[handle]
        self.delete_attempt_names.append(node.name)
        if node.name in self.delete_errors_by_name:
            raise self.delete_errors_by_name[node.name]
        if node.parent is None:
            raise PermissionError("cannot delete filesystem root")
        if node.children:
            raise OSError("directory is not empty")
        node.delete_pending = True
        self.deleted_names.append(node.name)
        self.cleanup_events.append(("delete", node.name, handle))

    def delete_file(self, path: str) -> None:
        self.path_child_calls += 1
        node = self._resolve_absolute(path, follow_final_reparse=False)
        if node.parent is None:
            raise PermissionError(path)
        node.parent.children.pop(ntpath.normcase(node.name), None)
        node.parent = None
        self._rebuild_indexes()

    def close_handle(self, handle: int) -> None:
        self._call_hook(self.before_close_handle, handle)
        node = self.handles[handle]
        self.cleanup_events.append(("close", node.name, handle))
        self.closed_handles.append(handle)
        self.handles.pop(handle, None)
        self.handle_access.pop(handle, None)
        self.handle_shares.pop(handle, None)
        if node.delete_pending and all(opened is not node for opened in self.handles.values()):
            if node.parent is not None:
                node.parent.children.pop(ntpath.normcase(node.name), None)
                node.parent = None
            self._rebuild_indexes()


def _fake_windows_artifact_storage() -> tuple[
    _FakeWin32API,
    attorney_artifacts._WindowsRunStorage,
    SimpleNamespace,
]:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\safe")
    storage = attorney_artifacts._WindowsRunStorage.open(
        Path("C:\\safe\\evaluation-run"),
        initialize=True,
        api=api,
    )
    api.add_directory("C:\\safe\\evaluation-run\\judge-responses")
    parent = api._resolve_absolute(
        "C:\\safe\\evaluation-run\\judge-responses",
        follow_final_reparse=False,
    )
    return api, storage, parent


def _write_canonical(path: Path, payload: object) -> None:
    path.write_bytes(canonical_json_bytes(payload))


def _rebind_manifest(
    run_dir: Path,
    *,
    manifest: dict[str, object] | None = None,
) -> None:
    manifest_path = run_dir / "run-manifest.json"
    if manifest is None:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifacts = manifest["artifacts"]
    assert isinstance(artifacts, list)
    for artifact in artifacts:
        assert isinstance(artifact, dict)
        artifact_path = artifact["artifact_path"]
        assert isinstance(artifact_path, str)
        artifact["artifact_hash"] = hashlib.sha256(
            (run_dir / artifact_path).read_bytes()
        ).hexdigest()
    artifacts.sort(key=lambda artifact: artifact["artifact_path"])
    manifest["artifact_inventory_fingerprint"] = hashlib.sha256(
        canonical_json_bytes(artifacts)
    ).hexdigest()
    manifest_payload = {
        key: value for key, value in manifest.items() if key != "manifest_fingerprint"
    }
    manifest["manifest_fingerprint"] = hashlib.sha256(
        canonical_json_bytes(manifest_payload)
    ).hexdigest()
    _write_canonical(manifest_path, manifest)


@pytest.mark.asyncio
async def test_resume_rejects_changed_completed_artifact(tmp_path: Path) -> None:
    await run_evaluation(
        synthetic_case(comparator=False),
        ScriptedJudge(),
        tmp_path,
        seed_hex="9" * 64,
    )
    (tmp_path / "legal-ledger.json").write_text("{}", encoding="utf-8")

    with pytest.raises(EvaluationIntegrityError, match="artifact hash"):
        resume_evaluation(tmp_path)


@pytest.mark.asyncio
async def test_verification_rejects_added_and_symlinked_artifacts(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "added"
    await run_evaluation(
        synthetic_case(comparator=False),
        ScriptedJudge(),
        run_dir,
        seed_hex="a" * 64,
    )
    (run_dir / "unlisted.json").write_text("{}", encoding="utf-8")
    verification = verify_evaluation_run(run_dir)
    assert not verification.valid
    assert any("inventory" in issue for issue in verification.issues)
    with pytest.raises(EvaluationIntegrityError, match="inventory"):
        resume_evaluation(run_dir)

    symlink_dir = tmp_path / "symlinked"
    await run_evaluation(
        synthetic_case(comparator=False),
        ScriptedJudge(),
        symlink_dir,
        seed_hex="b" * 64,
    )
    target = tmp_path / "outside.json"
    target.write_text("{}", encoding="utf-8")
    os.symlink(target, symlink_dir / "escape.json")
    verification = verify_evaluation_run(symlink_dir)
    assert not verification.valid
    assert any("symlink" in issue for issue in verification.issues)


@pytest.mark.asyncio
async def test_manifest_self_hash_and_exact_request_bytes_are_verified(
    tmp_path: Path,
) -> None:
    await run_evaluation(
        synthetic_case(comparator=False),
        ScriptedJudge(),
        tmp_path,
        seed_hex="c" * 64,
    )
    manifest_path = tmp_path / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["retry_count"] += 1
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    verification = verify_evaluation_run(tmp_path)
    assert not verification.valid
    assert any("manifest" in issue for issue in verification.issues)


@pytest.mark.asyncio
async def test_verification_rejects_reordered_call_history_with_valid_self_hash(
    tmp_path: Path,
) -> None:
    await run_evaluation(
        synthetic_case(comparator=False),
        ScriptedJudge(),
        tmp_path,
        seed_hex="2" * 64,
    )
    manifest = json.loads((tmp_path / "run-manifest.json").read_text(encoding="utf-8"))
    manifest["judge_calls"] = list(reversed(manifest["judge_calls"]))
    _rebind_manifest(tmp_path, manifest=manifest)

    verification = verify_evaluation_run(tmp_path)
    assert not verification.valid
    assert any("transition" in issue for issue in verification.issues)


@pytest.mark.asyncio
async def test_verification_binds_grade_artifact_to_exact_response_payload(
    tmp_path: Path,
) -> None:
    await run_evaluation(
        synthetic_case(comparator=False),
        ScriptedJudge(),
        tmp_path,
        seed_hex="3" * 64,
    )
    grade_path = tmp_path / "grader-1-report-A.json"
    grade = json.loads(grade_path.read_text(encoding="utf-8"))
    grade["entry_grades"][0]["rationale"] = "A different but valid rationale."
    _write_canonical(grade_path, grade)
    _rebind_manifest(tmp_path)

    verification = verify_evaluation_run(tmp_path)
    assert not verification.valid
    assert any("grade evidence" in issue for issue in verification.issues)


@pytest.mark.asyncio
async def test_verification_rejects_rebound_fabricated_report_passage(
    tmp_path: Path,
) -> None:
    await run_evaluation(
        synthetic_case(comparator=False),
        ScriptedJudge(),
        tmp_path,
        seed_hex="1" * 64,
    )
    manifest = json.loads((tmp_path / "run-manifest.json").read_text(encoding="utf-8"))
    call = next(item for item in manifest["judge_calls"] if item["call_id"] == "grade-A-1")
    response_path = tmp_path / call["response_artifact_path"]
    response = json.loads(response_path.read_text(encoding="utf-8"))
    response["payload"]["entry_grades"][0]["report_passage"] = "Fabricated passage."
    _write_canonical(response_path, response)
    grade_path = tmp_path / "grader-1-report-A.json"
    grade = json.loads(grade_path.read_text(encoding="utf-8"))
    grade["entry_grades"][0]["report_passage"] = "Fabricated passage."
    _write_canonical(grade_path, grade)
    call["response_fingerprint"] = hashlib.sha256(response_path.read_bytes()).hexdigest()
    _rebind_manifest(tmp_path, manifest=manifest)

    verification = verify_evaluation_run(tmp_path)

    assert not verification.valid
    assert any("exact anonymous-report passage" in issue for issue in verification.issues)


@pytest.mark.asyncio
async def test_verification_rejects_rebound_aggregate_isolation_downgrade(
    tmp_path: Path,
) -> None:
    await run_evaluation(
        synthetic_case(comparator=False),
        ScriptedJudge(),
        tmp_path,
        seed_hex="2" * 64,
    )
    result_path = tmp_path / "evaluation-result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    assert result["judge_isolation"] == "fresh_context"
    result["judge_isolation"] = "sequential_same_context"
    fingerprint_payload = {
        key: value for key, value in result.items() if key != "result_fingerprint"
    }
    result["result_fingerprint"] = hashlib.sha256(
        canonical_json_bytes(fingerprint_payload)
    ).hexdigest()
    _write_canonical(result_path, result)
    loaded = attorney_artifacts._load_model_bytes(
        result_path.read_bytes(),
        attorney_artifacts.AttorneyEvaluationResult,
        location="evaluation-result.json",
    )
    (tmp_path / "evaluation-report.md").write_text(
        render_evaluation_report(loaded),
        encoding="utf-8",
    )
    manifest = json.loads((tmp_path / "run-manifest.json").read_text(encoding="utf-8"))
    manifest["result_hash"] = hashlib.sha256(result_path.read_bytes()).hexdigest()
    _rebind_manifest(tmp_path, manifest=manifest)

    verification = verify_evaluation_run(tmp_path)

    assert verification.issues == (
        "terminal aggregate judge isolation differs from manifest provenance",
    )


@pytest.mark.asyncio
async def test_verification_binds_normalized_defaults_across_repair_and_referees(
    tmp_path: Path,
) -> None:
    completed = await run_evaluation(
        synthetic_case(comparator=False),
        DefaultOmittingRepairAndRefereeJudge(),
        tmp_path,
        seed_hex="d" * 64,
    )

    response_payloads = [
        json.loads((tmp_path / call.response_artifact_path).read_text(encoding="utf-8"))[
            "payload"
        ]
        for call in completed.manifest.judge_calls
        if call.state == "completed" and call.response_artifact_path is not None
    ]
    assert any(
        "repaired_ledger" in payload and "gaps" not in payload["repaired_ledger"]
        for payload in response_payloads
    )
    assert any(
        "narrative_scores" in payload
        and "finding_codes" not in payload["narrative_scores"][0]
        for payload in response_payloads
    )
    assert any(
        "selected_ledger_resolution" in payload and "replacement_entries" not in payload
        for payload in response_payloads
    )
    assert any(
        "selected_grade_resolution" in payload and "replacement_entries" not in payload
        for payload in response_payloads
    )
    verification = verify_evaluation_run(tmp_path)

    assert verification.valid, verification.issues


@pytest.mark.asyncio
async def test_verification_rejects_declared_unexpected_artifact(
    tmp_path: Path,
) -> None:
    await run_evaluation(
        synthetic_case(comparator=False),
        ScriptedJudge(),
        tmp_path,
        seed_hex="0" * 64,
    )
    extra_path = tmp_path / "declared-extra.json"
    _write_canonical(extra_path, {"plausible": True})
    manifest = json.loads((tmp_path / "run-manifest.json").read_text(encoding="utf-8"))
    manifest["artifacts"].append(
        {
            "artifact_path": "declared-extra.json",
            "artifact_hash": hashlib.sha256(extra_path.read_bytes()).hexdigest(),
        }
    )
    _rebind_manifest(tmp_path, manifest=manifest)

    verification = verify_evaluation_run(tmp_path)
    assert not verification.valid
    assert any("protocol inventory" in issue for issue in verification.issues)


@pytest.mark.asyncio
async def test_verification_rejects_identity_leak_in_source_only_packet(
    tmp_path: Path,
) -> None:
    await run_evaluation(
        synthetic_case(comparator=False),
        ScriptedJudge(),
        tmp_path,
        seed_hex="1" * 64,
    )
    manifest = json.loads((tmp_path / "run-manifest.json").read_text(encoding="utf-8"))
    build_call = next(
        call for call in manifest["judge_calls"] if call["operation"] == "build_ledger"
    )
    request_path = tmp_path / build_call["request_artifact_path"]
    request = json.loads(request_path.read_text(encoding="utf-8"))
    request["payload"]["candidate_id"] = "harvest-private-id"
    request_payload = {key: value for key, value in request.items() if key != "request_fingerprint"}
    request["request_fingerprint"] = hashlib.sha256(
        canonical_json_bytes(request_payload)
    ).hexdigest()
    _write_canonical(request_path, request)
    response_path = tmp_path / build_call["response_artifact_path"]
    response = json.loads(response_path.read_text(encoding="utf-8"))
    response["request_fingerprint"] = request["request_fingerprint"]
    _write_canonical(response_path, response)
    build_call["request_fingerprint"] = request["request_fingerprint"]
    build_call["response_fingerprint"] = hashlib.sha256(response_path.read_bytes()).hexdigest()
    _rebind_manifest(tmp_path, manifest=manifest)

    verification = verify_evaluation_run(tmp_path)
    assert not verification.valid
    assert any("source-only" in issue for issue in verification.issues)


@pytest.mark.asyncio
async def test_verification_replays_requirement_matrix_from_immutable_evidence(
    tmp_path: Path,
) -> None:
    await run_evaluation(
        synthetic_case(comparator=False),
        ScriptedJudge(),
        tmp_path,
        seed_hex="c" * 64,
    )
    result_path = tmp_path / "evaluation-result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["requirement_matrix"]["rows"][0]["proposition"] = "Altered proposition."
    result_payload = {key: value for key, value in result.items() if key != "result_fingerprint"}
    result["result_fingerprint"] = hashlib.sha256(
        canonical_json_bytes(result_payload)
    ).hexdigest()
    _write_canonical(result_path, result)
    (tmp_path / "evaluation-report.md").write_text(
        render_evaluation_report(
            attorney_artifacts._load_model_bytes(
                result_path.read_bytes(),
                attorney_artifacts.AttorneyEvaluationResult,
                location="evaluation-result.json",
            )
        ),
        encoding="utf-8",
    )
    manifest = json.loads((tmp_path / "run-manifest.json").read_text(encoding="utf-8"))
    manifest["result_hash"] = hashlib.sha256(result_path.read_bytes()).hexdigest()
    _rebind_manifest(tmp_path, manifest=manifest)

    verification = verify_evaluation_run(tmp_path)

    assert not verification.valid
    assert verification.issues == (
        "requirement matrix does not match exact ledger and grade replay",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("legacy_schema", ["1.2", "1.1"])
async def test_mixed_legacy_and_current_schema_is_rejected_stably(
    tmp_path: Path,
    legacy_schema: str,
) -> None:
    await run_evaluation(
        synthetic_case(comparator=False),
        ScriptedJudge(),
        tmp_path,
        seed_hex="b" * 64,
    )
    manifest_path = tmp_path / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["schema_version"] = legacy_schema
    _write_canonical(manifest_path, manifest)

    verification = verify_evaluation_run(tmp_path)

    assert verification.issues == (
        "EVALUATION_ARTIFACT_SCHEMA_UNSUPPORTED: run-manifest.json",
    )


def _set_nested_schema(payload: object, field_path: tuple[object, ...]) -> None:
    current = payload
    for segment in field_path[:-1]:
        current = current[segment]  # type: ignore[index]
    current[field_path[-1]] = "1.1"  # type: ignore[index]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("artifact_path", "field_path"),
    [
        ("evaluation-result.json", ("schema_version",)),
        ("evaluation-result.json", ("reports", 0, "schema_version")),
        ("report-evaluation-A.json", ("schema_version",)),
        ("grader-1-report-A.json", ("schema_version",)),
        ("grader-2-report-A.json", ("schema_version",)),
        (
            "judge-responses/grade-A-1-attempt-1.json",
            ("payload", "schema_version"),
        ),
        (
            "judge-responses/grade-A-2-attempt-1.json",
            ("payload", "schema_version"),
        ),
        ("resolved-grade-A.json", ("schema_version",)),
        ("resolved-grade-A.json", ("grade", "schema_version")),
        ("resolved-grade-A.json", ("original_grader_1", "schema_version")),
        ("resolved-grade-A.json", ("original_grader_2", "schema_version")),
        ("report-score-inputs-A.json", ("schema_version",)),
        (
            "report-score-inputs-A.json",
            ("resolved_grade", "grade", "schema_version"),
        ),
        (
            "report-score-inputs-A.json",
            ("resolved_grade", "original_grader_2", "schema_version"),
        ),
        ("report-disputes.json", ("schema_version",)),
    ],
)
async def test_each_persisted_artifact_family_reports_stable_schema_location(
    tmp_path: Path,
    artifact_path: str,
    field_path: tuple[object, ...],
) -> None:
    await run_evaluation(
        synthetic_case(comparator=False),
        ScriptedJudge(),
        tmp_path,
        seed_hex="8" * 64,
    )
    path = tmp_path / artifact_path
    payload = json.loads(path.read_text(encoding="utf-8"))
    _set_nested_schema(payload, field_path)
    if artifact_path == "evaluation-result.json":
        result_payload = {
            key: value for key, value in payload.items() if key != "result_fingerprint"
        }
        payload["result_fingerprint"] = hashlib.sha256(
            canonical_json_bytes(result_payload)
        ).hexdigest()
    _write_canonical(path, payload)
    manifest = json.loads((tmp_path / "run-manifest.json").read_text(encoding="utf-8"))
    if artifact_path.startswith("judge-responses/"):
        for call in manifest["judge_calls"]:
            if call["response_artifact_path"] == artifact_path:
                call["response_fingerprint"] = hashlib.sha256(path.read_bytes()).hexdigest()
                break
        else:
            raise AssertionError(f"missing manifest judge call for {artifact_path}")
    if artifact_path == "evaluation-result.json":
        manifest["result_hash"] = hashlib.sha256(path.read_bytes()).hexdigest()
    _rebind_manifest(tmp_path, manifest=manifest)

    verification = verify_evaluation_run(tmp_path)

    schema_code = (
        "EVALUATION_SCORE_INPUT_SCHEMA_UNSUPPORTED"
        if artifact_path == "report-score-inputs-A.json"
        and field_path == ("schema_version",)
        else "EVALUATION_ARTIFACT_SCHEMA_UNSUPPORTED"
    )
    assert verification.issues == (f"{schema_code}: {artifact_path}",)


@pytest.mark.asyncio
async def test_untouched_score_inputs_retain_nested_legal_ledger_schema(
    tmp_path: Path,
) -> None:
    await run_evaluation(
        synthetic_case(comparator=False),
        ScriptedJudge(),
        tmp_path,
        seed_hex="9" * 64,
    )
    score_inputs = json.loads(
        (tmp_path / "report-score-inputs-A.json").read_text(encoding="utf-8")
    )
    grade_response = json.loads(
        (
            tmp_path / "judge-responses/grade-A-1-attempt-1.json"
        ).read_text(encoding="utf-8")
    )

    assert score_inputs["schema_version"] == "1.4"
    envelope = attorney_artifacts._load_model_bytes(
        (tmp_path / "case-envelope.json").read_bytes(),
        attorney_artifacts.CaseEnvelope,
        location="case-envelope.json",
    )
    assert score_inputs["source_record"] == attorney_artifacts.build_admission_packet(
        envelope
    ).payload
    assert score_inputs["sealed_ledger"]["ledger"]["schema_version"] == "1.0"
    assert grade_response["schema_version"] == "1.0"
    assert grade_response["payload"]["schema_version"] == "1.3"
    assert verify_evaluation_run(tmp_path).valid


@pytest.mark.asyncio
@pytest.mark.parametrize("legacy_schema", ["1.3", "1.2"])
async def test_legacy_score_input_schema_fails_closed(
    tmp_path: Path,
    legacy_schema: str,
) -> None:
    await run_evaluation(
        synthetic_case(comparator=False),
        ScriptedJudge(),
        tmp_path,
        seed_hex="9" * 64,
    )
    path = tmp_path / "report-score-inputs-A.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["schema_version"] = legacy_schema
    _write_canonical(path, payload)
    _rebind_manifest(tmp_path)

    verification = verify_evaluation_run(tmp_path)

    assert verification.issues == (
        "EVALUATION_SCORE_INPUT_SCHEMA_UNSUPPORTED: report-score-inputs-A.json",
    )


@pytest.mark.asyncio
async def test_score_input_source_record_tamper_fails_exact_replay(tmp_path: Path) -> None:
    await run_evaluation(
        synthetic_case(comparator=False),
        ScriptedJudge(),
        tmp_path,
        seed_hex="9" * 64,
    )
    path = tmp_path / "report-score-inputs-A.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    source_record = payload["source_record"]
    source = source_record["sources"][0]
    source["normalized_text"] += " Tampered."
    source["content_hash"] = hashlib.sha256(
        source["normalized_text"].encode("utf-8")
    ).hexdigest()
    projection = {
        key: value
        for key, value in source_record.items()
        if key != "source_record_fingerprint"
    }
    source_record["source_record_fingerprint"] = hashlib.sha256(
        canonical_json_bytes(projection)
    ).hexdigest()
    _write_canonical(path, payload)
    _rebind_manifest(tmp_path)

    verification = verify_evaluation_run(tmp_path)

    assert verification.issues == (
        "score-input source record differs from immutable case evidence",
    )


@pytest.mark.asyncio
async def test_verification_replays_sealed_ledger_derivation(tmp_path: Path) -> None:
    initialize_evaluation(
        synthetic_case(comparator=False),
        tmp_path,
        seed_hex="4" * 64,
    )
    judge = ScriptedJudge()
    for _ in range(3):
        request = next_judge_request(tmp_path)
        assert request is not None
        submit_judge_response(tmp_path, await judge.evaluate(request))

    ledger_path = tmp_path / "legal-ledger.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    ledger["audit_fingerprint"] = "f" * 64
    _write_canonical(ledger_path, ledger)
    legal_hash = hashlib.sha256(ledger_path.read_bytes()).hexdigest()

    manifest = json.loads((tmp_path / "run-manifest.json").read_text(encoding="utf-8"))
    pending = next(call for call in manifest["judge_calls"] if call["state"] == "pending")
    request_path = tmp_path / pending["request_artifact_path"]
    request = json.loads(request_path.read_text(encoding="utf-8"))
    request["payload"]["sealed_ledger"] = ledger
    request["safe_metadata"]["legal_ledger_hash"] = legal_hash
    fingerprint_payload = {
        key: value for key, value in request.items() if key != "request_fingerprint"
    }
    request["request_fingerprint"] = hashlib.sha256(
        canonical_json_bytes(fingerprint_payload)
    ).hexdigest()
    _write_canonical(request_path, request)
    pending["request_fingerprint"] = request["request_fingerprint"]
    manifest["legal_ledger_hash"] = legal_hash
    _rebind_manifest(tmp_path, manifest=manifest)

    verification = verify_evaluation_run(tmp_path)
    assert not verification.valid
    assert any("sealed-ledger replay" in issue for issue in verification.issues)


@pytest.mark.asyncio
async def test_verification_rejects_repair_after_clean_audit(tmp_path: Path) -> None:
    await run_evaluation(
        synthetic_case(comparator=False),
        RepairAndRefereeJudge(),
        tmp_path,
        seed_hex="5" * 64,
    )
    audit_path = tmp_path / "legal-ledger-audit.json"
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    audit["disputes"] = []
    _write_canonical(audit_path, audit)

    manifest = json.loads((tmp_path / "run-manifest.json").read_text(encoding="utf-8"))
    audit_call = next(
        call for call in manifest["judge_calls"] if call["operation"] == "audit_ledger"
    )
    response_path = tmp_path / audit_call["response_artifact_path"]
    response = json.loads(response_path.read_text(encoding="utf-8"))
    response["payload"] = audit
    _write_canonical(response_path, response)
    audit_call["response_fingerprint"] = hashlib.sha256(response_path.read_bytes()).hexdigest()
    _rebind_manifest(tmp_path, manifest=manifest)

    verification = verify_evaluation_run(tmp_path)
    assert not verification.valid
    assert any("transition" in issue for issue in verification.issues)


@pytest.mark.asyncio
async def test_verification_binds_report_referee_to_recorded_dispute(
    tmp_path: Path,
) -> None:
    initialize_evaluation(
        synthetic_case(comparator=False),
        tmp_path,
        seed_hex="6" * 64,
    )
    judge = RepairAndRefereeJudge()
    while True:
        request = next_judge_request(tmp_path)
        assert request is not None
        if (
            request.operation is JudgeOperation.REFEREE
            and request.safe_metadata.get("referee_scope") == "report"
        ):
            break
        submit_judge_response(tmp_path, await judge.evaluate(request))

    disputes_path = tmp_path / "report-disputes.json"
    disputes = json.loads(disputes_path.read_text(encoding="utf-8"))
    disputes["disputes"] = []
    _write_canonical(disputes_path, disputes)
    _rebind_manifest(tmp_path)

    verification = verify_evaluation_run(tmp_path)
    assert not verification.valid
    assert any("report dispute" in issue for issue in verification.issues)


@pytest.mark.asyncio
async def test_verification_rejects_rebound_narrative_referee_prompt_tamper(
    tmp_path: Path,
) -> None:
    """Replay must reconstruct the context-bearing narrative referee request."""
    await run_evaluation(
        synthetic_case(comparator=False),
        MultiDisputeRefereeJudge(),
        tmp_path,
        seed_hex="8" * 64,
    )
    manifest = json.loads((tmp_path / "run-manifest.json").read_text(encoding="utf-8"))
    narrative_call = None
    narrative_request = None
    for call in manifest["judge_calls"]:
        if call["operation"] != "referee" or call["anonymous_label"] is None:
            continue
        request = json.loads(
            (tmp_path / call["request_artifact_path"]).read_text(encoding="utf-8")
        )
        if request["payload"]["dispute"]["kind"] == "narrative_score":
            narrative_call = call
            narrative_request = request
            break
    assert narrative_call is not None and narrative_request is not None

    narrative_request["system_instructions"] += " Tampered stored context instruction."
    request_payload = {
        key: value
        for key, value in narrative_request.items()
        if key != "request_fingerprint"
    }
    narrative_request["request_fingerprint"] = hashlib.sha256(
        canonical_json_bytes(request_payload)
    ).hexdigest()
    request_path = tmp_path / narrative_call["request_artifact_path"]
    _write_canonical(request_path, narrative_request)

    response_path = tmp_path / narrative_call["response_artifact_path"]
    response = json.loads(response_path.read_text(encoding="utf-8"))
    response["request_fingerprint"] = narrative_request["request_fingerprint"]
    _write_canonical(response_path, response)
    narrative_call["request_fingerprint"] = narrative_request["request_fingerprint"]
    narrative_call["prompt_fingerprint"] = attorney_artifacts._prompt_fingerprint(
        JudgeRequest.model_validate(narrative_request)
    )
    narrative_call["response_fingerprint"] = hashlib.sha256(
        response_path.read_bytes()
    ).hexdigest()
    _rebind_manifest(tmp_path, manifest=manifest)

    verification = verify_evaluation_run(tmp_path)
    assert not verification.valid
    assert any("report referee" in issue for issue in verification.issues)


@pytest.mark.asyncio
async def test_verification_replays_deterministic_checks(tmp_path: Path) -> None:
    initialize_evaluation(
        synthetic_case(comparator=False),
        tmp_path,
        seed_hex="7" * 64,
    )
    judge = ScriptedJudge()
    for _ in range(3):
        request = next_judge_request(tmp_path)
        assert request is not None
        submit_judge_response(tmp_path, await judge.evaluate(request))

    checks_path = tmp_path / "deterministic-checks-A.json"
    checks = json.loads(checks_path.read_text(encoding="utf-8"))
    checks["valid"] = False
    checks["critical_codes"] = ["FABRICATED_FAILURE"]
    _write_canonical(checks_path, checks)

    manifest = json.loads((tmp_path / "run-manifest.json").read_text(encoding="utf-8"))
    pending = next(call for call in manifest["judge_calls"] if call["state"] == "pending")
    request_path = tmp_path / pending["request_artifact_path"]
    request = json.loads(request_path.read_text(encoding="utf-8"))
    request["payload"]["deterministic_checks"] = checks
    fingerprint_payload = {
        key: value for key, value in request.items() if key != "request_fingerprint"
    }
    request["request_fingerprint"] = hashlib.sha256(
        canonical_json_bytes(fingerprint_payload)
    ).hexdigest()
    _write_canonical(request_path, request)
    pending["request_fingerprint"] = request["request_fingerprint"]
    _rebind_manifest(tmp_path, manifest=manifest)

    verification = verify_evaluation_run(tmp_path)
    assert not verification.valid
    assert any("deterministic-check replay" in issue for issue in verification.issues)


def test_initialize_rejects_unchecked_construct_before_writing(tmp_path: Path) -> None:
    valid = synthetic_case(comparator=False)
    unchecked = AttorneyEvaluationCase.model_construct(
        **{
            **valid.model_dump(mode="python"),
            "case_id": b"laundered-case-id",
        }
    )
    run_dir = tmp_path / "unchecked"

    with pytest.raises((EvaluationIntegrityError, ValueError, TypeError)):
        initialize_evaluation(unchecked, run_dir, seed_hex="d" * 64)

    assert not run_dir.exists() or not any(run_dir.iterdir())


def test_initialize_rejects_symlink_run_directory(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    run_dir = tmp_path / "run-link"
    os.symlink(outside, run_dir)

    with pytest.raises(EvaluationIntegrityError, match="symlink"):
        initialize_evaluation(
            synthetic_case(comparator=False),
            run_dir,
            seed_hex="e" * 64,
        )

    assert list(outside.iterdir()) == []


def test_initialize_rejects_symlinked_existing_parent(tmp_path: Path) -> None:
    outside = tmp_path / "outside-parent"
    outside.mkdir()
    alias = tmp_path / "parent-link"
    os.symlink(outside, alias)
    run_dir = alias / "evaluation-run"

    with pytest.raises(EvaluationIntegrityError, match="symlink"):
        initialize_evaluation(
            synthetic_case(comparator=False),
            run_dir,
            seed_hex="e" * 64,
        )

    assert list(outside.iterdir()) == []


def test_initialize_rejects_parent_replaced_before_descriptor_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    safe_parent = tmp_path / "safe-parent"
    safe_parent.mkdir()
    parked_parent = tmp_path / "parked-parent"
    outside = tmp_path / "outside-race"
    outside.mkdir()
    original_open = os.open
    swapped = False

    def racing_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if not swapped and path == safe_parent.name and dir_fd is not None:
            safe_parent.rename(parked_parent)
            os.symlink(outside, safe_parent, target_is_directory=True)
            swapped = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(attorney_artifacts.os, "open", racing_open)

    with pytest.raises(EvaluationIntegrityError, match=r"symlink|changed|unsafe"):
        initialize_evaluation(
            synthetic_case(comparator=False),
            safe_parent / "evaluation-run",
            seed_hex="f" * 64,
        )

    assert swapped
    assert list(outside.iterdir()) == []


def test_resume_rejects_artifact_replaced_before_descriptor_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "read-race"
    initialize_evaluation(
        synthetic_case(comparator=False),
        run_dir,
        seed_hex="1" * 64,
    )
    artifact = run_dir / "case-envelope.json"
    parked = run_dir / "case-envelope.parked"
    outside = tmp_path / "outside-read.json"
    outside_bytes = b'{"outside":true}\n'
    outside.write_bytes(outside_bytes)
    original_open = os.open
    swapped = False

    def racing_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if not swapped and path == artifact.name and dir_fd is not None:
            artifact.rename(parked)
            os.symlink(outside, artifact)
            swapped = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(attorney_artifacts.os, "open", racing_open)

    with pytest.raises(EvaluationIntegrityError, match=r"symlink|changed|unsafe"):
        resume_evaluation(run_dir)

    assert swapped
    assert outside.read_bytes() == outside_bytes


def test_path_compatibility_read_is_descriptor_anchored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "compatibility-read-race"
    initialize_evaluation(
        synthetic_case(comparator=False),
        run_dir,
        seed_hex="d" * 64,
    )
    artifact = run_dir / "case-envelope.json"
    parked = run_dir / "case-envelope.parked"
    outside = tmp_path / "compatibility-outside.json"
    outside.write_bytes(b'{"outside":true}\n')
    original_open = os.open
    swapped = False

    def racing_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if not swapped and path == artifact.name and dir_fd is not None:
            artifact.rename(parked)
            os.symlink(outside, artifact)
            swapped = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(attorney_artifacts.os, "open", racing_open)

    with pytest.raises(EvaluationIntegrityError, match=r"symlink|changed"):
        attorney_artifacts._read_artifact(run_dir, "case-envelope.json")

    assert swapped


def test_next_request_rejects_run_root_replaced_after_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "next-root-race"
    initialize_evaluation(
        synthetic_case(comparator=False),
        run_dir,
        seed_hex="2" * 64,
    )
    request_path = next((run_dir / "judge-requests").iterdir())
    relative_request = request_path.relative_to(run_dir).as_posix()
    replacement = tmp_path / "replacement-root"
    (replacement / "judge-requests").mkdir(parents=True)
    (replacement / relative_request).write_bytes(request_path.read_bytes())
    parked = tmp_path / "verified-root"
    original_read = attorney_workflow._read_artifact
    swapped = False

    def racing_read(
        storage: Path | attorney_artifacts._RunStorage,
        artifact_path: str,
    ) -> bytes:
        nonlocal swapped
        if not swapped and artifact_path == relative_request:
            run_dir.rename(parked)
            replacement.rename(run_dir)
            swapped = True
        return original_read(storage, artifact_path)

    monkeypatch.setattr(attorney_workflow, "_read_artifact", racing_read)

    with pytest.raises(EvaluationIntegrityError, match=r"identity|changed"):
        next_judge_request(run_dir)

    assert swapped


@pytest.mark.asyncio
async def test_submit_rejects_run_root_replaced_after_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "submit-root-race"
    initialize_evaluation(
        synthetic_case(comparator=False),
        run_dir,
        seed_hex="3" * 64,
    )
    request = next_judge_request(run_dir)
    assert request is not None
    request_artifact_path = (
        next((run_dir / "judge-requests").iterdir()).relative_to(run_dir).as_posix()
    )
    response = await ScriptedJudge().evaluate(request)
    replacement = tmp_path / "submit-replacement"
    shutil.copytree(run_dir, replacement)
    parked = tmp_path / "submit-verified-root"
    original_read = attorney_workflow._read_artifact
    swapped = False

    def racing_read(
        storage: Path | attorney_artifacts._RunStorage,
        artifact_path: str,
    ) -> bytes:
        nonlocal swapped
        if not swapped and artifact_path == request_artifact_path:
            run_dir.rename(parked)
            replacement.rename(run_dir)
            swapped = True
        return original_read(storage, artifact_path)

    monkeypatch.setattr(attorney_workflow, "_read_artifact", racing_read)

    with pytest.raises(EvaluationIntegrityError, match=r"identity|changed"):
        submit_judge_response(run_dir, response)

    assert swapped


def test_verify_uses_descriptor_anchored_artifact_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "verify-read-race"
    initialize_evaluation(
        synthetic_case(comparator=False),
        run_dir,
        seed_hex="4" * 64,
    )
    artifact = run_dir / "evaluation-rubric.json"
    parked = run_dir / "evaluation-rubric.parked"
    outside = tmp_path / "outside-rubric.json"
    outside.write_bytes(artifact.read_bytes())
    original_open = os.open
    swapped = False

    def racing_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if not swapped and path == artifact.name and dir_fd is not None:
            artifact.rename(parked)
            os.symlink(outside, artifact)
            swapped = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(attorney_artifacts.os, "open", racing_open)

    verification = verify_evaluation_run(run_dir)

    assert swapped
    assert not verification.valid
    assert any("symlink" in issue for issue in verification.issues)


def test_resume_rejects_inventory_added_before_verification_returns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "late-inventory"
    initialize_evaluation(
        synthetic_case(comparator=False),
        run_dir,
        seed_hex="5" * 64,
    )
    original_score_replay = attorney_artifacts._verify_score_replay
    injected = False

    def injecting_score_replay(*args: object, **kwargs: object) -> None:
        nonlocal injected
        original_score_replay(*args, **kwargs)
        if not injected:
            (run_dir / "late-added.json").write_text("{}", encoding="utf-8")
            injected = True

    monkeypatch.setattr(
        attorney_artifacts,
        "_verify_score_replay",
        injecting_score_replay,
    )

    with pytest.raises(EvaluationIntegrityError, match=r"inventory|changed|added"):
        resume_evaluation(run_dir)

    assert injected


def test_resume_rejects_same_bytes_replacement_during_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "same-bytes-replacement"
    initialize_evaluation(
        synthetic_case(comparator=False),
        run_dir,
        seed_hex="6" * 64,
    )
    artifact = run_dir / "case-envelope.json"
    original_inode = artifact.stat().st_ino
    original_score_replay = attorney_artifacts._verify_score_replay
    injected = False

    def replacing_score_replay(*args: object, **kwargs: object) -> None:
        nonlocal injected
        original_score_replay(*args, **kwargs)
        if not injected:
            replacement = run_dir / ".replacement.tmp"
            replacement.write_bytes(artifact.read_bytes())
            os.replace(replacement, artifact)
            injected = True

    monkeypatch.setattr(
        attorney_artifacts,
        "_verify_score_replay",
        replacing_score_replay,
    )

    with pytest.raises(EvaluationIntegrityError, match=r"inventory|identity|changed"):
        resume_evaluation(run_dir)

    assert injected
    assert artifact.stat().st_ino != original_inode


def test_resume_rejects_hard_linked_artifact(tmp_path: Path) -> None:
    run_dir = tmp_path / "hard-linked"
    initialize_evaluation(
        synthetic_case(comparator=False),
        run_dir,
        seed_hex="7" * 64,
    )
    os.link(run_dir / "case-envelope.json", tmp_path / "outside-hard-link.json")

    with pytest.raises(EvaluationIntegrityError, match="hard link"):
        resume_evaluation(run_dir)


def test_posix_capability_failure_precedes_target_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "unsupported-storage"

    def unsupported_probe(_: int) -> None:
        raise NotImplementedError("descriptor-relative replace unsupported")

    monkeypatch.setattr(
        attorney_artifacts,
        "_probe_posix_capabilities",
        unsupported_probe,
    )

    with pytest.raises(EvaluationIntegrityError, match=r"storage|capability"):
        initialize_evaluation(
            synthetic_case(comparator=False),
            run_dir,
            seed_hex="8" * 64,
        )

    assert not run_dir.exists()


@pytest.mark.parametrize("reported_errno", [40, 20])
def test_posix_directory_open_uses_platform_errno_constants(
    monkeypatch: pytest.MonkeyPatch,
    reported_errno: int,
) -> None:
    monkeypatch.setattr(
        attorney_artifacts,
        "errno",
        SimpleNamespace(ELOOP=40, ENOTDIR=20),
    )

    def rejected_open(*_: object, **__: object) -> int:
        raise OSError(reported_errno, "injected component failure")

    monkeypatch.setattr(attorney_artifacts.os, "open", rejected_open)

    with pytest.raises(EvaluationIntegrityError, match="symlink or non-directory"):
        attorney_artifacts._open_posix_directory(None, "unsafe")


def test_posix_write_fsyncs_file_and_parent_and_renames_relative(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "relative-write"
    initialize_evaluation(
        synthetic_case(comparator=False),
        run_dir,
        seed_hex="9" * 64,
    )
    original_replace = os.replace
    original_fsync = os.fsync
    replace_calls: list[tuple[object, object, int | None, int | None]] = []
    fsync_modes: list[int] = []

    def recording_replace(
        source: object,
        destination: object,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        replace_calls.append((source, destination, src_dir_fd, dst_dir_fd))
        original_replace(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    def recording_fsync(descriptor: int) -> None:
        fsync_modes.append(os.fstat(descriptor).st_mode)
        original_fsync(descriptor)

    monkeypatch.setattr(attorney_artifacts.os, "replace", recording_replace)
    monkeypatch.setattr(attorney_artifacts.os, "fsync", recording_fsync)

    with attorney_artifacts._open_run_storage(run_dir) as storage:
        storage.atomic_write("anchored.json", b"{}\n", mutable=False)

    assert len(replace_calls) == 1
    source, destination, src_dir_fd, dst_dir_fd = replace_calls[0]
    assert isinstance(source, str) and "/" not in source
    assert destination == "anchored.json"
    assert src_dir_fd is not None and src_dir_fd == dst_dir_fd
    assert any(stat.S_ISREG(mode) for mode in fsync_modes)
    assert any(stat.S_ISDIR(mode) for mode in fsync_modes)


def test_posix_write_root_swap_never_mutates_replacement_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "write-race"
    initialize_evaluation(
        synthetic_case(comparator=False),
        run_dir,
        seed_hex="a" * 64,
    )
    replacement = tmp_path / "write-race-replacement"
    replacement.mkdir()
    sentinel = replacement / "outside.txt"
    sentinel.write_bytes(b"outside\n")
    parked = tmp_path / "write-race-parked"
    original_replace = os.replace
    swapped = False

    def racing_replace(
        source: object,
        destination: object,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        nonlocal swapped
        if not swapped and destination == "anchored.json":
            run_dir.rename(parked)
            replacement.rename(run_dir)
            swapped = True
        original_replace(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr(attorney_artifacts.os, "replace", racing_replace)

    with (
        pytest.raises(EvaluationIntegrityError, match=r"identity|changed"),
        attorney_artifacts._open_run_storage(run_dir) as storage,
    ):
        storage.atomic_write("anchored.json", b"{}\n", mutable=False)

    assert swapped
    assert (run_dir / "outside.txt").read_bytes() == b"outside\n"
    assert not (run_dir / "anchored.json").exists()
    assert (parked / "anchored.json").read_bytes() == b"{}\n"


def test_posix_noop_write_detects_root_swap_during_existing_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "noop-write-race"
    initialize_evaluation(
        synthetic_case(comparator=False),
        run_dir,
        seed_hex="c" * 64,
    )
    artifact_bytes = (run_dir / "case-envelope.json").read_bytes()
    replacement = tmp_path / "noop-write-replacement"
    replacement.mkdir()
    (replacement / "outside.txt").write_bytes(b"outside\n")
    parked = tmp_path / "noop-write-parked"
    original_read_all = attorney_artifacts._read_all
    swapped = False

    def racing_read_all(descriptor: int) -> bytes:
        nonlocal swapped
        data = original_read_all(descriptor)
        if not swapped:
            run_dir.rename(parked)
            replacement.rename(run_dir)
            swapped = True
        return data

    monkeypatch.setattr(attorney_artifacts, "_read_all", racing_read_all)

    with (
        pytest.raises(EvaluationIntegrityError, match=r"identity|changed"),
        attorney_artifacts._open_run_storage(run_dir) as storage,
    ):
        storage.atomic_write(
            "case-envelope.json",
            artifact_bytes,
            mutable=False,
        )

    assert swapped
    assert (run_dir / "outside.txt").read_bytes() == b"outside\n"


def test_posix_write_error_closes_descriptors_and_removes_temporary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "write-error"
    initialize_evaluation(
        synthetic_case(comparator=False),
        run_dir,
        seed_hex="b" * 64,
    )
    original_open = os.open
    opened_descriptors: list[int] = []

    def recording_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        opened_descriptors.append(descriptor)
        return descriptor

    def failed_write(_: int, __: bytes) -> None:
        raise OSError("injected write failure")

    monkeypatch.setattr(attorney_artifacts.os, "open", recording_open)
    monkeypatch.setattr(attorney_artifacts, "_write_all", failed_write)

    with (
        pytest.raises(EvaluationIntegrityError, match="artifact write"),
        attorney_artifacts._open_run_storage(run_dir) as storage,
    ):
        storage.atomic_write("failed.json", b"{}\n", mutable=False)

    for descriptor in opened_descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    assert not any(path.name.endswith(".tmp") for path in run_dir.iterdir())


def test_win32_backend_rejects_reparse_parent_before_creation() -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\safe", reparse=True)
    backend = getattr(attorney_artifacts, "_WindowsRunStorage", None)

    assert backend is not None, "Win32 handle backend is unavailable"
    with pytest.raises(EvaluationIntegrityError, match="reparse"):
        backend.open(Path("C:\\safe\\evaluation-run"), initialize=True, api=api)

    assert api.created_directories == []
    assert api.probe_calls == 0
    assert api.handles == {}
    assert all(call[3] & _WIN_FILE_SHARE_DELETE == 0 for call in api.relative_open_calls)
    assert all(call[2] & _WIN_FILE_SHARE_DELETE == 0 for call in api.root_open_calls)
    assert api.path_child_calls == 0


def test_win32_directory_relative_open_uses_supported_reparse_safe_options() -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\safe")

    storage = attorney_artifacts._WindowsRunStorage.open(
        Path("C:\\safe\\evaluation-run"),
        initialize=True,
        api=api,
    )
    storage.close()

    directory_calls = [call for call in api.relative_open_calls if call[1] == "safe"]
    assert directory_calls
    for _, _, _, share_mode, _, options, _ in directory_calls:
        assert share_mode == (
            attorney_artifacts._WIN_FILE_SHARE_READ | attorney_artifacts._WIN_FILE_SHARE_WRITE
        )
        assert share_mode & attorney_artifacts._WIN_FILE_SHARE_DELETE == 0
        assert options == attorney_artifacts._windows_directory_options()
        assert options & attorney_artifacts._WIN_FILE_SYNCHRONOUS_IO_NONALERT
        assert options & attorney_artifacts._WIN_FILE_OPEN_FOR_BACKUP_INTENT
        assert options & attorney_artifacts._WIN_FILE_OPEN_REPARSE_POINT
        assert options & 0x00000001 == 0  # FILE_DIRECTORY_FILE is incompatible here.

    create_calls = [
        call
        for call in api.relative_open_calls
        if call[1] == "evaluation-run" and call[4] == attorney_artifacts._WIN_FILE_CREATE
    ]
    assert len(create_calls) == 1
    _, _, _, share_mode, _, options, attributes = create_calls[0]
    assert share_mode == (
        attorney_artifacts._WIN_FILE_SHARE_READ | attorney_artifacts._WIN_FILE_SHARE_WRITE
    )
    assert share_mode & attorney_artifacts._WIN_FILE_SHARE_DELETE == 0
    assert options == attorney_artifacts._windows_directory_create_options()
    assert options & attorney_artifacts._WIN_FILE_DIRECTORY_FILE
    assert options & attorney_artifacts._WIN_FILE_OPEN_REPARSE_POINT == 0
    assert attributes == _WIN_FILE_ATTRIBUTE_DIRECTORY


def test_win32_directory_create_collision_never_opens_or_follows_reparse() -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\safe")
    api.add_directory("C:\\outside")
    collided = False

    def race_relative(parent_handle: int, name: str) -> None:
        nonlocal collided
        if (
            collided
            or name != "evaluation-run"
            or api.relative_open_calls[-1][4] != attorney_artifacts._WIN_FILE_CREATE
        ):
            return
        parent = api.handles[parent_handle]
        outside = api._resolve_absolute("C:\\outside", follow_final_reparse=True)
        replacement = api._new_node(
            name=name,
            parent=parent,
            attributes=_WIN_FILE_ATTRIBUTE_DIRECTORY | _WIN_FILE_ATTRIBUTE_REPARSE_POINT,
            content=b"",
            redirect=outside,
        )
        parent.children[ntpath.normcase(name)] = replacement
        api._rebuild_indexes()
        collided = True

    api.before_relative_open = race_relative

    with pytest.raises(EvaluationIntegrityError, match="reparse"):
        attorney_artifacts._WindowsRunStorage.open(
            Path("C:\\safe\\evaluation-run"),
            initialize=True,
            api=api,
        )

    assert collided
    target_calls = [call for call in api.relative_open_calls if call[1] == "evaluation-run"]
    assert [call[4] for call in target_calls] == [
        attorney_artifacts._WIN_FILE_OPEN,
        attorney_artifacts._WIN_FILE_CREATE,
        attorney_artifacts._WIN_FILE_OPEN,
    ]
    create_call = target_calls[1]
    assert create_call[5] == attorney_artifacts._windows_directory_create_options()
    safe_open = target_calls[2]
    assert safe_open[5] == attorney_artifacts._windows_directory_options()
    assert safe_open[5] & attorney_artifacts._WIN_FILE_OPEN_REPARSE_POINT
    assert api.path_child_calls == 0
    assert api.created_directories == []
    assert api.handles == {}


@pytest.mark.parametrize("unsafe_kind", ["file", "reparse"])
def test_win32_directory_relative_open_rejects_unsafe_type_immediately(
    unsafe_kind: str,
) -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    if unsafe_kind == "file":
        api.add_file("C:\\safe", b"not a directory")
        expected = "directory"
    else:
        api.add_directory("C:\\safe", reparse=True)
        expected = "reparse"

    with pytest.raises(EvaluationIntegrityError, match=expected):
        attorney_artifacts._WindowsRunStorage.open(
            Path("C:\\safe\\evaluation-run"),
            initialize=True,
            api=api,
        )

    safe_calls = [call for call in api.relative_open_calls if call[1] == "safe"]
    assert len(safe_calls) == 1
    assert api.probe_calls == 0
    assert api.created_directories == []
    assert api.handles == {}


def test_win32_invalid_filesystem_root_closes_unretained_handle() -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\", reparse=True)

    with pytest.raises(EvaluationIntegrityError, match="reparse"):
        attorney_artifacts._WindowsRunStorage.open(
            Path("C:\\safe\\evaluation-run"),
            initialize=True,
            api=api,
        )

    assert api.handles == {}


def test_win32_capability_failure_precedes_target_creation() -> None:
    api = _FakeWin32API(probe_error=PermissionError("rename handles unsupported"))
    api.add_directory("C:\\")
    api.add_directory("C:\\safe")

    with pytest.raises(EvaluationIntegrityError, match=r"capability|storage"):
        attorney_artifacts._WindowsRunStorage.open(
            Path("C:\\safe\\evaluation-run"),
            initialize=True,
            api=api,
        )

    assert api.probe_calls == 1
    assert api.created_directories == []
    assert api.handles == {}


@pytest.mark.parametrize(
    "unsafe_path",
    [
        r"\\server\share\evaluation-run",
        r"\\?\C:\safe\evaluation-run",
        r"\\.\C:\safe\evaluation-run",
        r"\Device\HarddiskVolume1\evaluation-run",
        r"C:evaluation-run",
    ],
)
def test_win32_rejects_unc_device_and_drive_relative_roots(unsafe_path: str) -> None:
    api = _FakeWin32API()

    with pytest.raises(EvaluationIntegrityError, match=r"drive-absolute|namespace"):
        attorney_artifacts._WindowsRunStorage.open(
            Path(unsafe_path),
            initialize=True,
            api=api,
        )

    assert api.root_open_calls == []
    assert api.relative_open_calls == []
    assert api.probe_calls == 0


def test_ctypes_win32_capability_probe_uses_only_root_and_relative_handles() -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\Temp")
    api._temporary_directory_path = lambda: r"C:\Temp"

    attorney_artifacts._CtypesWin32API.probe(api)  # type: ignore[arg-type]

    assert [call[0] for call in api.root_open_calls] == [_FakeWin32API._key("C:\\")]
    directory_share = _WIN_FILE_SHARE_READ | _WIN_FILE_SHARE_WRITE
    assert api.root_open_calls[0][2] == directory_share
    assert api.root_open_calls[0][2] & _WIN_FILE_SHARE_DELETE == 0
    assert api.relative_open_calls
    assert all(
        ntpath.basename(name) == name and "\\" not in name and "/" not in name
        for _, name, *_ in api.relative_open_calls
    )
    directory_creates = [
        call
        for call in api.relative_open_calls
        if call[4] == attorney_artifacts._WIN_FILE_CREATE
        and call[6] == _WIN_FILE_ATTRIBUTE_DIRECTORY
    ]
    assert len(directory_creates) == 2
    assert all(
        call[5] == attorney_artifacts._windows_directory_create_options()
        for call in directory_creates
    )
    retained_directory_calls = [
        call for call in api.relative_open_calls if call[2] & _WIN_FILE_TRAVERSE
    ]
    assert retained_directory_calls
    assert all(call[3] == directory_share for call in retained_directory_calls)
    assert all(call[3] & _WIN_FILE_SHARE_DELETE == 0 for call in retained_directory_calls)
    assert len(api.rename_calls) == 1
    assert api.deleted_names[-3:-1] == ["after", "child"]
    assert api.deleted_names[-1].startswith("regulatory-harvest-storage-probe-")
    assert api.path_child_calls == 0
    assert api.handles == {}
    assert set(api.nodes) == {
        _FakeWin32API._key("C:\\"),
        _FakeWin32API._key("C:\\Temp"),
    }


@pytest.mark.parametrize("failure_stage", ["reopen", "validate", "read"])
def test_ctypes_win32_capability_probe_cleans_tree_after_post_rename_failure(
    failure_stage: str,
) -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\Temp")
    api._temporary_directory_path = lambda: r"C:\Temp"

    if failure_stage == "reopen":

        def fail_reopen(_: int, name: str) -> None:
            if name == "after":
                raise OSError("injected post-rename reopen failure")

        api.before_relative_open = fail_reopen
    elif failure_stage == "validate":

        def fail_validation(handle: int) -> None:
            if api.handles[handle].name == "after" and handle != api.rename_calls[-1][0]:
                raise OSError("injected post-rename validation failure")

        api.before_file_info = fail_validation
    else:
        original_read = api.read_file

        def fail_read(handle: int) -> bytes:
            if api.handles[handle].name == "after":
                raise OSError("injected post-rename read failure")
            return original_read(handle)

        api.read_file = fail_read

    expected_stage = "validation" if failure_stage == "validate" else failure_stage
    with pytest.raises(OSError, match=f"post-rename {expected_stage} failure"):
        attorney_artifacts._CtypesWin32API.probe(api)  # type: ignore[arg-type]

    assert api.delete_attempt_names[-3] == "after"
    assert api.delete_attempt_names[-2] == "child"
    assert api.delete_attempt_names[-1].startswith("regulatory-harvest-storage-probe-")
    assert api.handles == {}
    assert set(api.nodes) == {
        _FakeWin32API._key("C:\\"),
        _FakeWin32API._key("C:\\Temp"),
    }


def test_ctypes_win32_capability_probe_preserves_primary_and_reports_cleanup_failure() -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\Temp")
    api._temporary_directory_path = lambda: r"C:\Temp"
    original_read = api.read_file

    def fail_read(handle: int) -> bytes:
        if api.handles[handle].name == "after":
            api.delete_errors_by_name["child"] = OSError("injected child cleanup failure")
            raise OSError("injected primary capability failure")
        return original_read(handle)

    api.read_file = fail_read

    with pytest.raises(EvaluationIntegrityError, match="cleanup also failed") as raised:
        attorney_artifacts._CtypesWin32API.probe(api)  # type: ignore[arg-type]

    assert raised.value.__cause__ is not None
    assert "injected primary capability failure" in str(raised.value.__cause__)
    assert "injected child cleanup failure" in str(raised.value)
    assert api.delete_attempt_names[0] == "after"
    assert api.handles == {}


def test_ctypes_win32_capability_probe_retries_reader_close_before_directories() -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\Temp")
    api._temporary_directory_path = lambda: r"C:\Temp"
    injected = False

    def fail_reader_close_once(handle: int) -> None:
        nonlocal injected
        if (
            not injected
            and api.rename_calls
            and api.handles[handle].name == "after"
            and handle != api.rename_calls[-1][0]
        ):
            injected = True
            raise OSError("injected post-rename reader close failure")

    api.before_close_handle = fail_reader_close_once

    with pytest.raises(OSError, match="reader close failure"):
        attorney_artifacts._CtypesWin32API.probe(api)  # type: ignore[arg-type]

    assert injected
    assert api.delete_attempt_names[-3] == "after"
    assert api.delete_attempt_names[-2] == "child"
    assert api.delete_attempt_names[-1].startswith("regulatory-harvest-storage-probe-")
    original_handle = api.rename_calls[-1][0]
    delete_file_index = next(
        index
        for index, event in enumerate(api.cleanup_events)
        if event == ("delete", "after", original_handle)
    )
    close_reader_index = next(
        index
        for index, (operation, name, handle) in enumerate(api.cleanup_events)
        if operation == "close" and name == "after" and handle != original_handle
    )
    delete_child_index = next(
        index
        for index, (operation, name, _) in enumerate(api.cleanup_events)
        if operation == "delete" and name == "child"
    )
    assert delete_file_index < close_reader_index < delete_child_index
    assert api.handles == {}
    assert set(api.nodes) == {
        _FakeWin32API._key("C:\\"),
        _FakeWin32API._key("C:\\Temp"),
    }


@pytest.mark.parametrize(
    "failure_stage",
    [
        "rename_postcheck",
        "file_delete",
        "file_close",
        "post_delete_query",
        "child_delete",
        "child_close",
        "probe_postcheck",
        "probe_delete",
        "probe_close",
    ],
)
def test_ctypes_win32_capability_probe_cleans_every_later_failure(
    failure_stage: str,
) -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\Temp")
    api._temporary_directory_path = lambda: r"C:\Temp"
    injected = False
    post_rename = False
    original_info = api.file_info
    original_query = api.query_names
    original_delete = api.delete_handle
    original_close = api.close_handle

    def mark_renamed(_: int, __: int, ___: str) -> None:
        nonlocal post_rename
        post_rename = True

    def fail_once() -> None:
        nonlocal injected
        if injected:
            return
        injected = True
        raise OSError(f"injected post-rename {failure_stage} failure")

    def file_info(handle: int) -> SimpleNamespace:
        node = api.handles[handle]
        if post_rename and failure_stage == "rename_postcheck" and node.name == "child":
            fail_once()
        if (
            post_rename
            and failure_stage == "probe_postcheck"
            and node.name.startswith("regulatory-harvest-storage-probe-")
            and "child" in api.deleted_names
        ):
            fail_once()
        return original_info(handle)

    def query_names(handle: int) -> list[str]:
        if (
            post_rename
            and failure_stage == "post_delete_query"
            and api.handles[handle].name == "child"
            and "after" in api.deleted_names
        ):
            fail_once()
        return original_query(handle)

    def delete_handle(handle: int) -> None:
        node = api.handles[handle]
        if post_rename and (
            (failure_stage == "file_delete" and node.name == "after")
            or (failure_stage == "child_delete" and node.name == "child")
            or (
                failure_stage == "probe_delete"
                and node.name.startswith("regulatory-harvest-storage-probe-")
            )
        ):
            fail_once()
        original_delete(handle)

    def close_handle(handle: int) -> None:
        node = api.handles[handle]
        if post_rename and (
            (
                failure_stage == "file_close"
                and node.name == "after"
                and handle == api.rename_calls[-1][0]
            )
            or (failure_stage == "child_close" and node.name == "child")
            or (
                failure_stage == "probe_close"
                and node.name.startswith("regulatory-harvest-storage-probe-")
            )
        ):
            fail_once()
        original_close(handle)

    api.after_rename = mark_renamed
    api.file_info = file_info
    api.query_names = query_names
    api.delete_handle = delete_handle
    api.close_handle = close_handle

    with pytest.raises(OSError, match=f"post-rename {failure_stage} failure"):
        attorney_artifacts._CtypesWin32API.probe(api)  # type: ignore[arg-type]

    assert injected
    assert api.delete_attempt_names[-3] == "after"
    assert api.delete_attempt_names[-2] == "child"
    assert api.delete_attempt_names[-1].startswith("regulatory-harvest-storage-probe-")
    assert api.handles == {}
    assert set(api.nodes) == {
        _FakeWin32API._key("C:\\"),
        _FakeWin32API._key("C:\\Temp"),
    }


def test_win32_dynamic_parent_reparse_race_cannot_redirect_read() -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\safe")
    storage = attorney_artifacts._WindowsRunStorage.open(
        Path("C:\\safe\\evaluation-run"),
        initialize=True,
        api=api,
    )
    api.add_directory("C:\\safe\\evaluation-run\\judge-requests")
    api.add_file(
        "C:\\safe\\evaluation-run\\judge-requests\\request.json",
        b"trusted\n",
    )
    api.add_directory("C:\\outside")
    api.add_file("C:\\outside\\request.json", b"outside\n")
    raced = False

    def race() -> None:
        nonlocal raced
        if raced:
            return
        raced = True
        api.replace_directory_with_reparse(
            "C:\\safe\\evaluation-run\\judge-requests",
            "C:\\outside",
        )

    def race_path(path: str) -> None:
        if ntpath.basename(path) == "request.json":
            race()

    def race_relative(_: int, name: str) -> None:
        if name == "request.json":
            race()

    api.before_path_open = race_path
    api.before_relative_open = race_relative
    try:
        with pytest.raises(EvaluationIntegrityError, match=r"reparse|identity"):
            storage.read_artifact("judge-requests/request.json")
    finally:
        storage.close()

    assert raced
    assert _FakeWin32API._key("C:\\outside") not in api.read_parent_paths
    assert api.path_child_calls == 0
    assert api.handles == {}


def test_win32_child_open_rechecks_parent_before_using_opened_child() -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\safe")
    storage = attorney_artifacts._WindowsRunStorage.open(
        Path("C:\\safe\\evaluation-run"),
        initialize=True,
        api=api,
    )
    api.add_directory("C:\\safe\\evaluation-run\\judge-requests")
    api.add_file(
        "C:\\safe\\evaluation-run\\judge-requests\\request.json",
        b"trusted\n",
    )
    api.add_directory("C:\\outside")
    api.add_file("C:\\outside\\request.json", b"outside\n")
    raced = False

    def mutate_after_open(parent_handle: int, name: str, _: int) -> None:
        nonlocal raced
        if raced or name != "request.json":
            return
        raced = True
        parent = api.handles[parent_handle]
        parent.attributes |= _WIN_FILE_ATTRIBUTE_REPARSE_POINT
        parent.reparse_tag = 0xA0000003
        parent.redirect = api._resolve_absolute("C:\\outside", follow_final_reparse=True)

    api.after_relative_open = mutate_after_open
    try:
        with pytest.raises(EvaluationIntegrityError, match="reparse"):
            storage.read_artifact("judge-requests/request.json")
    finally:
        storage.close()

    assert raced
    assert api.read_parent_paths == []
    assert api.path_child_calls == 0
    assert api.handles == {}


def test_win32_dynamic_parent_reparse_race_cannot_redirect_write() -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\safe")
    storage = attorney_artifacts._WindowsRunStorage.open(
        Path("C:\\safe\\evaluation-run"),
        initialize=True,
        api=api,
    )
    api.add_directory("C:\\safe\\evaluation-run\\judge-responses")
    api.add_directory("C:\\outside")
    raced = False

    def race() -> None:
        nonlocal raced
        if raced:
            return
        raced = True
        api.replace_directory_with_reparse(
            "C:\\safe\\evaluation-run\\judge-responses",
            "C:\\outside",
        )

    def race_path(path: str) -> None:
        if ntpath.basename(path) == "response.json":
            race()

    def race_relative(_: int, name: str) -> None:
        if name == "response.json":
            race()

    api.before_path_open = race_path
    api.before_relative_open = race_relative
    try:
        with pytest.raises(EvaluationIntegrityError, match=r"reparse|identity"):
            storage.atomic_write(
                "judge-responses/response.json",
                b"trusted write\n",
                mutable=False,
            )
    finally:
        storage.close()

    assert raced
    assert _FakeWin32API._key("C:\\outside") not in api.write_parent_paths
    outside = api._resolve_absolute("C:\\outside", follow_final_reparse=True)
    assert outside.children == {}
    assert api.path_child_calls == 0
    assert api.handles == {}


def test_win32_dynamic_parent_race_during_temp_create_cleans_bound_temp() -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\safe")
    storage = attorney_artifacts._WindowsRunStorage.open(
        Path("C:\\safe\\evaluation-run"),
        initialize=True,
        api=api,
    )
    api.add_directory("C:\\safe\\evaluation-run\\judge-responses")
    api.add_directory("C:\\outside")
    trusted_parent = api._resolve_absolute(
        "C:\\safe\\evaluation-run\\judge-responses",
        follow_final_reparse=False,
    )
    raced = False

    def race_relative(_: int, name: str) -> None:
        nonlocal raced
        if raced or not name.startswith(".rh-"):
            return
        raced = True
        api.replace_directory_with_reparse(
            "C:\\safe\\evaluation-run\\judge-responses",
            "C:\\outside",
        )

    api.before_relative_open = race_relative
    try:
        with pytest.raises(EvaluationIntegrityError, match=r"reparse|identity"):
            storage.atomic_write(
                "judge-responses/response.json",
                b"trusted write\n",
                mutable=False,
            )
    finally:
        storage.close()

    assert raced
    assert _FakeWin32API._key("C:\\outside") not in api.write_parent_paths
    assert api.deleted_handles
    assert not any(".rh-" in key for key in api.nodes)
    assert not any(name.startswith(".rh-") for name in trusted_parent.children)
    outside = api._resolve_absolute("C:\\outside", follow_final_reparse=True)
    assert outside.children == {}
    assert api.path_child_calls == 0
    assert api.handles == {}


def test_win32_temp_create_parent_postcheck_cleans_new_file() -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\safe")
    storage = attorney_artifacts._WindowsRunStorage.open(
        Path("C:\\safe\\evaluation-run"),
        initialize=True,
        api=api,
    )
    api.add_directory("C:\\safe\\evaluation-run\\judge-responses")
    trusted_parent = api._resolve_absolute(
        "C:\\safe\\evaluation-run\\judge-responses",
        follow_final_reparse=False,
    )
    raced = False

    def mutate_parent_after_temp_open(parent_handle: int, name: str, _: int) -> None:
        nonlocal raced
        if raced or not name.startswith(".rh-"):
            return
        raced = True
        parent = api.handles[parent_handle]
        parent.attributes |= _WIN_FILE_ATTRIBUTE_REPARSE_POINT
        parent.reparse_tag = 0xA0000003

    api.after_relative_open = mutate_parent_after_temp_open
    try:
        with pytest.raises(EvaluationIntegrityError, match="reparse"):
            storage.atomic_write(
                "judge-responses/response.json",
                b"trusted write\n",
                mutable=False,
            )
    finally:
        storage.close()

    assert raced
    assert not any(name.startswith(".rh-") for name in trusted_parent.children)
    assert api.handles == {}


def test_win32_write_flushes_and_renames_relative_to_retained_parent() -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\safe")
    storage = attorney_artifacts._WindowsRunStorage.open(
        Path("C:\\safe\\evaluation-run"),
        initialize=True,
        api=api,
    )

    try:
        storage.atomic_write(
            "judge-requests/admission-attempt-1.json",
            b'{"request":true}\n',
            mutable=False,
        )
    finally:
        storage.close()

    assert api.flushed_handles
    assert len(api.rename_calls) == 1
    renamed_handle, _, new_name, replace = api.rename_calls[0]
    assert renamed_handle in api.flushed_handles
    assert api.rename_root_paths == [_FakeWin32API._key("C:\\safe\\evaluation-run\\judge-requests")]
    assert new_name == "admission-attempt-1.json"
    assert not replace
    final_path = _FakeWin32API._key(
        "C:\\safe\\evaluation-run\\judge-requests\\admission-attempt-1.json"
    )
    assert api.contents[final_path] == b'{"request":true}\n'
    directory_share = _WIN_FILE_SHARE_READ | _WIN_FILE_SHARE_WRITE
    retained_directory_calls = [
        call for call in api.relative_open_calls if call[2] & _WIN_FILE_TRAVERSE
    ]
    assert retained_directory_calls
    assert all(call[3] == directory_share for call in retained_directory_calls)
    assert all(call[3] & _WIN_FILE_SHARE_DELETE == 0 for call in api.relative_open_calls)
    assert api.path_child_calls == 0
    assert api.handles == {}


def test_win32_runtime_rooted_rename_replaces_only_a_mutable_observed_target() -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\safe")
    storage = attorney_artifacts._WindowsRunStorage.open(
        Path("C:\\safe\\evaluation-run"),
        initialize=True,
        api=api,
    )
    api.add_file("C:\\safe\\evaluation-run\\mutable.json", b"old\n")

    try:
        storage.atomic_write("mutable.json", b"new\n", mutable=True)
    finally:
        storage.close()

    assert api.rename_calls[-1][3] is True
    assert api.rename_root_paths[-1] == _FakeWin32API._key("C:\\safe\\evaluation-run")
    assert api.contents[_FakeWin32API._key("C:\\safe\\evaluation-run\\mutable.json")] == b"new\n"
    assert all(
        call[3] == (_WIN_FILE_SHARE_READ | _WIN_FILE_SHARE_WRITE)
        for call in api.relative_open_calls
        if call[2] & _WIN_FILE_TRAVERSE
    )
    assert all(call[3] & _WIN_FILE_SHARE_DELETE == 0 for call in api.relative_open_calls)
    assert api.handles == {}


@pytest.mark.parametrize(
    "failure_stage",
    [
        "temp_metadata",
        "write_chunk",
        "flush",
        "temp_postcheck",
        "target_binding",
        "root_identity",
        "rename_call",
        "rename_postcheck",
    ],
)
def test_win32_atomic_write_primary_failures_dispose_temp_before_close(
    failure_stage: str,
) -> None:
    api, storage, parent = _fake_windows_artifact_storage()
    primary = OSError(f"injected {failure_stage} failure")
    original_file_info = api.file_info
    original_write = api.write_file
    original_flush = api.flush_file
    original_bindings = storage._assert_relative_bindings
    original_root_identity = storage.assert_root_identity
    temp_info_calls = 0
    native_rename_completed = False

    def file_info(handle: int) -> SimpleNamespace:
        nonlocal temp_info_calls
        node = api.handles[handle]
        if api.temporary_handles and handle == api.temporary_handles[-1]:
            temp_info_calls += 1
            if failure_stage == "temp_metadata" and temp_info_calls == 1:
                raise primary
            if failure_stage == "temp_postcheck" and temp_info_calls == 2:
                raise primary
        if failure_stage == "rename_postcheck" and native_rename_completed and node is parent:
            raise primary
        return original_file_info(handle)

    def write_file(handle: int, data: bytes) -> None:
        if failure_stage == "write_chunk" and handle == api.temporary_handles[-1]:
            raise primary
        original_write(handle, data)

    def flush_file(handle: int) -> None:
        if failure_stage == "flush" and handle == api.temporary_handles[-1]:
            raise primary
        original_flush(handle)

    def assert_bindings(bindings: tuple[attorney_artifacts._WindowsAnchor, ...]) -> None:
        if failure_stage == "target_binding" and api.temporary_handles:
            raise primary
        original_bindings(bindings)

    def assert_root_identity() -> None:
        if failure_stage == "root_identity" and api.temporary_handles:
            raise primary
        original_root_identity()

    def before_rename(_: int, __: int, ___: str) -> None:
        if failure_stage == "rename_call":
            raise primary

    def after_rename(_: int, __: int, ___: str) -> None:
        nonlocal native_rename_completed
        native_rename_completed = True

    api.file_info = file_info
    api.write_file = write_file
    api.flush_file = flush_file
    storage._assert_relative_bindings = assert_bindings
    storage.assert_root_identity = assert_root_identity
    api.before_rename = before_rename
    api.after_rename = after_rename

    try:
        with pytest.raises(OSError) as raised:
            storage.atomic_write(
                "judge-responses/response.json",
                b"trusted write\n",
                mutable=False,
            )
    finally:
        storage.close()

    assert raised.value is primary
    temp_handle = api.temporary_handles[-1]
    delete_index = next(
        index
        for index, (operation, _, handle) in enumerate(api.cleanup_events)
        if operation == "delete" and handle == temp_handle
    )
    close_index = next(
        index
        for index, (operation, _, handle) in enumerate(api.cleanup_events)
        if operation == "close" and handle == temp_handle
    )
    assert delete_index < close_index
    assert parent.children == {}
    assert not any(".rh-" in path for path in api.nodes)
    assert api.handles == {}


def test_win32_atomic_write_reports_disposition_failure_without_masking_primary() -> None:
    api, storage, parent = _fake_windows_artifact_storage()
    primary = OSError("injected production write failure")
    disposition_error = OSError("injected temp disposition failure")
    original_write = api.write_file
    close_attempts: list[int] = []

    def write_file(handle: int, data: bytes) -> None:
        if handle == api.temporary_handles[-1]:
            raise primary
        original_write(handle, data)

    def fail_disposition(handle: int) -> None:
        if handle == api.temporary_handles[-1]:
            raise disposition_error

    def record_close(handle: int) -> None:
        if api.temporary_handles and handle == api.temporary_handles[-1]:
            close_attempts.append(handle)

    api.write_file = write_file
    api.before_delete_handle = fail_disposition
    api.before_close_handle = record_close

    try:
        with pytest.raises(EvaluationIntegrityError, match="cleanup also failed") as raised:
            storage.atomic_write(
                "judge-responses/response.json",
                b"trusted write\n",
                mutable=False,
            )
    finally:
        storage.close()

    assert raised.value.__cause__ is primary
    assert "dispose temporary artifact" in str(raised.value)
    assert "injected temp disposition failure" in str(raised.value)
    temp_handle = api.temporary_handles[-1]
    assert close_attempts == [temp_handle]
    assert temp_handle in api.closed_handles
    assert api.handles == {}
    assert any(name.startswith(".rh-") for name in parent.children)


def test_win32_atomic_write_reports_close_failure_without_masking_primary() -> None:
    api, storage, parent = _fake_windows_artifact_storage()
    primary = OSError("injected production write failure")
    close_error = OSError("injected temp close failure")
    original_write = api.write_file
    close_attempts: list[int] = []

    def write_file(handle: int, data: bytes) -> None:
        if handle == api.temporary_handles[-1]:
            raise primary
        original_write(handle, data)

    def fail_close(handle: int) -> None:
        if api.temporary_handles and handle == api.temporary_handles[-1]:
            close_attempts.append(handle)
            raise close_error

    api.write_file = write_file
    api.before_close_handle = fail_close

    try:
        with pytest.raises(EvaluationIntegrityError, match="cleanup also failed") as raised:
            storage.atomic_write(
                "judge-responses/response.json",
                b"trusted write\n",
                mutable=False,
            )
    finally:
        storage.close()

    assert raised.value.__cause__ is primary
    assert "close temporary artifact" in str(raised.value)
    assert "injected temp close failure" in str(raised.value)
    temp_handle = api.temporary_handles[-1]
    assert close_attempts == [temp_handle]
    assert temp_handle in api.handles
    assert any(name.startswith(".rh-") for name in parent.children)


def test_win32_atomic_write_orders_multiple_cleanup_failures() -> None:
    api, storage, _ = _fake_windows_artifact_storage()
    primary = OSError("injected production write failure")
    disposition_error = OSError("first cleanup failure")
    close_error = OSError("second cleanup failure")

    def fail_write(_: int, __: bytes) -> None:
        raise primary

    def fail_disposition(handle: int) -> None:
        if handle == api.temporary_handles[-1]:
            raise disposition_error

    def fail_close(handle: int) -> None:
        if api.temporary_handles and handle == api.temporary_handles[-1]:
            raise close_error

    api.write_file = fail_write
    api.before_delete_handle = fail_disposition
    api.before_close_handle = fail_close

    try:
        with pytest.raises(EvaluationIntegrityError, match="cleanup also failed") as raised:
            storage.atomic_write(
                "judge-responses/response.json",
                b"trusted write\n",
                mutable=False,
            )
    finally:
        storage.close()

    assert raised.value.__cause__ is primary
    message = str(raised.value)
    assert message.index("dispose temporary artifact") < message.index("close temporary artifact")
    assert "first cleanup failure" in message
    assert "second cleanup failure" in message
    assert api.temporary_handles[-1] in api.handles


def test_win32_atomic_write_surfaces_cleanup_only_failure_after_successful_rename() -> None:
    api, storage, parent = _fake_windows_artifact_storage()
    close_error = OSError("injected renamed handle close failure")

    def fail_close(handle: int) -> None:
        if api.temporary_handles and handle == api.temporary_handles[-1]:
            raise close_error

    api.before_close_handle = fail_close

    try:
        with pytest.raises(EvaluationIntegrityError, match="cleanup failed") as raised:
            storage.atomic_write(
                "judge-responses/response.json",
                b"trusted write\n",
                mutable=False,
            )
    finally:
        storage.close()

    assert raised.value.__cause__ is close_error
    assert "close renamed artifact" in str(raised.value)
    assert ntpath.normcase("response.json") in parent.children
    assert parent.children[ntpath.normcase("response.json")].content == b"trusted write\n"
    assert not any(name.startswith(".rh-") for name in parent.children)
    temp_handle = api.temporary_handles[-1]
    assert temp_handle in api.handles
    assert temp_handle not in api.deleted_handles


def test_win32_inventory_rejects_reparse_artifact_without_leaking_handles() -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\safe")
    storage = attorney_artifacts._WindowsRunStorage.open(
        Path("C:\\safe\\evaluation-run"),
        initialize=True,
        api=api,
    )
    api.add_file(
        "C:\\safe\\evaluation-run\\escape.json",
        b"{}\n",
        reparse=True,
    )

    with pytest.raises(EvaluationIntegrityError, match="reparse"):
        storage.scan_inventory()

    storage.close()
    assert api.handles == {}


def test_win32_inventory_dynamic_parent_race_never_descends_into_redirect() -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\safe")
    storage = attorney_artifacts._WindowsRunStorage.open(
        Path("C:\\safe\\evaluation-run"),
        initialize=True,
        api=api,
    )
    api.add_directory("C:\\safe\\evaluation-run\\nested")
    api.add_file("C:\\safe\\evaluation-run\\nested\\trusted.json", b"trusted\n")
    api.add_directory("C:\\outside")
    api.add_file("C:\\outside\\trusted.json", b"outside\n")
    raced = False

    def race_relative(_: int, name: str) -> None:
        nonlocal raced
        if raced or name != "trusted.json":
            return
        raced = True
        api.replace_directory_with_reparse(
            "C:\\safe\\evaluation-run\\nested",
            "C:\\outside",
        )

    api.before_relative_open = race_relative
    try:
        with pytest.raises(EvaluationIntegrityError, match=r"reparse|identity"):
            storage.scan_inventory()
    finally:
        storage.close()

    assert raced
    assert api.path_child_calls == 0
    assert api.handles == {}


def test_win32_inventory_rechecks_directory_immediately_after_enumeration() -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\safe")
    storage = attorney_artifacts._WindowsRunStorage.open(
        Path("C:\\safe\\evaluation-run"),
        initialize=True,
        api=api,
    )
    api.add_file("C:\\safe\\evaluation-run\\trusted.json", b"trusted\n")
    api.add_directory("C:\\outside")
    api.add_file("C:\\outside\\outside.json", b"outside\n")
    calls_before_scan = len(api.relative_open_calls)
    raced = False

    def mutate_after_query(directory_handle: int) -> None:
        nonlocal raced
        if raced or directory_handle != storage._root_handle:
            return
        raced = True
        directory = api.handles[directory_handle]
        directory.attributes |= _WIN_FILE_ATTRIBUTE_REPARSE_POINT
        directory.reparse_tag = 0xA0000003
        directory.redirect = api._resolve_absolute("C:\\outside", follow_final_reparse=True)

    api.after_query_names = mutate_after_query
    try:
        with pytest.raises(EvaluationIntegrityError, match="reparse"):
            storage.scan_inventory()
    finally:
        storage.close()

    assert raced
    scan_opens = api.relative_open_calls[calls_before_scan:]
    assert all(call[1] != "trusted.json" for call in scan_opens)
    assert all(call[1] != "outside.json" for call in scan_opens)
    assert api.handles == {}


def test_win32_rooted_rename_rechecks_parent_without_redirecting_write() -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\safe")
    storage = attorney_artifacts._WindowsRunStorage.open(
        Path("C:\\safe\\evaluation-run"),
        initialize=True,
        api=api,
    )
    api.add_directory("C:\\safe\\evaluation-run\\judge-responses")
    api.add_directory("C:\\outside")
    trusted_parent = api._resolve_absolute(
        "C:\\safe\\evaluation-run\\judge-responses",
        follow_final_reparse=False,
    )
    outside = api._resolve_absolute("C:\\outside", follow_final_reparse=True)
    raced = False

    def mutate_after_rename(_: int, root_directory: int, __: str) -> None:
        nonlocal raced
        raced = True
        parent = api.handles[root_directory]
        parent.attributes |= _WIN_FILE_ATTRIBUTE_REPARSE_POINT
        parent.reparse_tag = 0xA0000003
        parent.redirect = outside

    api.after_rename = mutate_after_rename
    try:
        with pytest.raises(EvaluationIntegrityError, match="reparse"):
            storage.atomic_write(
                "judge-responses/response.json",
                b"trusted write\n",
                mutable=False,
            )
    finally:
        storage.close()

    assert raced
    assert trusted_parent.children == {}
    assert outside.children == {}
    assert "response.json" in api.deleted_names
    assert api.handles == {}


def test_win32_inventory_rejects_reparse_tag_without_attribute_bit() -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\safe")
    storage = attorney_artifacts._WindowsRunStorage.open(
        Path("C:\\safe\\evaluation-run"),
        initialize=True,
        api=api,
    )
    artifact_path = "C:\\safe\\evaluation-run\\tagged.json"
    api.add_file(artifact_path, b"{}\n")
    api.nodes[_FakeWin32API._key(artifact_path)].reparse_tag = 0xA000000C

    with pytest.raises(EvaluationIntegrityError, match="reparse"):
        storage.scan_inventory()

    storage.close()
    assert api.handles == {}


def test_win32_read_uses_reparse_handle_without_delete_or_write_sharing() -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\safe")
    storage = attorney_artifacts._WindowsRunStorage.open(
        Path("C:\\safe\\evaluation-run"),
        initialize=True,
        api=api,
    )
    artifact_path = "C:\\safe\\evaluation-run\\case-envelope.json"
    api.add_file(artifact_path, b'{"case":true}\n')

    try:
        data = storage.read_artifact("case-envelope.json")
    finally:
        storage.close()

    assert data == b'{"case":true}\n'
    artifact_opens = [call for call in api.relative_open_calls if call[1] == "case-envelope.json"]
    assert artifact_opens
    _, _, _, share_mode, _, options, _ = artifact_opens[-1]
    assert share_mode == 1
    assert share_mode & _WIN_FILE_SHARE_DELETE == 0
    assert options & 0x00200000
    assert api.path_child_calls == 0
    assert api.handles == {}


def test_win32_inventory_rejects_hard_linked_artifact() -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\safe")
    storage = attorney_artifacts._WindowsRunStorage.open(
        Path("C:\\safe\\evaluation-run"),
        initialize=True,
        api=api,
    )
    artifact_path = "C:\\safe\\evaluation-run\\hard-linked.json"
    api.add_file(artifact_path, b"{}\n")
    api.nodes[_FakeWin32API._key(artifact_path)].link_count = 2

    with pytest.raises(EvaluationIntegrityError, match="hard link"):
        storage.scan_inventory()

    storage.close()
    assert api.handles == {}


def test_win32_write_error_is_controlled_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\safe")
    monkeypatch.setattr(attorney_artifacts, "_storage_platform", lambda: "nt")
    monkeypatch.setattr(attorney_artifacts, "_new_win32_api", lambda: api)

    def failed_write(_: int, __: bytes) -> None:
        raise OSError("injected Win32 write failure")

    monkeypatch.setattr(api, "write_file", failed_write)

    with (
        pytest.raises(EvaluationIntegrityError, match="artifact write"),
        attorney_artifacts._open_run_storage(
            Path("C:\\safe\\evaluation-run"),
            initialize=True,
        ) as storage,
    ):
        storage.atomic_write("failed.json", b"{}\n", mutable=False)

    assert api.deleted_handles
    assert not any(key.endswith(".tmp") for key in api.nodes)
    assert api.path_child_calls == 0
    assert api.handles == {}


def test_storage_factory_selects_win32_handle_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\safe")
    monkeypatch.setattr(
        attorney_artifacts,
        "_storage_platform",
        lambda: "nt",
        raising=False,
    )
    monkeypatch.setattr(
        attorney_artifacts,
        "_new_win32_api",
        lambda: api,
        raising=False,
    )

    with attorney_artifacts._open_run_storage(
        Path("C:\\safe\\evaluation-run"),
        initialize=True,
    ) as storage:
        assert isinstance(storage, attorney_artifacts._WindowsRunStorage)

    assert api.probe_calls == 1
    assert api.handles == {}


def test_mock_win32_backend_initializes_resumes_and_verifies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\safe")
    run_dir = Path("C:\\safe\\evaluation-run")
    monkeypatch.setattr(attorney_artifacts, "_storage_platform", lambda: "nt")
    monkeypatch.setattr(attorney_artifacts, "_new_win32_api", lambda: api)

    initialized = initialize_evaluation(
        synthetic_case(comparator=False),
        run_dir,
        seed_hex="e" * 64,
    )
    resumed = resume_evaluation(run_dir)
    verification = verify_evaluation_run(run_dir)

    assert initialized == resumed
    assert verification.valid
    assert verification.root_hash == initialized.manifest_fingerprint
    assert api.probe_calls == 1
    assert api.handles == {}


def test_ctypes_win32_relative_rename_supports_short_leaf_names() -> None:
    api = object.__new__(attorney_artifacts._CtypesWin32API)
    observed: dict[str, object] = {}

    def set_file_information(
        handle: object,
        information_class: int,
        buffer: object,
        buffer_size: int,
    ) -> int:
        information = attorney_artifacts._FileRenameInformation.from_buffer(buffer)
        observed.update(
            {
                "handle": handle,
                "information_class": information_class,
                "root_directory": information.root_directory,
                "name_length": information.file_name_length,
                "buffer_size": buffer_size,
            }
        )
        return 1

    api._set_file_information = set_file_information

    api.rename_file(11, root_directory=22, new_name="a", replace=False)

    assert observed["information_class"] == 3
    assert observed["root_directory"] == 22
    assert observed["name_length"] == 2
    assert observed["buffer_size"] >= attorney_artifacts.ctypes.sizeof(
        attorney_artifacts._FileRenameInformation
    )


def test_ctypes_win32_cleanup_marks_open_handle_for_disposition() -> None:
    api = object.__new__(attorney_artifacts._CtypesWin32API)
    observed: dict[str, int] = {}

    def set_file_information(
        _: object,
        information_class: int,
        buffer: object,
        buffer_size: int,
    ) -> int:
        information = attorney_artifacts.ctypes.cast(
            buffer,
            attorney_artifacts.ctypes.POINTER(attorney_artifacts._FileDispositionInformation),
        ).contents
        observed.update(
            {
                "information_class": information_class,
                "delete_file": information.delete_file,
                "buffer_size": buffer_size,
            }
        )
        return 1

    api._set_file_information = set_file_information

    api.delete_handle(11)

    assert observed == {
        "information_class": attorney_artifacts._WIN_FILE_DISPOSITION_INFO_CLASS,
        "delete_file": 1,
        "buffer_size": 1,
    }


@pytest.mark.parametrize(("delete_file", "serialized"), [(0, b"\x00"), (1, b"\x01")])
def test_ctypes_win32_disposition_serializes_a_one_byte_boolean(
    delete_file: int,
    serialized: bytes,
) -> None:
    information = attorney_artifacts._FileDispositionInformation(delete_file=delete_file)

    assert attorney_artifacts.ctypes.sizeof(information) == 1
    assert bytes(information) == serialized


def test_ctypes_ntcreatefile_binds_name_to_supplied_parent_handle() -> None:
    api = object.__new__(attorney_artifacts._CtypesWin32API)
    observed: dict[str, object] = {}

    def nt_create_file(
        output_handle: object,
        desired_access: int,
        object_attributes: object,
        _: object,
        __: object,
        file_attributes: int,
        share_access: int,
        disposition: int,
        create_options: int,
        ___: object,
        ____: int,
    ) -> int:
        output = attorney_artifacts.ctypes.cast(
            output_handle,
            attorney_artifacts.ctypes.POINTER(attorney_artifacts.ctypes.c_void_p),
        )
        output.contents.value = 321
        attributes = attorney_artifacts.ctypes.cast(
            object_attributes,
            attorney_artifacts.ctypes.POINTER(attorney_artifacts._ObjectAttributes),
        ).contents
        unicode_name = attributes.object_name.contents
        observed.update(
            {
                "desired_access": desired_access,
                "root_directory": attributes.root_directory,
                "attributes": attributes.attributes,
                "name": attorney_artifacts.ctypes.string_at(
                    unicode_name.buffer,
                    unicode_name.length,
                ).decode("utf-16-le"),
                "file_attributes": file_attributes,
                "share_access": share_access,
                "disposition": disposition,
                "create_options": create_options,
            }
        )
        return 0

    api._nt_create_file = nt_create_file

    handle = api.open_relative(
        77,
        "child.json",
        0x123,
        1,
        attorney_artifacts._WIN_FILE_OPEN,
        attorney_artifacts._windows_file_options(),
        0,
    )

    assert handle == 321
    assert observed == {
        "desired_access": 0x123,
        "root_directory": 77,
        "attributes": attorney_artifacts._WIN_OBJ_CASE_INSENSITIVE,
        "name": "child.json",
        "file_attributes": 0,
        "share_access": 1,
        "disposition": attorney_artifacts._WIN_FILE_OPEN,
        "create_options": attorney_artifacts._windows_file_options(),
    }


def test_ctypes_ntquerydirectoryfile_parses_handle_relative_names() -> None:
    api = object.__new__(attorney_artifacts._CtypesWin32API)
    restarts: list[int] = []

    def nt_query_directory_file(*arguments: object) -> int:
        restarts.append(int(arguments[10]))
        if len(restarts) > 1:
            return attorney_artifacts.ctypes.c_int32(
                attorney_artifacts._WIN_STATUS_NO_MORE_FILES
            ).value
        io_status = attorney_artifacts.ctypes.cast(
            arguments[4],
            attorney_artifacts.ctypes.POINTER(attorney_artifacts._IOStatusBlock),
        ).contents
        output = arguments[5]
        encoded = "child.json".encode("utf-16-le")
        payload = (
            (0).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
            + len(encoded).to_bytes(4, "little")
            + encoded
        )
        attorney_artifacts.ctypes.memmove(output, payload, len(payload))
        io_status.information = len(payload)
        return 0

    api._nt_query_directory_file = nt_query_directory_file

    assert api.query_names(55) == ["child.json"]
    assert restarts == [1, 0]


@pytest.mark.parametrize(
    ("status", "expected"),
    [(0, True), (0x40000000, True), (0x80000006, False), (0xC0000001, False)],
)
def test_ctypes_nt_success_uses_signed_fixed_width_status(
    status: int,
    expected: bool,
) -> None:
    assert attorney_artifacts._nt_success(status) is expected
    assert attorney_artifacts._ntstatus_code(status) == status


def test_ctypes_nt_errors_map_known_statuses_and_translate_unknown_status() -> None:
    api = object.__new__(attorney_artifacts._CtypesWin32API)
    translated: list[int] = []

    def translate(status: object) -> int:
        translated.append(int(status.value))
        return 5

    api._rtl_nt_status_to_dos_error = translate

    assert isinstance(
        api._nt_error(attorney_artifacts._WIN_STATUS_OBJECT_NAME_NOT_FOUND, "missing"),
        FileNotFoundError,
    )
    assert isinstance(
        api._nt_error(attorney_artifacts._WIN_STATUS_OBJECT_NAME_COLLISION, "existing"),
        FileExistsError,
    )
    denied = api._nt_error(0xC0000022, "denied")
    assert isinstance(denied, OSError)
    assert denied.errno == 5
    assert translated == [attorney_artifacts.ctypes.c_int32(0xC0000022).value]


def test_ctypes_file_info_queries_reparse_tag_and_fixed_identity() -> None:
    api = object.__new__(attorney_artifacts._CtypesWin32API)
    observed_classes: list[int] = []

    def get_information(_: object, output: object) -> int:
        value = attorney_artifacts.ctypes.cast(
            output,
            attorney_artifacts.ctypes.POINTER(attorney_artifacts._ByHandleFileInformation),
        ).contents
        value.attributes = _WIN_FILE_ATTRIBUTE_DIRECTORY
        value.volume_serial = 7
        value.file_index_high = 1
        value.file_index_low = 2
        value.link_count = 1
        value.size_high = 3
        value.size_low = 4
        value.last_write_time.high = 5
        value.last_write_time.low = 6
        return 1

    def get_information_ex(
        _: object,
        information_class: int,
        output: object,
        size: int,
    ) -> int:
        observed_classes.append(information_class)
        assert size == attorney_artifacts.ctypes.sizeof(
            attorney_artifacts._FileAttributeTagInformation
        )
        value = attorney_artifacts.ctypes.cast(
            output,
            attorney_artifacts.ctypes.POINTER(attorney_artifacts._FileAttributeTagInformation),
        ).contents
        value.attributes = _WIN_FILE_ATTRIBUTE_DIRECTORY | _WIN_FILE_ATTRIBUTE_REPARSE_POINT
        value.reparse_tag = 0xA000000C
        return 1

    api._get_file_information = get_information
    api._get_file_information_ex = get_information_ex
    api._get_file_type = lambda _: 1

    info = api.file_info(44)

    assert info.attributes == (_WIN_FILE_ATTRIBUTE_DIRECTORY | _WIN_FILE_ATTRIBUTE_REPARSE_POINT)
    assert info.reparse_tag == 0xA000000C
    assert info.volume_serial == 7
    assert info.file_index == (1 << 32) | 2
    assert info.link_count == 1
    assert info.size == (3 << 32) | 4
    assert info.write_time == (5 << 32) | 6
    assert observed_classes == [attorney_artifacts._WIN_FILE_ATTRIBUTE_TAG_INFO_CLASS]


def test_ctypes_win32_structures_use_fixed_windows_field_widths() -> None:
    pointer_size = attorney_artifacts.ctypes.sizeof(attorney_artifacts.ctypes.c_void_p)
    assert attorney_artifacts.ctypes.sizeof(attorney_artifacts._WinDword) == 4
    assert attorney_artifacts.ctypes.sizeof(attorney_artifacts._WinBool) == 4
    assert attorney_artifacts._WinDword is attorney_artifacts.ctypes.c_uint32
    assert attorney_artifacts._WinBool is attorney_artifacts.ctypes.c_int32
    assert attorney_artifacts.ctypes.sizeof(attorney_artifacts._WinFileTime) == 8
    assert attorney_artifacts.ctypes.sizeof(attorney_artifacts._ByHandleFileInformation) == 52
    assert attorney_artifacts._FileRenameInformation.root_directory.offset == (
        8 if pointer_size == 8 else 4
    )
    assert attorney_artifacts._FileRenameInformation.file_name_length.offset == (
        16 if pointer_size == 8 else 8
    )
    assert attorney_artifacts._FileRenameInformation.file_name.offset == (
        20 if pointer_size == 8 else 12
    )
    assert attorney_artifacts.ctypes.sizeof(attorney_artifacts._FileRenameInformation) == (
        24 if pointer_size == 8 else 16
    )
    assert attorney_artifacts._FileRenameInformation.file_name_length.size == 4
    assert attorney_artifacts._FileRenameInformation.file_name.size == 2
    assert attorney_artifacts._UnicodeString.length.size == 2
    assert attorney_artifacts._UnicodeString.maximum_length.size == 2
    assert attorney_artifacts._UnicodeString.buffer.offset == (8 if pointer_size == 8 else 4)
    assert attorney_artifacts.ctypes.sizeof(attorney_artifacts._UnicodeString) == (
        16 if pointer_size == 8 else 8
    )
    assert attorney_artifacts._ObjectAttributes.length.size == 4
    assert attorney_artifacts._ObjectAttributes.attributes.size == 4
    assert attorney_artifacts._ObjectAttributes.root_directory.offset == (
        8 if pointer_size == 8 else 4
    )
    assert attorney_artifacts._ObjectAttributes.object_name.offset == (
        16 if pointer_size == 8 else 8
    )
    assert attorney_artifacts._ObjectAttributes.attributes.offset == (
        24 if pointer_size == 8 else 12
    )
    assert attorney_artifacts.ctypes.sizeof(attorney_artifacts._ObjectAttributes) == (
        48 if pointer_size == 8 else 24
    )
    assert attorney_artifacts.ctypes.sizeof(attorney_artifacts._IOStatusBlock) == (
        16 if pointer_size == 8 else 8
    )
    assert attorney_artifacts._FileNamesInformation.next_entry_offset.size == 4
    assert attorney_artifacts._FileNamesInformation.file_name_length.size == 4
    assert attorney_artifacts._FileNamesInformation.file_name.offset == 12
    assert attorney_artifacts.ctypes.sizeof(attorney_artifacts._FileAttributeTagInformation) == 8
    assert attorney_artifacts.ctypes.sizeof(attorney_artifacts._FileDispositionInformation) == 1


@pytest.mark.asyncio
async def test_completed_artifacts_are_restrictive_and_report_order_is_fixed(
    tmp_path: Path,
) -> None:
    completed = await run_evaluation(
        synthetic_case(comparator=False),
        ScriptedJudge(),
        tmp_path,
        seed_hex="f" * 64,
    )
    report = render_evaluation_report(completed.result)
    headings = [
        "# Automated Attorney Evaluation",
        "## Disposition",
        "## Case Readiness",
        "## Critical Defects",
        "## Requirement-by-Requirement Matrix",
        "## Score Summary",
        "## Unsupported or Overstated Claims",
        "## Regulatory Walk",
        "## Comparative Result",
        "## Evaluation Limits and Provenance",
    ]
    assert [report.index(heading) for heading in headings] == sorted(
        report.index(heading) for heading in headings
    )
    assert (
        "| 0 | notice-duty | requirement | critical | "
        "A covered entity must file notice within 30 days. | source-1@0:49 | "
        "COMPLETE | paragraph 1 | None | The report states the duty and its deadline. | "
        "Not supplied | Not supplied | Not supplied | Not supplied |"
    ) in report
    assert "harvest-private-id" not in report
    assert "comparator-private-id" not in report
    assert (tmp_path / "evaluation-report.md").read_text(encoding="utf-8") == report
    assert (tmp_path / "case-envelope.json").stat().st_mode & 0o777 == 0o600
    assert tmp_path.stat().st_mode & 0o077 == 0


@pytest.mark.asyncio
async def test_requirement_matrix_escapes_every_markdown_table_control(
    tmp_path: Path,
) -> None:
    class MarkdownControlJudge(ScriptedJudge):
        def _payload(self, request):  # type: ignore[no-untyped-def]
            payload = super()._payload(request)
            if request.operation is JudgeOperation.BUILD_LEDGER:
                entries = payload["entries"]
                assert isinstance(entries, list)
                entry = entries[0]
                assert isinstance(entry, dict)
                entry["ledger_id"] = "matrix-entry"
                entry["proposition"] = (
                    "<img src=x onerror=alert(1)> | slash \\ cr\r lf\n tab\t "
                    "bell\x07 c1\x85 entity &lt; source <br>"
                )
            if request.operation is JudgeOperation.GRADE_REPORT:
                entry_grades = payload["entry_grades"]
                assert isinstance(entry_grades, list)
                grade = entry_grades[0]
                assert isinstance(grade, dict)
                grade["ledger_id"] = "matrix-entry"
                grade["report_location"] = "<script>alert(1)</script> | 1\\2\r\nnext"
                grade["rationale"] = "why | because\\yes\r\nthen\tend\x7f &amp; <br>"
            return payload

    completed = await run_evaluation(
        synthetic_case(comparator=False),
        MarkdownControlJudge(),
        tmp_path,
        seed_hex="a" * 64,
    )

    report = render_evaluation_report(completed.result)
    matrix_row = next(line for line in report.splitlines() if line.startswith("| 0 |"))
    assert "&lt;img src=x onerror=alert(1)&gt;" in matrix_row
    assert "\\| slash \\\\ cr\\r lf\\n tab\\x09 bell\\x07 c1\\x85" in matrix_row
    assert "entity &amp;lt; source &lt;br&gt;" in matrix_row
    assert "&lt;script&gt;alert(1)&lt;/script&gt; \\| 1\\\\2\\r\\nnext" in matrix_row
    assert "why \\| because\\\\yes\\r\\nthen\\x09end\\x7f &amp;amp; &lt;br&gt;" in matrix_row
    assert "<img" not in matrix_row
    assert "<script" not in matrix_row
    assert matrix_row.count("<br>") == 0
    assert matrix_row.count(" | ") == 13
    assert verify_evaluation_run(tmp_path).valid


@pytest.mark.asyncio
async def test_renderer_rejects_post_validation_result_invariant_mutations(
    tmp_path: Path,
) -> None:
    one = await run_evaluation(
        synthetic_case(comparator=False),
        ScriptedJudge(),
        tmp_path / "one",
        seed_hex="1" * 64,
    )
    a_with_b = one.result.model_copy(deep=True)
    a_with_b.requirement_matrix.rows[0].report_b = (
        a_with_b.requirement_matrix.rows[0].report_a.model_copy(
            update={"anonymous_label": "B"}
        )
    )
    b_only = one.result.model_copy(deep=True)
    b_only.reports[0].anonymous_label = "B"
    non_admitted = one.result.model_copy(deep=True)
    non_admitted.readiness.status = ReadinessStatus.INCONCLUSIVE
    noncontiguous = one.result.model_copy(deep=True)
    noncontiguous.requirement_matrix.rows[0].walk_order = 1

    for malformed in (a_with_b, b_only, non_admitted, noncontiguous):
        with pytest.raises(EvaluationIntegrityError, match="malformed AttorneyEvaluationResult"):
            render_evaluation_report(malformed)


@pytest.mark.asyncio
async def test_semantic_findings_round_trip_through_immutable_artifacts(tmp_path: Path) -> None:
    class FindingJudge(ScriptedJudge):
        def _payload(self, request):  # type: ignore[no-untyped-def]
            payload = super()._payload(request)
            if request.operation is JudgeOperation.GRADE_REPORT:
                entry_grades = payload["entry_grades"]
                assert isinstance(entry_grades, list)
                finding = entry_grades[0]
                assert isinstance(finding, dict)
                finding.update(
                    {
                        "disposition": "MISSING",
                        "report_location": None,
                        "report_passage": None,
                        "finding_codes": ["CRITICAL_LEDGER_ENTRY_MISSING"],
                    }
                )
            return payload

    completed = await run_evaluation(
        synthetic_case(comparator=False),
        FindingJudge(),
        tmp_path,
        seed_hex="e" * 64,
    )
    label = completed.result.reports[0].anonymous_label
    resolved = json.loads((tmp_path / f"resolved-grade-{label}.json").read_text())
    report = json.loads((tmp_path / f"report-evaluation-{label}.json").read_text())

    assert resolved["grade"]["entry_grades"][0]["finding_codes"] == [
        "CRITICAL_LEDGER_ENTRY_MISSING"
    ]
    assert report["issue_codes"] == ["CRITICAL_LEDGER_ENTRY_MISSING"]
    assert verify_evaluation_run(tmp_path).valid


@pytest.mark.asyncio
async def test_pre_6a_manifest_schema_is_rejected_without_artifact_reinterpretation(
    tmp_path: Path,
) -> None:
    """A retained pre-6A root cannot acquire semantic defaults under schema 1.0."""
    await run_evaluation(
        synthetic_case(comparator=False),
        ScriptedJudge(),
        tmp_path,
        seed_hex="d" * 64,
    )
    manifest_path = tmp_path / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["schema_version"] = "1.0"
    manifest_path.write_bytes(canonical_json_bytes(manifest))

    verification = verify_evaluation_run(tmp_path)

    assert not verification.valid
    assert verification.issues == ("EVALUATION_ARTIFACT_SCHEMA_UNSUPPORTED: run-manifest.json",)
