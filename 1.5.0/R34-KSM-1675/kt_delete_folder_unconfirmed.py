"""
Helper for R34.2 / R34.3 (KSM-1675). Runs KeeperAnsible.delete_folder() against the real keeper-secrets-manager-core
SDK, with SecretsManager._post_query replaced by the repo's FakeKeeperServer (tests/folder_fake_server.py: real
encrypted folders, real per-folder responses). No network, nothing in any vault.

An unreadable folder cannot be made in a live vault. The SDK leaves a folder out of get_folders() and logs
"Folder <uid> skipped due to error" when it cannot decode it. This helper reproduces exactly that on the second
(confirmation) read, by wrapping client.get_folders, as the repo's own contract test does.

usage: kt_delete_folder_unconfirmed.py <repo_path> [<collections_root>]
  repo_path:        integration/keeper_secrets_manager_ansible (holds tests/folder_fake_server.py)
  collections_root: if given, import the Galaxy-collection copy of the library from there (R34.2);
                    if omitted, import the plain keeper_secrets_manager_ansible package (R34.3).
Prints one JSON document: {"package_file": ..., "cases": [{case, force, check_mode, outcome, delete_requests,
folder_reads, target_still_in_server}]}.
"""
import importlib
import json
import logging
import sys
from unittest.mock import patch

repo_path = sys.argv[1]
collections_root = sys.argv[2] if len(sys.argv) > 2 else None
if collections_root:
    sys.path.insert(0, collections_root)
sys.path.append(repo_path)  # append, not insert: the installed package must win over the source tree

from keeper_secrets_manager_core import SecretsManager, mock  # noqa: E402
from keeper_secrets_manager_core.keeper_globals import logger_name  # noqa: E402
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage  # noqa: E402
from tests.folder_fake_server import FakeKeeperServer  # noqa: E402

if collections_root:
    lib = importlib.import_module(
        "ansible_collections.keepersecurity.keeper_secrets_manager.plugins.common.keeper_secrets_manager_ansible")
else:
    lib = importlib.import_module("keeper_secrets_manager_ansible")

UID = "TARGET_UID"
OTHER = "OTHER_UID"
FOLDERS = [{"uid": "SHARED_UID", "name": "Shared", "parent": None},
           {"uid": UID, "name": "Staging", "parent": "SHARED_UID"}]


class StatusServer(FakeKeeperServer):
    """Really deletes (like FakeKeeperServer), but answers the delete request with a chosen body."""

    def __init__(self, body, **kwargs):
        self.body = body
        super().__init__(**kwargs)

    def handle(self, sm, path, payload):
        response = super().handle(sm, path, payload)
        return self._json(self.body) if path == "delete_folder" else response


def run(case, force, check_mode=False, skipped=None, drop=None, skip_second_read=False, body=None, folders=None, **server_kw):
    folders = folders or FOLDERS
    if body is not None:
        server = StatusServer(body, folders=folders, **server_kw)
    else:
        server = FakeKeeperServer(folders=folders, **server_kw)
    reads = []
    try:
        with server.patch():
            keeper = object.__new__(lib.KeeperAnsible)
            keeper.client = SecretsManager(config=InMemoryKeyValueStorage(mock.MockConfig.make_base64()))
            original_get = keeper.client.get_folders

            def get_folders():
                result = original_get()
                reads.append(1)
                if skip_second_read and len(reads) == 2:
                    logging.getLogger(logger_name).warning("Folder %s skipped due to error: %s", skipped,
                                                           "simulated unreadable metadata")
                    return [f for f in result if f.folder_uid != drop]
                return result

            with patch.object(keeper.client, "get_folders", side_effect=get_folders):
                try:
                    outcome = {"result": keeper.delete_folder(UID, force=force, check_mode=check_mode)}
                except Exception as err:
                    outcome = {"error": "{}: {}".format(type(err).__name__, err)}
            return {"case": case, "force": force, "check_mode": check_mode, "outcome": outcome,
                    "delete_requests": [c for c in server.calls("delete_folder")],
                    "folder_reads": len(reads),
                    "target_still_in_server": server.folder(UID) is not None}
    finally:
        server.cleanup()


other_folders = FOLDERS + [{"uid": OTHER, "name": "Unrelated", "parent": "SHARED_UID"}]
cases = []
for force in (False, True):
    # Target exists, the server sends no status, and the confirmation read skips the target.
    cases.append(run("target_skipped", force, skipped=UID, drop=UID, skip_second_read=True, omit_delete_status=True))
    # Same, but the skipped folder has no usable UID.
    for label, value in (("none_uid", None), ("empty_uid", ""), ("blank_uid", " ")):
        cases.append(run("skip_id_" + label, force, skipped=value, drop=UID, skip_second_read=True, omit_delete_status=True))
    # No status, the delete really happened, and an unrelated exact UID is skipped: absence is true.
    cases.append(run("unrelated_skipped_gone", force, skipped=OTHER, drop=OTHER, skip_second_read=True,
                     body={"folders": []}, folders=other_folders))
    # No status, nothing deleted, nothing skipped: the target is readable and present.
    cases.append(run("target_readable_present", force, omit_delete_status=True))
    # No status, the delete really happened, nothing skipped: absence is true.
    cases.append(run("no_status_gone", force, body={"folders": []}))
    # Explicit ok: success and no extra read.
    cases.append(run("explicit_ok", force))
    # Explicit refusal.
    cases.append(run("explicit_refusal", force, delete_status={UID: ["access_denied", "No permission"]}))
    # Check mode: one read, no request, even when the server would send no status.
    cases.append(run("check_mode", force, check_mode=True, omit_delete_status=True))
print(json.dumps({"package_file": lib.__file__, "cases": cases}))
