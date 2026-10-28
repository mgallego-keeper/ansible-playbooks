"""
Helper for R29.2 (KSM-1644). Runs KeeperAnsible.remove_record() from the INSTALLED collection against the real
keeper-secrets-manager-core SDK, with SecretsManager._post_query replaced by the repo's UnreadableRecordServer
(real encrypted records; one record is one the SDK cannot read). No network, nothing in any vault.

usage: kt_unreadable.py <collections_root> <repo_path>
Prints one JSON document: a list of {fault, selector, check_mode, outcome, delete_requests, record_in_server}.
"""
import importlib
import json
import sys

collections_root, repo_path = sys.argv[1], sys.argv[2]
sys.path.insert(0, collections_root)
sys.path.insert(1, repo_path)

from keeper_secrets_manager_core import SecretsManager, mock  # noqa: E402
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage  # noqa: E402
from tests.unreadable_record_server import UID, UnreadableRecordServer  # noqa: E402

lib = importlib.import_module(
    "ansible_collections.keepersecurity.keeper_secrets_manager.plugins.common.keeper_secrets_manager_ansible")


def run(fault, selector, check_mode, shared_title=False):
    server = UnreadableRecordServer(fault, shared_title=shared_title)
    try:
        with server.patch():
            sdk = lib.KeeperAnsible.__new__(lib.KeeperAnsible)
            sdk.client = SecretsManager(config=InMemoryKeyValueStorage(mock.MockConfig.make_base64()))
            try:
                outcome = {"result": sdk.remove_record(check_mode=check_mode, **selector)}
            except Exception as err:
                outcome = {"error": "{}: {}".format(type(err).__name__, err)}
            return {"fault": fault, "selector": selector, "check_mode": check_mode, "outcome": outcome,
                    "delete_requests": [c["record_uids"] for c in server.calls("delete_secret")],
                    "target_still_in_server": UID in [r["uid"] for r in server.records()]}
    finally:
        server.cleanup()


cases = []
for fault in ("attachment", "record_data", "folder_key", "folder_peer"):
    for check_mode in (False, True):
        cases.append(run(fault, {"uids": UID}, check_mode))
for check_mode in (False, True):
    cases.append(run("attachment", {"titles": "Record 1"}, check_mode, shared_title=True))
    cases.append(run("attachment", {"uids": "MISSING_UID"}, check_mode))
    cases.append(run("attachment", {"uids": "OTHER_UID"}, check_mode))
print(json.dumps(cases))
