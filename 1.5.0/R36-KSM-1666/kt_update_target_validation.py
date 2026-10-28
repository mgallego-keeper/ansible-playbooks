"""
Helper for R36.2 / R36.3 (KSM-1666). Runs KeeperAnsible.set_value() (the code behind keeper_set) against the real
keeper-secrets-manager-core SDK, with SecretsManager._post_query replaced by the repo's fake server
(tests/keeper_set_cache_test.py::_NotesServer: real encrypted records, real update_secret handling). No network, nothing in
any vault. Also covers a response that holds two live records with the SAME UID, which a live vault cannot produce.

usage: kt_update_target_validation.py <repo_path> [<collections_root>]
  repo_path:        integration/keeper_secrets_manager_ansible (holds tests/keeper_set_cache_test.py)
  collections_root: if given, import the Galaxy-collection copy of the library from there (R36.2);
                    if omitted, import the plain keeper_secrets_manager_ansible package (R36.3).
Prints one JSON document: {"package_file": ..., "cases": [{case, outcome, update_requests, notes_after}]}.
"""
import copy
import importlib
import json
import sys
from types import SimpleNamespace
from unittest.mock import Mock

repo_path = sys.argv[1]
collections_root = sys.argv[2] if len(sys.argv) > 2 else None
if collections_root:
    sys.path.insert(0, collections_root)
sys.path.append(repo_path)  # append, not insert: the installed package must win over the source tree

from keeper_secrets_manager_core import SecretsManager, mock  # noqa: E402
from keeper_secrets_manager_core.dto.dtos import SecretsManagerResponse  # noqa: E402
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage  # noqa: E402
from tests.keeper_set_cache_test import _NotesServer  # noqa: E402

if collections_root:
    lib = importlib.import_module(
        "ansible_collections.keepersecurity.keeper_secrets_manager.plugins.common.keeper_secrets_manager_ansible")
else:
    lib = importlib.import_module("keeper_secrets_manager_ansible")

SHARED = "SHARED_FOLDER_UID"
RECORDS = [
    {"uid": "UNIQ_UID", "title": "Unique", "folder": SHARED, "notes": "old-uniq"},
    {"uid": "DUP_UID_1", "title": "Dup", "folder": SHARED, "notes": "old-dup1"},
    {"uid": "DUP_UID_2", "title": "Dup", "folder": SHARED, "notes": "old-dup2"},
]
NEW = "NEW_VALUE"


def run(case, check_mode=False, **selector):
    server = _NotesServer(folders=[{"uid": SHARED, "name": "Shared"}], records=copy.deepcopy(RECORDS))
    try:
        with server.patch():
            keeper = object.__new__(lib.KeeperAnsible)
            keeper.client = SecretsManager(config=InMemoryKeyValueStorage(mock.MockConfig.make_base64()))
            try:
                outcome = {"changed": keeper.set_value(lib.KeeperFieldType.NOTES, None, NEW, check_mode=check_mode,
                                                       **selector)}
            except Exception as err:
                outcome = {"error": "{}: {}".format(type(err).__name__, err)}
            return {"case": case, "outcome": outcome,
                    "update_requests": len(server.calls("update_secret")),
                    "reads": len(server.calls("get_secret")),
                    "notes_after": {r["uid"]: r.get("notes") for r in server.records()}}
    finally:
        server.cleanup()


cases = [
    run("title_unique", title="Unique"),
    run("uid", uid="UNIQ_UID"),
    run("list1_uid", uid=["UNIQ_UID"]),
    run("tuple1_title", title=("Unique",)),
    run("list2_uid", uid=["UNIQ_UID", "DUP_UID_1"]),
    run("list2_title", title=["Unique", "Dup"]),
    run("set_uid", uid={"UNIQ_UID", "DUP_UID_1"}),
    run("dict_title", title={"Unique": 1}),
    run("empty_list_uid", uid=[]),
    run("title_duplicate", title="Dup"),
    run("list1_title_duplicate", title=["Dup"]),
    run("title_missing", title="NoSuchTitle"),
    run("uid_missing", uid="NO_SUCH_UID"),
    run("check_mode_unique", check_mode=True, title="Unique"),
    run("check_mode_duplicate", check_mode=True, title="Dup"),
]

# Two LIVE records with the same UID in one response: a save would go to an unknown one of them.
for selector in ("uid", "title"):
    records = [SimpleNamespace(uid="UNIQ_UID", title=t, dict={"notes": "old"}, _update=Mock())
               for t in ("Unique", "Other record")]
    response = SecretsManagerResponse()
    response.records = records
    keeper = object.__new__(lib.KeeperAnsible)
    keeper.client = SimpleNamespace(get_secrets=Mock(return_value=response), save=Mock())
    sel = {"uid": "UNIQ_UID"} if selector == "uid" else {"title": "Unique"}
    try:
        outcome = {"changed": keeper.set_value(lib.KeeperFieldType.NOTES, None, NEW, **sel)}
    except Exception as err:
        outcome = {"error": "{}: {}".format(type(err).__name__, err)}
    cases.append({"case": "duplicate_live_uid_by_" + selector, "outcome": outcome,
                  "update_requests": keeper.client.save.call_count, "reads": keeper.client.get_secrets.call_count,
                  "notes_after": {r.title: r.dict["notes"] for r in records}})
print(json.dumps({"package_file": lib.__file__, "cases": cases}))
