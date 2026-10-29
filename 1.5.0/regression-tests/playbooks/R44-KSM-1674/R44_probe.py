"""KSM-1674: simulated SDK partial read against REAL vault data.

Usage: R44_probe.py <config.json> '<json args>'
The args are the seeded folder UIDs and names (see create_seed_records.yml):
    res, users, hidden, databases, subfolder, deep   folder UIDs
    shared_name, root_name, databases_name, production_name   folder names

The public SDK (17.3.0) never skips an unreadable folder, so this wraps SecretsManager.get_folders to drop one real
folder and log the 17.4.0-style "Folder <uid> skipped due to error" warning. Every call is a read; nothing is written.
Run it with PYTHONPATH pointing at a source tree to compare a pre-fix and a post-fix KeeperAnsible.
"""
import json
import logging
import os
import sys

from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.keeper_globals import logger_name
from keeper_secrets_manager_core.storage import FileKeyValueStorage

try:
    import keeper_secrets_manager_ansible as ksm
except ModuleNotFoundError:
    # An execution environment installs the collection, not the pip package. Import the copy bundled in the collection.
    for root in (os.environ.get("ANSIBLE_COLLECTIONS_PATH", "") + ":/usr/share/ansible/collections:"
                 + os.path.expanduser("~/.ansible/collections")).split(":"):
        if root and os.path.isdir(os.path.join(root, "ansible_collections")) and root not in sys.path:
            sys.path.append(root)
    from ansible_collections.keepersecurity.keeper_secrets_manager.plugins.common import (
        keeper_secrets_manager_ansible as ksm)
KeeperAnsible = ksm.KeeperAnsible


def build_cases(a):
    res, users, hidden = a["res"], a["users"], a["hidden"]
    return [
        # id, label, hidden uid, kwargs, expectation ("reject" or the expected folder_uid)
        ("S1", "folder_name, one readable match, a sibling is skipped", hidden,
         dict(shared_folder_uid=res, folder_name=a["root_name"]), "reject"),
        ("S2", "folder_name, subfolder_uid start, a folder is skipped", hidden,
         dict(subfolder_uid=a["databases"], folder_name=a["production_name"]), "reject"),
        ("S3", "folder_path from the top level, a shared root is skipped", users,
         dict(folder_path="%s/%s" % (a["shared_name"], a["databases_name"])), "reject"),
        ("S4", "folder_path list, depth 3, a folder is skipped", hidden,
         dict(folder_path=[a["shared_name"], a["databases_name"], a["production_name"]]), "reject"),
        ("S5", "name that does not exist, a folder is skipped", hidden,
         dict(shared_folder_uid=res, folder_name="No Such Folder"), "reject"),
        ("S6", "explicit shared_folder_uid, a folder is skipped", hidden, dict(shared_folder_uid=res), res),
        ("S7", "explicit subfolder_uid, a folder is skipped", hidden,
         dict(subfolder_uid=a["subfolder"]), a["subfolder"]),
        ("S8", "shared_folder_uid + subfolder_uid, a folder is skipped", hidden,
         dict(shared_folder_uid=res, subfolder_uid=a["deep"]), a["deep"]),
    ]


def main(config, args):
    original = SecretsManager.get_folders
    out = []
    for cid, label, hidden, kwargs, expect in build_cases(args):
        for inc in (False, True):
            def partial(sm, _hidden=hidden):
                folders = original(sm)
                logging.getLogger(logger_name).warning("Folder %s skipped due to error: %s", _hidden, "simulated")
                return [f for f in folders if f.folder_uid != _hidden]

            SecretsManager.get_folders = partial
            try:
                keeper = object.__new__(KeeperAnsible)
                keeper.client = SecretsManager(config=FileKeyValueStorage(config), log_level="ERROR")
                try:
                    res = keeper.get_folder(include_subfolders=inc, **kwargs)
                    outcome, detail = "selected", res["folder_uid"]
                except Exception as err:  # noqa: BLE001
                    outcome, detail = "rejected", str(err)
            finally:
                SecretsManager.get_folders = original
            ok = (outcome == "rejected") if expect == "reject" else (outcome == "selected" and detail == expect)
            out.append(dict(id=cid, include_subfolders=inc, label=label, outcome=outcome, detail=detail, ok=ok))
    print(json.dumps(dict(source=ksm.__file__, results=out)))


main(sys.argv[1], json.loads(sys.argv[2]))
