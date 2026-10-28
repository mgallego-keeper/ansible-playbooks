#!/usr/bin/env python3
"""KSM-1673 regression helper.

usage: R43_probe.py <config.json> <title-prefix> [--delete]
Prints {title: {uid, folder_uid, inner_folder_uid}} for records whose title starts with the prefix.
folder_uid is the shared-folder root; inner_folder_uid is the subfolder (empty for records at the root).
--delete removes the matched records after listing them.
"""
import json
import sys

from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.storage import FileKeyValueStorage

config_file, prefix = sys.argv[1], sys.argv[2]
sm = SecretsManager(config=FileKeyValueStorage(config_file))
found = [r for r in sm.get_secrets() if r.title.startswith(prefix)]
print(json.dumps({r.title: {"uid": r.uid, "folder_uid": r.folder_uid, "inner_folder_uid": r.inner_folder_uid or ""}
                  for r in found}))
if "--delete" in sys.argv and found:
    sm.delete_secret([r.uid for r in found])
