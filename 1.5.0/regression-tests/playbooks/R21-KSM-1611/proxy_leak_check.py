#!/usr/bin/env python3
"""R21-KSM-1611 helper — real (non-mocked) proxy-credential-leak check against live QA CA.

Run as a standalone process (via the `command` module from the regression playbooks in
this directory) so a malformed https_proxy can be exported for exactly this process
without affecting the parent ansible-playbook run or any other task.

Usage: proxy_leak_check.py <config_file> <record_uid> <mode>
  mode is "read" (keeper_get_record-equivalent, exercises custom_post_function/post_function
  on the read side) or "write" (keeper_set-equivalent, exercises plain post_function on the
  write side).

Exits 0 and prints PASS if the operation failed with no credential substring in the error
text. Exits 1 and prints FAIL with the offending text otherwise. Exits 2 if the operation
did NOT fail at all (which would mean the malformed proxy was not actually exercised).
"""
import os
import sys
import traceback

CREDENTIAL = "u:p"
MALFORMED_PROXY = "http://u:p#w@127.0.0.1:9"

os.environ["https_proxy"] = MALFORMED_PROXY
os.environ["HTTPS_PROXY"] = MALFORMED_PROXY
for name in list(os.environ):
    if name.lower() in ("no_proxy", "all_proxy"):
        del os.environ[name]

config_file, record_uid, mode = sys.argv[1], sys.argv[2], sys.argv[3]

try:
    from keeper_secrets_manager_ansible import KeeperAnsible  # noqa: E402  (pip / source checkout)
except ImportError:
    # Galaxy collection and Tower/AWX EE: the library lives inside the installed collection, so put the
    # collection roots on sys.path and import it from there.
    roots = [p for p in os.environ.get("ANSIBLE_COLLECTIONS_PATH", "").split(os.pathsep) if p]
    roots += ["/usr/share/ansible/collections", os.path.expanduser("~/.ansible/collections")]
    sys.path[:0] = [p for p in roots if os.path.isdir(os.path.join(p, "ansible_collections"))]
    from ansible_collections.keepersecurity.keeper_secrets_manager.plugins.common.keeper_secrets_manager_ansible import (  # noqa: E402,E501
        KeeperAnsible,
    )

keeper = KeeperAnsible(task_vars={"keeper_config_file": config_file})

try:
    if mode == "read":
        keeper.client.get_secrets(uids=[record_uid])
    elif mode == "write":
        # delete_secret() goes straight to _post_query -> self.post_function with no prior
        # read, so this is a clean, direct hit on the plain post_function write-path route
        # (the one save/delete/create/folder calls use) with no dependency on a successful
        # read happening first.
        keeper.client.delete_secret([record_uid])
    else:
        print("FAIL: unknown mode {}".format(mode))
        sys.exit(2)
except Exception as err:
    full_text = str(err) + "".join(traceback.format_exception(type(err), err, err.__traceback__))
    if CREDENTIAL in full_text:
        print("FAIL: credential leaked in {} mode: {}".format(mode, full_text))
        sys.exit(1)
    print("PASS: {} mode failed cleanly, no credential in error: {}".format(mode, err))
    sys.exit(0)

print("FAIL: {} mode did not fail at all — the malformed proxy was not exercised".format(mode))
sys.exit(2)
