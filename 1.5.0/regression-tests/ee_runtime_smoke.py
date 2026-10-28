#!/usr/bin/env python3
"""Validate the EE runtime without installing packages or accessing Keeper."""

import argparse
import importlib
import json
import os
import shutil
import subprocess
import sys
from importlib.metadata import version


REQUIRED_PYTHON = (3, 12)
SDK_MINIMUMS = {
    "keeper-secrets-manager-core": "17.3.0",
    "keeper-secrets-manager-helper": "1.1.2",
}
ANSIBLE_MINIMUM = "2.16.19"
ANSIBLE_UPPER_BOUND = "2.17"
PACKAGES = [
    "openssh-clients", "sshpass", "rsync", "git", "krb5-workstation",
]
BINARIES = [
    "ssh", "ssh-agent", "ssh-add", "ssh-keygen", "sshpass",
    "rsync", "git", "kinit", "klist",
]
MODULES = [
    "keeper_info", "keeper_cache_records", "keeper_create",
    "keeper_create_folder", "keeper_get_folder",
    "keeper_update_folder", "keeper_delete_folder",
]
AGENT_COMMAND = """
test -S "$SSH_AUTH_SOCK"
keydir=$(mktemp -d)
ssh-keygen -q -t ed25519 -N "" -f "$keydir/test_key"
ssh-add "$keydir/test_key"
ssh-add -l
echo SSH_AGENT_STARTUP_OK
"""


def runtime_details():
    return {
        "executable": sys.executable,
        "python_version": ".".join(str(part) for part in sys.version_info[:3]),
        "required_major_minor": ".".join(str(part) for part in REQUIRED_PYTHON),
    }


def dependency_versions_match(versions, version_class):
    """Check the published EE policy without importing host dependencies."""
    ansible_version = version_class(versions["ansible-core"])
    return (
        all(
            version_class(versions[name]) >= version_class(minimum)
            for name, minimum in SDK_MINIMUMS.items()
        )
        and version_class(ANSIBLE_MINIMUM) <= ansible_version
        and ansible_version < version_class(ANSIBLE_UPPER_BOUND)
        and not ansible_version.is_prerelease
        and not ansible_version.is_devrelease
    )


def inspect_keeper_actions():
    """Import action classes without instantiating plugins or Keeper clients."""
    loader = importlib.import_module("ansible.plugins.loader")
    loader.init_plugin_loader()
    actions = {}
    for module in MODULES:
        name = "keepersecurity.keeper_secrets_manager." + module
        try:
            action_class = loader.action_loader.get(name, class_only=True)
            actions[name] = {
                "loaded": isinstance(action_class, type),
                "module": getattr(action_class, "__module__", None),
            }
        except Exception as error:
            actions[name] = {"loaded": False, "error": str(error)}
    return actions


def inspect_keeper_helper():
    """Exercise helper implementation imports and local type enumeration."""
    record_module = importlib.import_module(
        "keeper_secrets_manager_helper.record_type",
    )
    field_module = importlib.import_module(
        "keeper_secrets_manager_helper.field_type",
    )
    return {
        "record_types": list(record_module.RecordType.get_record_type_list()),
        "field_types": list(field_module.FieldType.get_field_type_list()),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-collection-version", default="1.5.0")
    parser.add_argument("--require-controller-ssh-agent", action="store_true")
    args = parser.parse_args()
    checks = []

    def record(name, passed, details):
        checks.append({"name": name, "passed": bool(passed), "details": details})

    def command(name, argv, validate=None):
        try:
            result = subprocess.run(
                argv, capture_output=True, text=True, timeout=120,
            )
            passed = result.returncode == 0
            if passed and validate is not None:
                passed = validate(result.stdout)
            record(name, passed, {
                "returncode": result.returncode,
                "stdout": result.stdout[:4096],
                "stderr": result.stderr[:4096],
            })
        except Exception as error:
            record(name, False, {"error": str(error)})

    record("Python runtime", sys.version_info[:2] == REQUIRED_PYTHON,
           runtime_details())
    record("non-root runtime user", os.getuid() != 0, {"uid": os.getuid()})
    for package in PACKAGES:
        command("RPM: " + package, ["rpm", "-q", package])

    paths = {binary: shutil.which(binary) for binary in BINARIES}
    record("required executables", all(paths.values()), paths)
    for binary, argv in [
        ("ssh", ["ssh", "-V"]),
        ("sshpass", ["sshpass", "-V"]),
        ("rsync", ["rsync", "--version"]),
        ("git", ["git", "--version"]),
        ("Kerberos", ["klist", "-V"]),
    ]:
        command(binary + " execution", argv)

    try:
        from packaging.version import Version

        versions = {
            name: version(name) for name in [
                "keeper-secrets-manager-core", "keeper-secrets-manager-helper",
                "ansible-core", "ansible-runner",
            ]
        }
        for name in [
            "keeper_secrets_manager_core", "keeper_secrets_manager_helper",
            "ansible", "ansible_runner",
        ]:
            importlib.import_module(name)
        passed = dependency_versions_match(versions, Version)
        record("Python imports and dependency versions", passed, versions)
    except Exception as error:
        record("Python imports and dependency versions", False, {"error": str(error)})

    def collection_matches(stdout):
        inventory = json.loads(stdout)
        installed = [
            collections["keepersecurity.keeper_secrets_manager"]["version"]
            for collections in inventory.values()
            if "keepersecurity.keeper_secrets_manager" in collections
        ]
        return bool(installed) and all(
            item == args.expected_collection_version for item in installed
        )

    command("exact Keeper collection version", [
        "ansible-galaxy", "collection", "list",
        "keepersecurity.keeper_secrets_manager", "--format", "json",
    ], collection_matches)

    module_names = [
        "keepersecurity.keeper_secrets_manager." + module for module in MODULES
    ]
    command("Keeper module discovery", ["ansible-doc", "--json"] + module_names,
            lambda stdout: set(module_names).issubset(json.loads(stdout)))

    try:
        actions = inspect_keeper_actions()
        record("Keeper action implementation imports", all(
            action["loaded"] for action in actions.values()
        ), actions)
    except Exception as error:
        record("Keeper action implementation imports", False, {"error": str(error)})

    try:
        helper_types = inspect_keeper_helper()
        record("Keeper helper type enumeration", all(
            helper_types.values()
        ), helper_types)
    except Exception as error:
        record("Keeper helper type enumeration", False, {"error": str(error)})

    command("SSH agent startup and key loading", [
        "ssh-agent", "/bin/bash", "-ec", AGENT_COMMAND,
    ], lambda stdout: "SSH_AGENT_STARTUP_OK" in stdout)

    if args.require_controller_ssh_agent:
        socket = os.environ.get("SSH_AUTH_SOCK")
        record("Controller-injected agent socket", bool(socket), {"socket": socket})
        command("Controller-injected SSH key", ["ssh-add", "-l"])

    report = {"passed": all(check["passed"] for check in checks), "checks": checks}
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
