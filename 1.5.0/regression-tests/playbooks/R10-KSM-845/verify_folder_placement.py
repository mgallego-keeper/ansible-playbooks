#!/usr/bin/env python3
"""Check whether a record UID is visible when querying a specific folder UID.

Usage: verify_folder_placement.py <config_file> <folder_uid> <record_uid>
Prints FOUND or NOT_FOUND and exits 0 either way (the caller decides pass/fail).
"""
import sys

from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.storage import FileKeyValueStorage
from keeper_secrets_manager_core.dto.payload import QueryOptions


def main():
    config_file, folder_uid, record_uid = sys.argv[1], sys.argv[2], sys.argv[3]
    config = FileKeyValueStorage(config_file_location=config_file)
    sm = SecretsManager(config=config)

    query_options = QueryOptions(records_filter=None, folders_filter=[folder_uid])
    records = sm.get_secrets_with_options(query_options)
    uids_in_folder = [r.uid for r in records]

    print("FOUND" if record_uid in uids_in_folder else "NOT_FOUND")


if __name__ == "__main__":
    main()
