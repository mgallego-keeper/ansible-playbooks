#!/usr/bin/env python3
"""Seed helper for create_seed_records.yml: find or create one record by title, and attach a synthetic file.

Usage: seed_helper.py <config.json> <shared_folder_uid> '<spec json>'

The spec is a JSON object:
    {"title": "...", "type": "login", "fields": [{"type": "login", "value": "x"}],
     "custom": [{"type": "text", "label": "Environment", "value": "qa"}], "notes": "...",
     "attachment": "qa-attachment.jpeg"}          (custom, notes and attachment are optional)

The helper looks up the title first, so a second run creates nothing. It prints one JSON line:
    {"uid": "...", "created": true|false, "attached": true|false}
Records and attachments are synthetic. The attachment bytes start with 0xFF (not valid UTF-8), contain the text JFIF
and are longer than 1000 bytes, which is what R38 and R42 need from the attachment fixture.
"""
import json
import os
import sys
import tempfile

from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.dto.dtos import RecordCreate, RecordField
from keeper_secrets_manager_core.storage import FileKeyValueStorage


def synthetic_jpeg():
    header = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    body = bytes((i * 7 + 13) % 256 for i in range(2048))
    return header + body + b"\xff\xd9"


def field(spec):
    return RecordField(field_type=spec["type"], value=spec["value"], label=spec.get("label"))


def find(sm, title):
    matches = sm.get_secrets_by_title(title) or []
    if len(matches) > 1:
        sys.exit("ERROR: %d records are titled %r. Delete the duplicates, then run the seed again." % (len(matches), title))
    return matches[0] if matches else None


def main():
    config, folder_uid, raw = sys.argv[1:4]
    spec = json.loads(raw)
    sm = SecretsManager(config=FileKeyValueStorage(config_file_location=config))

    record = find(sm, spec["title"])
    created = record is None
    if created:
        new = RecordCreate(spec.get("type", "login"), spec["title"])
        new.fields = [field(f) for f in spec.get("fields", [])]
        if spec.get("custom"):
            new.custom = [field(f) for f in spec["custom"]]
        if spec.get("notes"):
            new.notes = spec["notes"]
        uid = sm.create_secret(folder_uid, new)
        record = sm.get_secrets([uid])[0]

    attached = False
    name = spec.get("attachment")
    if name and name not in [f.name for f in (record.files or [])]:
        path = os.path.join(tempfile.mkdtemp(prefix="ksm-seed-"), name)
        with open(path, "wb") as fh:
            fh.write(synthetic_jpeg())
        sm.upload_file_path(record, path)
        attached = True

    print(json.dumps({"uid": record.uid, "created": created, "attached": attached}))


if __name__ == "__main__":
    main()
