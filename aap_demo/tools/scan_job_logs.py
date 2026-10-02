#!/usr/bin/env python3
"""Find QA canaries in AAP stdout or event exports without echoing their values."""

import argparse
import base64
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
import sys


ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
RUN_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
PREFIXES = {
    "password": "QA_CANARY_PASSWORD_",
    "updated_password": "QA_CANARY_UPDATED_PASSWORD_",
    "notes": "QA_CANARY_NOTES_",
    "updated_notes": "QA_CANARY_UPDATED_NOTES_",
    "custom_field": "QA_CANARY_CUSTOM_",
    "folder_name": "QA_CANARY_FOLDER_",
    "error_name": "QA_CANARY_ERROR_",
    "file_content": "QA_CANARY_FILE_",
    "cache_key": "QA_CANARY_CACHE_KEY_",
}


@dataclass(frozen=True, order=True)
class Match:
    source: str
    location: str
    label: str
    representation: str


def run_canaries(run_id):
    values = {label: prefix + run_id for label, prefix in PREFIXES.items()}
    values["password"] += "!"
    values["updated_password"] += "!"
    return values


def strings_in(value, location="$"):
    if isinstance(value, str):
        yield location, value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from strings_in(child, location + "[" + json.dumps(str(key)) + "]")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from strings_in(child, location + "[" + str(index) + "]")


def variants(value):
    candidates = {
        "plaintext": value,
        "json_escaped": json.dumps(value, ensure_ascii=False)[1:-1],
        "json_ascii": json.dumps(value, ensure_ascii=True)[1:-1],
        "base64": base64.b64encode(value.encode()).decode(),
        "base64_urlsafe": base64.urlsafe_b64encode(value.encode()).decode(),
    }
    seen = set()
    for representation, candidate in candidates.items():
        if candidate and candidate not in seen:
            seen.add(candidate)
            yield representation, candidate


def scan_text(text, canaries, source="<input>"):
    text = ANSI_ESCAPE.sub("", text)
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        segments = (
            ("line:" + str(index), line)
            for index, line in enumerate(text.splitlines(), start=1)
        )
    else:
        segments = strings_in(decoded)

    matches = set()
    needles = {
        label: list(variants(value))
        for label, value in canaries.items()
        if isinstance(value, str) and value
    }
    for location, segment in segments:
        for label, representations in needles.items():
            for representation, needle in representations:
                if needle in segment:
                    matches.add(Match(source, location, label, representation))
    return sorted(matches)


def redact_metadata(value, canaries):
    for secret in sorted(set(canaries.values()), key=len, reverse=True):
        if secret:
            value = value.replace(secret, "[REDACTED]")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument(
        "--canary", action="append", default=[], metavar="LABEL=VALUE",
        help="Add a synthetic canary. Use --secrets-file for actual credentials.",
    )
    parser.add_argument(
        "--secrets-file", type=Path,
        help="Read additional labeled strings from an ignored local JSON object.",
    )
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument("--fail-on-match", action="store_true")
    args = parser.parse_args(argv)

    if not (args.run_id or args.canary or args.secrets_file):
        parser.error("Supply --run-id, --canary, or --secrets-file.")
    if args.run_id and not RUN_ID.fullmatch(args.run_id):
        parser.error("The run identifier does not match the demo's allowed format.")

    canaries = run_canaries(args.run_id) if args.run_id else {}
    canaries["positive_control"] = "QA_LOG_SCAN_POSITIVE_CONTROL"
    for entry in args.canary:
        label, separator, value = entry.partition("=")
        if not separator or not label or not value:
            parser.error("Each --canary must have a nonempty label and value.")
        canaries[label] = value

    try:
        if args.secrets_file:
            credentials = json.loads(args.secrets_file.read_text(encoding="utf-8"))
            if not isinstance(credentials, dict):
                parser.error("--secrets-file must contain a JSON object.")
            for location, value in strings_in(credentials, "credentials"):
                if value:
                    canaries[location] = value
        matches = [
            match
            for file in args.files
            for match in scan_text(
                file.read_text(encoding="utf-8"), canaries, source=str(file),
            )
        ]
    except (OSError, UnicodeError, json.JSONDecodeError):
        parser.error("Could not read the inputs as UTF-8 text or JSON. Check paths and formats.")

    report = [
        {
            key: redact_metadata(value, canaries)
            for key, value in asdict(match).items()
        }
        for match in matches
    ]
    if args.json_output:
        print(json.dumps({"match_count": len(report), "matches": report}, indent=2))
    else:
        print("Match locations:", len(report))
        for match in report:
            print(
                "{source} {location}: {label} ({representation})".format(**match)
            )
        if not report:
            print("No supplied canaries matched. This is not proof of zero sensitive-data exposure.")
    return 1 if args.fail_on_match and report else 0


if __name__ == "__main__":
    sys.exit(main())
