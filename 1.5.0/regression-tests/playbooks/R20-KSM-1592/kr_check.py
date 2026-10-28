#!/usr/bin/env python3
"""Check captured ansible-playbook output for KSM-1592 leaks.

usage: kr_check.py OUTPUT_FILE SECRETS_JSON [--expect-marker] [--allow-secrets-key]
             [--skip-secret-values] [--expect-plain-visible]

Fails (exit 1) if any secret appears raw, as JSON text with ensure_ascii on or off, as a
Python repr, or (for the multiline secret) as one of its lines; or if the printed output
contains a `_secrets` key. With --expect-marker it also fails if no `****` is present, so
a run that printed nothing cannot pass by accident. --skip-secret-values checks only the
_secrets key; --expect-plain-visible then requires the plain secret to be present (a control
that shows the run printed task results and no redaction was active).
"""
import json
import re
import sys

# The _secrets key as JSON or YAML prints it. A plain substring test also matches the path
# 'keeper_secrets_manager' that -vvv prints for a plugin path, so require a non-word character
# before the name and a colon after it.
SECRETS_KEY = re.compile(r'(?<![A-Za-z0-9])_secrets["\']?\s*:')


def forms(value):
    text = value if isinstance(value, str) else str(value)
    out = {text, json.dumps(text)[1:-1], json.dumps(text, ensure_ascii=False)[1:-1], repr(text)[1:-1]}
    if "\n" in text:
        out.update(line for line in text.split("\n") if len(line) >= 8)
    return out


def main():
    output_file, secrets_file = sys.argv[1], sys.argv[2]
    expect_marker = "--expect-marker" in sys.argv
    allow_secrets_key = "--allow-secrets-key" in sys.argv
    skip_values = "--skip-secret-values" in sys.argv
    expect_plain_visible = "--expect-plain-visible" in sys.argv
    with open(output_file, encoding="utf-8", errors="replace") as handle:
        output = handle.read()
    with open(secrets_file, encoding="utf-8") as handle:
        secrets = json.load(handle)

    failures = []
    for name, value in ([] if skip_values else secrets.items()):
        leaked = sorted(form for form in forms(value) if form and form in output)
        if leaked:
            failures.append("FAIL: secret '%s' appears in output (%d form(s), first form length %d)"
                            % (name, len(leaked), len(leaked[0])))
        else:
            print("PASS: secret '%s' absent from output in every form checked" % name)
    if not allow_secrets_key:
        if SECRETS_KEY.search(output):
            failures.append("FAIL: the output prints a _secrets key")
        else:
            print("PASS: no _secrets key in output")
    if expect_marker:
        if "****" in output:
            print("PASS: redaction marker **** present (callback was active)")
        else:
            failures.append("FAIL: no **** marker in output (callback not active, or nothing printed)")
    if expect_plain_visible:
        if secrets["plain"] in output:
            print("PASS: control: the plain secret is visible, so task results were printed unredacted")
        else:
            failures.append("FAIL: control: the plain secret is not in the output")
    print("output bytes checked: %d" % len(output))
    for line in failures:
        print(line)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
