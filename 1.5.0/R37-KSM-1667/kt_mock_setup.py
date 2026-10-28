"""Offline setup for R29 (KSM-1667): writes a mock KSM config and the record spec the sitecustomize fake vault serves.
usage: kt_mock_setup.py SECRETS.json OUTDIR   -> OUTDIR/config.json, OUTDIR/spec.json ; prints the mock record uid."""
import json, sys, os
from keeper_secrets_manager_core import mock
sec = json.load(open(sys.argv[1]))
out = sys.argv[2]
rec = mock.Record(title="KSMV-R37-%s" % sec["run"], record_type="login")
rec.field("login", "kt_user")
rec.field("password", sec["single"])
rec.custom_field("pem_lf", sec["pem_lf"])
rec.custom_field("pem_crlf", sec["pem_crlf"])
fd = os.open(out + "/config.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as fh:
    fh.write(mock.MockConfig.make_json())
fd = os.open(out + "/spec.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as fh:
    json.dump({"uid": rec.uid, "title": rec.title, "login": "kt_user", "password": sec["single"], "pem_lf": sec["pem_lf"], "pem_crlf": sec["pem_crlf"]}, fh)
print(rec.uid)
