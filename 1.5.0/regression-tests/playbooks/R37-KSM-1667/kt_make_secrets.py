"""Writes the throw-away multiline secrets for R29 (KSM-1667) to a JSON file (mode 0600).
usage: kt_make_secrets.py OUT.json
Fake PEM-style keys: one with LF line ends and a trailing newline, one with CRLF line ends and a trailing CRLF.
Every body line is random per run, so no earlier run or other record can contain it."""
import json, os, secrets, string, sys

alpha = string.ascii_letters + string.digits


def body(n=64):
    return "".join(secrets.choice(alpha) for _ in range(n))


run = "".join(secrets.choice(string.digits) for _ in range(8))
lf = ["-----BEGIN KT1667 FAKE PRIVATE KEY-----", body(), body(), body(), "kQ==", "-----END KT1667 FAKE PRIVATE KEY-----"]
crlf = ["-----BEGIN KT1667CR FAKE PRIVATE KEY-----", body(), body(), body(), "Zg==", "-----END KT1667CR FAKE PRIVATE KEY-----"]
data = {
    "run": run,
    "single": "KtSingle" + body(24),
    "lines_lf": lf, "pem_lf": "\n".join(lf) + "\n",
    "lines_crlf": crlf, "pem_crlf": "\r\n".join(crlf) + "\r\n",
}
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as fh:
    json.dump(data, fh)
print(json.dumps({"run": run}))
