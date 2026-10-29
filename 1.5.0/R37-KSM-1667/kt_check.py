"""Checks the console output of the R29 inner run (KSM-1667). Prints one JSON document; never prints a secret.
usage: kt_check.py OUTPUT.txt SECRETS.json SCRATCH_DIR
A leak = the full key, a JSON/repr-escaped form of it, or any single line of it (>= 4 chars) in the output of a T.. task.
The check covers both the intended values and the values keeper_get really returned (the files the inner playbook wrote)."""
import json, re, sys

out = open(sys.argv[1], errors="surrogateescape").read()
sec = json.load(open(sys.argv[2]))
scratch = sys.argv[3]
cases = []


def add(case, ok, detail):
    cases.append({"case": case, "result": "PASS" if ok else "FAIL", "detail": detail})


def read(name):
    try:
        return open("%s/%s" % (scratch, name), newline="", errors="surrogateescape").read()
    except OSError:
        return None


ret_lf, ret_crlf, ret_single = read("lf.pem"), read("crlf.pem"), read("single.txt")
add("readback LF key equals what was stored", ret_lf == sec["pem_lf"], "returned %s chars, intended %s" % (len(ret_lf or ""), len(sec["pem_lf"])))
add("readback CRLF key equals what was stored (CR kept)", ret_crlf == sec["pem_crlf"],
    "returned %s chars with %s CR, intended %s chars with %s CR" % (len(ret_crlf or ""), (ret_crlf or "").count("\r"), len(sec["pem_crlf"]), sec["pem_crlf"].count("\r")))
add("readback single-line secret equals what was stored", ret_single == sec["single"], "returned %s chars" % len(ret_single or ""))

# Split into task blocks.
blocks = {}
for m in re.finditer(r"TASK \[(.+?)\] \*+\n(.*?)(?=\nTASK \[|\nPLAY RECAP|\Z)", out, re.S):
    blocks[m.group(1)] = m.group(2)
tnames = sorted(n for n in blocks if re.match(r"T\d\d ", n))
section = "\n".join(blocks[n] for n in tnames)
add("all T.. tasks present in the output", len(tnames) >= 13, "%d T.. task blocks found" % len(tnames))

secrets_full, lines = [], []
for key, rkey, lkey in (("pem_lf", ret_lf, "lines_lf"), ("pem_crlf", ret_crlf, "lines_crlf")):
    for v in {sec[key], sec[key].rstrip("\r\n"), rkey or sec[key]}:
        secrets_full.append(v)
    lines += [l for l in sec[lkey] if len(l) >= 4]


def forms(s):
    return {s, json.dumps(s)[1:-1], json.dumps(s, ensure_ascii=False)[1:-1], repr(s)[1:-1]}


def leaks(text, values):
    return sum(1 for v in values for f in forms(v) if f and f in text)


add("full LF key never appears (raw, JSON, repr forms)", leaks(section, [sec["pem_lf"], sec["pem_lf"].rstrip("\n")]) == 0,
    "%d occurrences" % leaks(section, [sec["pem_lf"], sec["pem_lf"].rstrip("\n")]))
add("full CRLF key never appears (raw, JSON, repr forms)", leaks(section, [sec["pem_crlf"], sec["pem_crlf"].rstrip("\r\n")]) == 0,
    "%d occurrences" % leaks(section, [sec["pem_crlf"], sec["pem_crlf"].rstrip("\r\n")]))
n_lines = {}
for l in lines:
    if l in section:
        n_lines[l[:6] + "..."] = section.count(l)
add("no individual key line (LF or CRLF key, 8 lines >= 4 chars) appears", not n_lines, "leaked lines: %s" % (sorted(n_lines) or "none"))
add("single-line secret never appears", leaks(section, [sec["single"]]) == 0, "%d occurrences" % leaks(section, [sec["single"]]))

# Per task: every secret-printing task is masked and shows the marker; one row per task.
secret_tasks = [n for n in tnames if re.match(r"T(1\d|20) ", n)]
for n in secret_tasks:
    b = blocks[n]
    bad = leaks(b, secrets_full) + sum(1 for l in lines if l in b) + leaks(b, [sec["single"]])
    add("%s: masked, marker shown" % n, bad == 0 and "****" in b, "leaks=%d marker=%s" % (bad, "****" in b))

# Controls: public text must be untouched (no over-redaction).
def need(name_prefix, words):
    n = [x for x in tnames if x.startswith(name_prefix)]
    b = blocks[n[0]] if n else ""
    miss = [w for w in words if w not in b]
    return not miss and "****" not in b, "missing=%s marker_present=%s" % (miss, "****" in b)


ok, d = need("T21", ["public-alpha-1667", "-----BEGIN CERTIFICATE-----", "public-gamma-1667", "-----END CERTIFICATE-----"])
add("control T21: public multiline msg untouched", ok, d)
ok, d = need("T22", ["public-one-1667", "public-two-1667", "-----BEGIN CERTIFICATE-----"])
add("control T22: public command output untouched", ok, d)
t17 = blocks.get([x for x in tnames if x.startswith("T17")][0], "") if any(x.startswith("T17") for x in tnames) else ""
add("control T17: public lines around the key stay readable while the key is masked",
    "public-before-1667" in t17 and "public-after-1667" in t17 and "****" in t17, "before=%s after=%s marker=%s" % ("public-before-1667" in t17, "public-after-1667" in t17, "****" in t17))
add("inner run finished with failed=0", re.search(r"failed=0", out) is not None, "recap found=%s" % (re.search(r"failed=\d+", out) is not None))

# Observations: not pass/fail.
obs = []
for n in blocks:
    if n.startswith("OBS"):
        b = blocks[n]
        obs.append({"task": n, "key_text_visible": bool(sum(1 for l in lines if l in b)), "marker": "****" in b})
print(json.dumps({"cases": cases, "observations": obs, "fails": sum(1 for c in cases if c["result"] == "FAIL")}, indent=1))
