#!/usr/bin/env python3
# ------------------------------------------------------------------------- #
# gen_sweep.py -- build the COMPLETE MRS/MSR sweep (cs_sysregs) from the
# ARM-MRS Registers.json, so you never hand-curate (and never mis-encode) the
# list again. Every register that has a System accessor is emitted with its
# authoritative (op0, op1, CRn, CRm, op2) encoding.
#
# Usage:
#   python3 gen_sweep.py Registers.json            # prints the Rust cs_sysregs block
#   python3 gen_sweep.py Registers.json --list     # prints "NAME op0 op1 CRn CRm op2"
#   python3 gen_sweep.py Registers.json --out cs_sysregs.rs
#
# It is schema-robust: it recursively searches each System accessor for fields
# named op0/op1/CRn/CRm/op2 (case-insensitive) and parses bit-string ('11'),
# 0b-prefixed, or decimal values. Any register whose 5 fields cannot all be
# found is reported (with the raw accessor of the first failure dumped) so the
# extraction can be adjusted -- nothing is silently guessed.
# ------------------------------------------------------------------------- #
import json
import sys
import argparse

FIELDS = ("op0", "op1", "crn", "crm", "op2")


def parse_val(v):
    """Parse an ARM-MRS encoding value into an int. Accepts bit strings like
    "'1100'", "0b1100", "1100" (binary), or decimal "12"; or a dict carrying a
    'value'. Returns None if unparseable."""
    if isinstance(v, dict):
        for k in ("value", "val", "bits"):
            if k in v:
                return parse_val(v[k])
        return None
    if isinstance(v, int):
        return v
    if not isinstance(v, str):
        return None
    s = v.strip().strip("'").strip('"').strip()
    if s.startswith(("0b", "0B")):
        s = s[2:]
    if s == "":
        return None
    if all(c in "01" for c in s):           # bit string -> binary
        return int(s, 2)
    if s.isdigit():                          # plain decimal
        return int(s)
    return None


def extract_aarch64(entry):
    """Pull (op0, op1, CRn, CRm, op2) from a register's AArch64 MRS/MSR accessor.

    Real ARM-MRS schema: accessors[] (each a SystemAccessor) carry
    `encoding`: [ { "_type":"Encoding", "asmvalue":<name>,
                    "encodings": { "op0": {"value":"'11'"}, "op1": {...},
                                   "CRn": {...}, "CRm": {...}, "op2": {...} } } ]
    AArch32 accessors (A32.MRC/MCR) instead carry coproc/opc1/opc2 -- those are
    skipped: the presence of an "op0" key is the AArch64 discriminator.

    Returns ((op0,op1,crn,crm,op2), asmname) or (None, reason)."""
    saw_system = False
    for acc in entry.get("accessors", []):
        if not isinstance(acc, dict) or "SystemAccessor" not in acc.get("_type", ""):
            continue
        saw_system = True
        for enc in (acc.get("encoding") or []):
            encs = enc.get("encodings") or {}
            # case-insensitive key map for robustness
            low = {k.lower(): v for k, v in encs.items()}
            if "op0" not in low:                       # AArch32 (coproc/opc1/opc2)
                continue
            vals = {f: parse_val(low.get(f)) for f in FIELDS}
            if all(vals[f] is not None for f in FIELDS):
                return ((vals["op0"], vals["op1"], vals["crn"], vals["crm"], vals["op2"]),
                        enc.get("asmvalue"))
            return (None, "AArch64 accessor but unparseable encodings: %r" % encs)
    if not saw_system:
        return (None, "no System accessor")
    return (None, "AArch32-only (no AArch64 op0 encoding)")


def load_lenient(path):
    """json.load, but tolerate a truncated chunk by trimming to the last
    complete top-level array element."""
    raw = open(path).read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        depth = 0; in_str = False; esc = False; last = None
        for i, ch in enumerate(raw):
            if esc: esc = False; continue
            if ch == '\\': esc = True; continue
            if ch == '"': in_str = not in_str; continue
            if in_str: continue
            if ch == '{': depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0: last = i
        if last is None:
            raise
        data = json.loads(raw[:last + 1] + "]")
        sys.stderr.write("# NOTE: input looked truncated; parsed first %d complete "
                         "entries.\n" % len(data))
    if isinstance(data, dict):
        data = data.get("registers") or next(
            (v for v in data.values() if isinstance(v, list)), [])
    return data


def main():
    ap = argparse.ArgumentParser(description="Generate cs_sysregs sweep from Registers.json")
    ap.add_argument("registers_json")
    ap.add_argument("--list", action="store_true", help="emit 'NAME op0 op1 CRn CRm op2' instead of Rust")
    ap.add_argument("--out", default=None, help="write to file instead of stdout")
    ap.add_argument("--skip-substr", action="append", default=[],
                    help="skip register names containing this substring (repeatable)")
    args = ap.parse_args()

    data = load_lenient(args.registers_json)

    rows = {}            # name -> (op0,op1,crn,crm,op2)
    aarch32_only = []    # registers with no AArch64 MRS/MSR encoding (correctly skipped)
    unparsed = []        # AArch64 accessor present but encoding unreadable (REPORT)
    first_bad = None

    for entry in data:
        if not isinstance(entry, dict) or entry.get("_type") != "Register":
            continue
        name = entry.get("name", "")
        if not name or any(sub in name for sub in args.skip_substr):
            continue
        enc, info = extract_aarch64(entry)
        if enc is not None:
            rows[name] = enc
        elif "unparseable" in (info or ""):
            unparsed.append(name)
            if first_bad is None:
                first_bad = (name, entry.get("accessors"))
        else:
            aarch32_only.append(name)   # or no system accessor -- not an error

    lines = []
    if args.list:
        for n in sorted(rows):
            lines.append("%s %d %d %d %d %d" % (n, *rows[n]))
    else:
        lines.append("// Auto-generated by gen_sweep.py from Registers.json -- do not")
        lines.append("// hand-edit. (op0, op1, CRn, CRm, op2); o0 field used = op0 & 1.")
        lines.append("let cs_sysregs: &[(&str, u64, u64, u64, u64, u64)] = &[")
        for n in sorted(rows):
            lines.append('    ("%s", %d, %d, %d, %d, %d),' % (n, *rows[n]))
        lines.append("];")
    out_text = "\n".join(lines) + "\n"

    if args.out:
        open(args.out, "w").write(out_text)
        sys.stderr.write("# Wrote %d AArch64 registers to %s\n" % (len(rows), args.out))
    else:
        sys.stdout.write(out_text)

    sys.stderr.write("\n# %d AArch64 sweep registers emitted.\n" % len(rows))
    sys.stderr.write("# %d AArch32-only registers skipped (no MRS/MSR encoding -- "
                     "expected).\n" % len(aarch32_only))
    if unparsed:
        sys.stderr.write("# %d AArch64 register(s) had an UNREADABLE encoding -- "
                         "check schema:\n#   %s\n"
                         % (len(unparsed), ", ".join(sorted(unparsed)[:40])))
        if first_bad:
            sys.stderr.write("# sample accessors for '%s':\n%s\n"
                             % (first_bad[0], json.dumps(first_bad[1], indent=1)[:1500]))


if __name__ == "__main__":
    main()
