#!/usr/bin/env python3
# ------------------------------------------------------------------------- #
# gen_sweep.py -- build the MRS/MSR sweep (cs_sysregs) from the ARM-MRS
# Registers.json, with authoritative encodings and two filters so the sweep
# stays relevant:
#
#   * op0 filter (DEFAULT): only real system registers (op0 in {2,3}) are
#     emitted. op0==1 entries are SYS/SYSL *instructions* (AT/DC/IC/TLBI/BRB/
#     GIC/CFP/GCS-push...), NOT MRS/MSR registers; because the sweep masks
#     op0 & 1, an op0==1 entry would even collide with an op0==3 register.
#     Names containing a space (instruction "CLASS operand" forms) are dropped
#     too. Use --include-sys to keep them.
#
#   * feature gate (OPT-IN): drop registers that require a DISABLED extension.
#     "Requires FEAT_X" is read straight from each register's access AST (an
#     `Undefined` action guarded by exactly `!IsFeatureImplemented(FEAT_X)`).
#     The disabled set comes from --config <toml> (FEAT_*_IMPLEMENTED = false)
#     and/or --disabled-feats; --enabled-feats/--config true-flags are kept.
#     Conservative: only the unambiguous single-feature global guard drops a
#     register, so nothing accessible-without-the-feature is removed.
#
# Usage:
#   python3 gen_sweep.py Registers.json --config armv9p4_mmu_on.toml --out cs_sysregs.rs
#   python3 gen_sweep.py Registers.json --disabled-feats FEAT_MPAM,FEAT_SME --list
# ------------------------------------------------------------------------- #
import json
import sys
import argparse

FIELDS = ("op0", "op1", "crn", "crm", "op2")

# Name-prefix extension groups, for dropping whole optional extensions whose
# registers do not all carry a clean single-feature guard in the AST. PMU vs
# SPE are split on the PMB/PMS prefix (Profiling Buffer / Statistical Profiling).
def ext_groups_of(n):
    g = set()
    if n.startswith(("ICC_", "ICH_", "ICV_")): g.add("gic")
    if n.startswith(("AMC", "AMU", "AMEV")):    g.add("amu")     # not AMAIR (AMA*)
    if n.startswith(("PMB", "PMS")):            g.add("spe")
    elif n.startswith("PM"):                    g.add("pmu")
    if n.startswith("SPM"):                     g.add("spmu")
    if n.startswith("MPAM"):                    g.add("mpam")
    if n.startswith(("SMCR", "SMIDR", "SMPRI")) or n == "SVCR": g.add("sme")
    if n.startswith("ZCR_"):                    g.add("sve")
    if n.startswith(("TRC", "TRB", "TRF")):     g.add("trace")
    if n.startswith(("MECID", "VMECID")):       g.add("mec")
    if n.startswith("GCS"):                     g.add("gcs")
    if n.startswith("CNT"):                     g.add("timer")
    if n.startswith(("APIA", "APIB", "APDA", "APDB", "APGA")): g.add("pauth")
    if n.startswith(("ID_", "MVFR", "REVIDR", "CCSIDR", "CLIDR", "CTR_", "DCZID",
                     "GMID", "MIDR", "MPIDR", "VPIDR", "VMPIDR", "AIDR", "MECIDR")):
        g.add("ids")
    return g

ALL_EXT_GROUPS = ("gic", "amu", "spe", "pmu", "spmu", "mpam", "sme", "sve",
                  "trace", "mec", "gcs", "timer", "pauth", "ids")


def parse_val(v):
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
    if all(c in "01" for c in s):
        return int(s, 2)
    if s.isdigit():
        return int(s)
    return None


def aarch64_accessor(entry):
    """Return (accessor_dict, lowercased_encodings) for the AArch64 MRS/MSR
    accessor (the one whose encodings carry op0), or (None, None)."""
    for acc in entry.get("accessors", []):
        if not isinstance(acc, dict) or "SystemAccessor" not in acc.get("_type", ""):
            continue
        for enc in (acc.get("encoding") or []):
            low = {k.lower(): v for k, v in (enc.get("encodings") or {}).items()}
            if "op0" in low:
                return acc, low
    return None, None


def _is_undefined(node):
    return (isinstance(node, dict) and node.get("_type") == "AST.Function"
            and node.get("name") == "Undefined")


def _neg_single_feature(cond):
    """Return F iff cond is exactly !IsFeatureImplemented(F), else None."""
    if (isinstance(cond, dict) and cond.get("_type") == "AST.UnaryOp"
            and cond.get("op") == "!"):
        e = cond.get("expr")
        if (isinstance(e, dict) and e.get("_type") == "AST.Function"
                and e.get("name") == "IsFeatureImplemented"):
            args = e.get("arguments") or []
            if len(args) == 1 and isinstance(args[0], dict):
                return args[0].get("value")
    return None


def required_features(node, out):
    """Collect features F for which there is an UNCONDITIONAL `Undefined` guarded
    by `!IsFeatureImplemented(F)` -- i.e. the register does not exist without F."""
    if isinstance(node, dict):
        if "access" in node and "condition" in node and _is_undefined(node.get("access")):
            f = _neg_single_feature(node.get("condition"))
            if f:
                out.add(f)
        for v in node.values():
            required_features(v, out)
    elif isinstance(node, list):
        for v in node:
            required_features(v, out)
    return out


def load_lenient(path):
    raw = open(path).read()
    try:
        return json.loads(raw)
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
        sys.stderr.write("# NOTE: input truncated; parsed first %d complete entries.\n"
                         % len(data))
        return data


def feats_from_config(path):
    """Return (enabled, disabled) feature-name sets from a Sail TOML config,
    mapping FEAT_X_IMPLEMENTED -> FEAT_X."""
    import re
    enabled, disabled = set(), set()
    for line in open(path):
        m = re.search(r'"?(FEAT_[A-Za-z0-9_]+?)(?:_IMPLEMENTED)?"?\s*=\s*(true|false)', line)
        if m:
            (enabled if m.group(2) == "true" else disabled).add(m.group(1))
    return enabled, disabled


def main():
    ap = argparse.ArgumentParser(description="Generate cs_sysregs sweep from Registers.json")
    ap.add_argument("registers_json")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--out", default=None)
    ap.add_argument("--include-sys", action="store_true",
                    help="keep op0!=2/3 SYS instructions and space-named entries (default: drop)")
    ap.add_argument("--config", default=None,
                    help="Sail TOML; FEAT_*_IMPLEMENTED=false registers are dropped")
    ap.add_argument("--disabled-feats", default="",
                    help="comma-separated extra features to treat as disabled")
    ap.add_argument("--enabled-feats", default="",
                    help="comma-separated features to force-keep (overrides disabled)")
    ap.add_argument("--skip-substr", action="append", default=[])
    ap.add_argument("--drop-ext", default="",
                    help="comma-separated extension groups to drop by name: "
                         + ",".join(ALL_EXT_GROUPS))
    ap.add_argument("--list-ext", action="store_true",
                    help="list extension groups and how many of the emitted regs each covers")
    args = ap.parse_args()

    drop_ext = {g.strip() for g in args.drop_ext.split(",") if g.strip()}
    bad_ext = drop_ext - set(ALL_EXT_GROUPS)
    if bad_ext:
        ap.error("unknown --drop-ext group(s): %s (known: %s)"
                 % (", ".join(sorted(bad_ext)), ", ".join(ALL_EXT_GROUPS)))

    disabled, enabled = set(), set()
    if args.config:
        en, dis = feats_from_config(args.config)
        enabled |= en; disabled |= dis
    disabled |= {f.strip() for f in args.disabled_feats.split(",") if f.strip()}
    enabled |= {f.strip() for f in args.enabled_feats.split(",") if f.strip()}
    disabled -= enabled                       # explicit enable wins

    data = load_lenient(args.registers_json)
    if isinstance(data, dict):
        data = data.get("registers") or next(
            (v for v in data.values() if isinstance(v, list)), [])

    rows = {}
    n_sys = n_feat = n_a32 = n_ext = 0
    dropped_feat = {}
    ext_counts = {g: 0 for g in ALL_EXT_GROUPS}

    def is_disabled(feat):
        # family-aware: FEAT_MPAM disabled also disables FEAT_MPAMv1p1, FEAT_SME -> FEAT_SME2, etc.
        return any(feat == d or feat.startswith(d) for d in disabled)

    for entry in data:
        if not isinstance(entry, dict) or entry.get("_type") != "Register":
            continue
        name = entry.get("name", "")
        if not name or any(s in name for s in args.skip_substr):
            continue
        acc, low = aarch64_accessor(entry)
        if acc is None:
            n_a32 += 1
            continue
        vals = {f: parse_val(low.get(f)) for f in FIELDS}
        if any(vals[f] is None for f in FIELDS):
            continue
        enc = (vals["op0"], vals["op1"], vals["crn"], vals["crm"], vals["op2"])

        # op0 / SYS-instruction filter
        if not args.include_sys and (enc[0] not in (2, 3) or " " in name):
            n_sys += 1
            continue

        # feature gate (family-aware)
        if disabled:
            req = required_features(acc.get("access"), set())
            bad = {f for f in req if is_disabled(f)}
            if bad:
                n_feat += 1
                dropped_feat[name] = sorted(bad)
                continue

        # extension-group drop (by name prefix)
        groups = ext_groups_of(name)
        for g in groups:
            ext_counts[g] += 1
        if drop_ext and (groups & drop_ext):
            n_ext += 1
            continue

        rows[name] = enc

    if args.list_ext:
        sys.stderr.write("# extension-group coverage of the emitted set "
                         "(before --drop-ext):\n")
        for g in ALL_EXT_GROUPS:
            sys.stderr.write("#   %-7s %d\n" % (g, ext_counts[g]))
        return

    lines = []
    if args.list:
        for n in sorted(rows):
            lines.append("%s %d %d %d %d %d" % (n, *rows[n]))
    else:
        lines.append("// Auto-generated by gen_sweep.py -- do not hand-edit.")
        lines.append("// (op0, op1, CRn, CRm, op2); o0 field used = op0 & 1.")
        lines.append("let cs_sysregs: &[(&str, u64, u64, u64, u64, u64)] = &[")
        for n in sorted(rows):
            lines.append('    ("%s", %d, %d, %d, %d, %d),' % (n, *rows[n]))
        lines.append("];")
    out_text = "\n".join(lines) + "\n"
    if args.out:
        open(args.out, "w").write(out_text)
        sys.stderr.write("# Wrote %d registers to %s\n" % (len(rows), args.out))
    else:
        sys.stdout.write(out_text)

    sys.stderr.write("\n# %d sweep registers emitted.\n" % len(rows))
    sys.stderr.write("# dropped: %d SYS-instructions (op0!=2/3 or spaced), "
                     "%d feature-disabled, %d extension-group, %d AArch32-only.\n"
                     % (n_sys, n_feat, n_ext, n_a32))
    if drop_ext:
        sys.stderr.write("# extension groups dropped: %s\n" % ", ".join(sorted(drop_ext)))
    if disabled:
        sys.stderr.write("# disabled features applied: %s\n" % ", ".join(sorted(disabled)))
    if dropped_feat:
        sample = list(sorted(dropped_feat))[:25]
        sys.stderr.write("# feature-dropped e.g.: %s\n"
                         % ", ".join("%s(%s)" % (r, "/".join(dropped_feat[r])) for r in sample))


if __name__ == "__main__":
    main()
