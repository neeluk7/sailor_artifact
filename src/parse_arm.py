import os
import sys
import csv
import json
import re

# Paths are env-overridable so the parser can be pointed at a test fixture
# (or a relocated tree) without editing the source. Defaults unchanged.
REGISTER_JSONpath  = os.environ.get('SAILOR_REGISTERS_JSON', '../AARCHMRS/Registers.json')
ISLA_TRACES_DIR    = os.environ.get('SAILOR_TRACES_DIR',    '../arm_traces_output')
OUTPUT_DIR         = os.environ.get('SAILOR_OUTPUT_DIR',    '../results')

INSTR_SKIP_LIST = set()

EXCLUDE_DEAD = True

# SAILOR_MAX_PARTS=N collapses the per-EL part count to N (handy for a small
# --only run or a fixture). Default is the full sweep size.
_mp = os.environ.get('SAILOR_MAX_PARTS')
MAX_PARTS = [int(_mp)] * 4 if _mp else [
    216,
    216,
    216,
    216,
]

ISLA_TRACE_FILES = [
    f"EL{el}_part_{str(part).zfill(4)}.txt"
    for el in range(4)
    for part in range(1, MAX_PARTS[el] + 1)
]

SYSREG_SKIP_EXACT = {
    'CCSIDR_EL1', 'CCSIDR2_EL1',
    'VMPIDR_EL2', 'VPIDR_EL2',
    'PSTATE',
}
SYSREG_SKIP_SUBSTRINGS = ['ALLINT', 'PM', 'S1_', 'S3_', 'SVCR']

# --------------------------------------------------------------------------- #
# Alias / internal -> architectural register-name canonicalization.
#
# THE CORE FIX. During a stage-1 page-table walk the Sail/isla model reads the
# translation base and memory-attribute registers under the model-internal or
# AArch32-banked spellings, NOT under their architectural AArch64 names:
#
#     EL1 walk base   : TTBR0_NS / _TTBR0_EL1   (architectural: TTBR0_EL1)
#     EL1 high base   : TTBR1_NS / _TTBR1_EL1   (architectural: TTBR1_EL1)
#     EL2 walk base   : HTTBR    / _TTBR0_EL2   (architectural: TTBR0_EL2)
#     stage-2 base    : VTTBR    / _VTTBR_EL2   (architectural: VTTBR_EL2)
#     attributes      : _MAIR_EL1 / MAIR0_NS..  (architectural: MAIR_EL1, ...)
#
# load_sysreg_list() only keeps names that appear in Registers.json with a
# SystemAccessor, so the underscore-prefixed internal registers and the _NS
# banked aliases were silently dropped by the `reg in sysregs` filter -- which
# is exactly why TTBR0_EL1/TTBR1_EL1/MAIR_EL1 never showed up in any EL0/EL1
# footprint and therefore never became EL*->EL0 channels.
#
# Canonicalizing the name BEFORE the membership test makes the architectural
# name (which IS in Registers.json) survive.
#
# NOTE(confirm-against-a-real-trace): the explicit entries below are the
# spellings called out in the config (TTBR0_NS / HTTBR primacy, the zeroed
# 128-bit _TTBR0_EL{1,2}) and the task description. Step 1 of the task is to
# grep one real clean EL0 LDR trace for TTBR/MAIR spellings and verify these.
# Add ONLY spellings you actually observe; do not invent names. The generic
# leading-underscore fallback in canonicalize_reg() never invents a name -- it
# only collapses `_X` to `X` when `X` is already a tracked architectural reg.
# --------------------------------------------------------------------------- #
REG_ALIASES = {
    # EL1 stage-1 translation base (low / high halves)
    "TTBR0_NS": "TTBR0_EL1", "_TTBR0_EL1": "TTBR0_EL1",
    "TTBR1_NS": "TTBR1_EL1", "_TTBR1_EL1": "TTBR1_EL1",
    # EL2 stage-1 base (AArch32 name HTTBR has primacy in the config)
    "HTTBR": "TTBR0_EL2", "_TTBR0_EL2": "TTBR0_EL2",
    # stage-2 base (AArch32 name VTTBR)
    "VTTBR": "VTTBR_EL2", "_VTTBR_EL2": "VTTBR_EL2",
    # EL3 secure base (if the walk ever runs there)
    "TTBR0_S": "TTBR0_EL3", "_TTBR0_EL3": "TTBR0_EL3",
    # memory-attribute registers
    "_MAIR_EL1": "MAIR_EL1", "MAIR0_NS": "MAIR_EL1", "MAIR1_NS": "MAIR_EL1",
    "_MAIR_EL2": "MAIR_EL2", "HMAIR0": "MAIR_EL2", "HMAIR1": "MAIR_EL2",
    "_MAIR_EL3": "MAIR_EL3",
}


def canonicalize_reg(reg, sysregs):
    """Map a model-internal / banked register spelling to its architectural
    AArch64 name, so the `reg in sysregs` membership filter keeps it.

    1. Explicit observed aliases (REG_ALIASES) take priority.
    2. Generic fallback: a leading-underscore internal register `_X` is
       collapsed to `X` ONLY when `X` is a real tracked sysreg. This cannot
       introduce a name that is not already in the universe."""
    if reg in REG_ALIASES:
        return REG_ALIASES[reg]
    if reg not in sysregs and reg.startswith("_") and reg[1:] in sysregs:
        return reg[1:]
    return reg


HEADER_SPLIT = re.compile(r'(?=--- Instruction:)')

# A status counts as "usable" iff at least one execution path completed cleanly.
USABLE_STATUSES = {"Allowed", "Conditional"}


def load_sysreg_list(json_path):
    with open(json_path) as f:
        data = json.load(f)

    sysregs = set()
    for entry in data:
        if not isinstance(entry, dict) or entry.get('_type') != 'Register':
            continue
        name = entry.get('name', '')
        if not name or name in SYSREG_SKIP_EXACT:
            continue
        if any(s in name.upper() for s in SYSREG_SKIP_SUBSTRINGS):
            continue
        if any(a.get('_type') == 'Accessors.SystemAccessor'
               for a in entry.get('accessors', [])):
            sysregs.add(name)

    print(f"Loaded {len(sysregs)} system registers from {json_path}")
    return sysregs


def classify(clean, exception, undefined, exec_err):
    """Collapsed, binary-outcome classification.

    An instruction/EL pairing is only ever reported as one of:
        "No traces"   -- total == 0, nothing was ever measured.
        "Allowed"     -- every trace that ran completed cleanly.
        "Conditional" -- at least one trace completed cleanly, but not all
                         (some paths are gated on state/condition codes).
        "Not allowed" -- total > 0 and NOT ONE trace completed cleanly,
                         regardless of *why* (undefined, exception, execerr,
                         or a mix of those). The old build separated this
                         into "Not allowed (undefined)" / "(exception)" /
                         "Timeout/ExecErr" / "(mixed)"; that distinction is
                         no longer surfaced here -- if the caller wants it,
                         it's still fully recoverable from the raw counts in
                         trace_breakdown_per_instruction.csv.
    """
    total = clean + exception + undefined + exec_err
    if total == 0:
        return "No traces"
    if clean == total:
        return "Allowed"
    if clean > 0:
        return "Conditional"
    return "Not allowed"


def _merge_reg(fp, reg, is_write):
    rd, wr = reg + " Read", reg + " Write"
    if is_write:
        if wr in fp:
            return
        if rd in fp:
            fp[fp.index(rd)] = wr
        else:
            fp.append(wr)
    else:
        if rd in fp or wr in fp:
            return
        fp.append(rd)


def _trace_is_undefined(chunk_lines):
    for ln in chunk_lines:
        if "write-reg" in ln and "exception" in ln and "Error_Undefined" in ln:
            return True
    return False


def parse_traces(trace_files, sysregs):
    footprint = [{}, {}, {}, {}]
    counts    = [{}, {}, {}, {}]   # counts[el][instr] = [clean, exc, undef, eerr]

    for filename in trace_files:
        el = next(
            (i for i, tok in enumerate(["el0", "el1", "el2", "el3"])
             if tok in filename.lower()),
            -1,
        )
        if el == -1:
            sys.exit(f"Error: could not determine EL from filename '{filename}'.")

        filepath = os.path.join(ISLA_TRACES_DIR, filename)
        if not os.path.exists(filepath):
            print(f"Warning: File {filepath} not found. Skipping.")
            continue

        with open(filepath) as f:
            content = f.read()

        for chunk in HEADER_SPLIT.split(content):
            if not chunk.startswith("--- Instruction:"):
                continue

            chunk_lines = chunk.splitlines()
            header = chunk_lines[0]
            name = header.replace("--- Instruction:", "").split("|")[0].strip()
            if not name:
                continue

            footprint[el].setdefault(name, [])
            counts[el].setdefault(name, [0, 0, 0, 0])

            if "EXEC_ERR" in header:
                counts[el][name][3] += 1
                continue
            if _trace_is_undefined(chunk_lines):
                counts[el][name][2] += 1
                continue
            if "throw_at: Some" in header:
                counts[el][name][1] += 1
                continue

            counts[el][name][0] += 1
            fp = footprint[el][name]
            for ln in chunk_lines:
                # NOTE: do NOT `continue` on lines containing "field". The model
                # reads several context-switch registers through a FIELD accessor,
                # e.g. MAIR is read as `(read-reg |MAIR_EL1| ((_ field |bits|)) ...)`
                # and `(read-reg |MAIR2_EL1| ((_ field |bits|)) ...)`. The old
                # blanket `if "field" in ln: continue` dropped every such line
                # BEFORE the read-reg check, so MAIR_EL1/MAIR2_EL1 (and any other
                # field-accessed reg) never entered the footprint. The register
                # name is always the FIRST `|...|` token (parts[1]); the field
                # name sits in a later token and is simply never used, so keying on
                # parts[1] captures the register correctly whether the access is a
                # whole-register read (`nil` accessor) or a field read.
                if "read-reg" in ln:
                    parts = ln.split("|")
                    if len(parts) >= 2:
                        reg = canonicalize_reg(parts[1].strip(), sysregs)
                        if reg in sysregs:
                            _merge_reg(fp, reg, False)
                elif "write-reg" in ln:
                    parts = ln.split("|")
                    if len(parts) >= 2:
                        reg = canonicalize_reg(parts[1].strip(), sysregs)
                        if reg in sysregs:
                            _merge_reg(fp, reg, True)

    access = [{}, {}, {}, {}]
    for el in range(4):
        for name, c in counts[el].items():
            access[el][name] = classify(*c)

    return footprint, access, counts


def _dead_reason(statuses):
    """Why an instruction is dead (it has no usable EL).

    With classify() collapsed to Allowed/Conditional/Not allowed/No traces,
    the fine-grained "why" (undefined vs exception vs timeout vs mixed) is no
    longer encoded in the status string itself. This only distinguishes
    "never measured anywhere" from "measured everywhere and never usable";
    the raw per-EL counts (clean/exception/undefined/execerr) are still
    written out in full to trace_breakdown_per_instruction.csv for anyone who
    needs the finer detail.
    """
    real = [s for s in statuses if s != "No traces"]
    if not real:
        return "no-data"
    return "always-failing"


def write_csvs(footprint, access, counts):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    el_names       = ["EL0", "EL1", "EL2", "EL3"]
    fp_files       = [f"sysreg_footprint_per_instruction_el{i}.csv" for i in range(4)]
    access_file    = os.path.join(OUTPUT_DIR, "instruction_access_per_mode.csv")
    breakdown_file = os.path.join(OUTPUT_DIR, "trace_breakdown_per_instruction.csv")
    excluded_file  = os.path.join(OUTPUT_DIR, "excluded_instructions.csv")
    live_list_file = os.path.join(OUTPUT_DIR, "live_instructions.txt")

    all_instrs = sorted(
        instr
        for instr in set().union(*(fp.keys() for fp in footprint))
        if instr not in INSTR_SKIP_LIST and instr != ""
    )

    # Split into live (usable at >=1 EL) and dead (usable nowhere).
    live, dead = [], []
    for instr in all_instrs:
        statuses = [access[el].get(instr, "No data") for el in range(4)]
        if any(s in USABLE_STATUSES for s in statuses):
            live.append(instr)
        else:
            dead.append((instr, statuses, _dead_reason(statuses)))

    emit = live if EXCLUDE_DEAD else all_instrs

    # The MRS/MSR sweep probes ARE the direct-access matrix: a probe that is
    # undefined/exception at every EL is a real measurement ("this register is
    # not directly accessible anywhere"), not noise to drop. If EXCLUDE_DEAD
    # removed such a probe, the analyzer would never see an MRS@<reg> row and
    # would wrongly call the register "unprobed" instead of "measured: not
    # accessible". This bit SMCR_EL*/ZCR_EL*/SP_EL0 (dead because SME/SVE access
    # is off in the config, or architecturally non-MRS-able) even though they
    # ARE in the sweep. So always emit the sweep rows, dead or not.
    SWEEP_PREFIXES = ("MRS_RS_systemmove@", "MSR_SR_systemmove@")
    emit = sorted(set(emit) | {i for i in all_instrs if i.startswith(SWEEP_PREFIXES)})

    # Per-EL footprint CSVs (clean-path footprints, live instructions only).
    for el in range(4):
        path = os.path.join(OUTPUT_DIR, fp_files[el])
        with open(path, 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(["Instruction", "Sysreg footprint"])
            for instr in emit:
                w.writerow([instr] + footprint[el].get(instr, []))

    # Combined access CSV (live instructions only).
    with open(access_file, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(["Instruction"] + el_names)
        for instr in emit:
            w.writerow([instr] + [access[el].get(instr, "No data") for el in range(4)])

    # Trace breakdown for every instruction (live and dead) -- diagnostics.
    with open(breakdown_file, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(["Instruction", "EL", "Clean", "Exception", "Undefined", "ExecErr", "Status"])
        for instr in all_instrs:
            for el in range(4):
                c = counts[el].get(instr)
                if c:
                    w.writerow([instr, el_names[el]] + c + [access[el].get(instr, "No data")])

    with open(excluded_file, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(["Instruction"] + el_names + ["Reason"])
        for instr, statuses, reason in dead:
            w.writerow([instr] + statuses + [reason])

    # Live keep-list: feed straight back into the harness as --keep-list to
    # re-run only the instructions worth tracing.
    with open(live_list_file, 'w') as f:
        for instr in live:
            f.write(instr + "\n")

    print(f"Live (usable >=1 EL): {len(live)}   Excluded (dead): {len(dead)}")
    reasons = {}
    for _, _, r in dead:
        reasons[r] = reasons.get(r, 0) + 1
    for r in sorted(reasons):
        print(f"  excluded [{r}]: {reasons[r]}")
    for el in range(4):
        agg = [0, 0, 0, 0]
        for c in counts[el].values():
            for i in range(4):
                agg[i] += c[i]
        print(f"  {el_names[el]}: clean={agg[0]} exception={agg[1]} "
              f"undefined={agg[2]} execerr={agg[3]}")
    print(f"Wrote footprints/access/breakdown + excluded_instructions.csv + "
          f"live_instructions.txt to {OUTPUT_DIR}/")


if __name__ == "__main__":
    sysregs                   = load_sysreg_list(REGISTER_JSONpath)
    footprint, access, counts = parse_traces(ISLA_TRACE_FILES, sysregs)
    write_csvs(footprint, access, counts)
