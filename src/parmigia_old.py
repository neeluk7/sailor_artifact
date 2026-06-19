import os
import sys
import csv
import json
import re

REGISTER_JSONpath  = '../AARCHMRS/Registers.json'
ISLA_TRACES_DIR    = '../arm_traces_output'
OUTPUT_DIR         = 'big_isla_traces_test'

INSTR_SKIP_LIST = set()

MAX_PARTS = [
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

# Each trace in the isla output begins with one of these headers:
#   --- Instruction: NAME | Mode: ELx | throw_at: None ---
#   --- Instruction: NAME | Mode: ELx | throw_at: Some("src/...") ---
#   --- Instruction: NAME | Mode: ELx | EXEC_ERR: <message> ---
# The harness writes ONE header per execution path, so a single instruction
# can have several consecutive trace blocks here.
HEADER_SPLIT = re.compile(r'(?=--- Instruction:)')


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
    """Per-instruction verdict from the tally across ALL of its traces."""
    total = clean + exception + undefined + exec_err
    if total == 0:
        return "No traces"
    if clean == total:
        return "Allowed"
    if clean > 0:
        # At least one path executes cleanly and at least one fails: the
        # instruction is legal but its behaviour is input-dependent.
        return "Conditional"
    # No clean path at all. Report the dominant blocking reason.
    if exec_err == total:
        return "Timeout/ExecErr"
    if undefined == total:
        return "Not allowed (undefined)"
    if exception == total:
        return "Not allowed (exception)"
    return "Not allowed (mixed)"


def _merge_reg(fp, reg, is_write):
    """Add a sysreg access to a footprint list, promoting Read -> Write."""
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
    """True iff this trace contains an actual Error_Undefined exception event.

    Matched the same precise way as the original parser (a write-reg event to
    the exception variable carrying Error_Undefined) so the Error_Undefined
    type name appearing in an enum *definition* does not false-positive every
    trace.
    """
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

        # One chunk == one trace (header + its event body).
        for chunk in HEADER_SPLIT.split(content):
            if not chunk.startswith("--- Instruction:"):
                continue  # any preamble before the first header

            chunk_lines = chunk.splitlines()
            header = chunk_lines[0]
            name = header.replace("--- Instruction:", "").split("|")[0].strip()
            if not name:
                continue

            footprint[el].setdefault(name, [])
            counts[el].setdefault(name, [0, 0, 0, 0])

            # --- Classify THIS trace -------------------------------------
            #   exec-err : executor failed/timed out (no usable body)
            #   undefined: model raised Error_Undefined (UNALLOCATED decode)
            #   exception: model took an architectural exception (throw_at Some)
            #              -> alignment/FP/abort; body is HANDLER state, not the
            #                 instruction's own footprint, so it is discarded
            #   clean    : completed normally -> contributes footprint
            if "EXEC_ERR" in header:
                counts[el][name][3] += 1
                continue
            if _trace_is_undefined(chunk_lines):
                counts[el][name][2] += 1
                continue
            if "throw_at: Some" in header:
                counts[el][name][1] += 1
                continue

            # Clean path: record its sysreg footprint.
            counts[el][name][0] += 1
            fp = footprint[el][name]
            for ln in chunk_lines:
                if "field" in ln:
                    continue
                if "read-reg" in ln:
                    parts = ln.split("|")
                    if len(parts) >= 2:
                        reg = parts[1].strip()
                        if reg in sysregs:
                            _merge_reg(fp, reg, False)
                elif "write-reg" in ln:
                    parts = ln.split("|")
                    if len(parts) >= 2:
                        reg = parts[1].strip()
                        if reg in sysregs:
                            _merge_reg(fp, reg, True)

    access = [{}, {}, {}, {}]
    for el in range(4):
        for name, c in counts[el].items():
            access[el][name] = classify(*c)

    return footprint, access, counts


def write_csvs(footprint, access, counts):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    el_names       = ["EL0", "EL1", "EL2", "EL3"]
    fp_files       = [f"sysreg_footprint_per_instruction_el{i}.csv" for i in range(4)]
    access_file    = os.path.join(OUTPUT_DIR, "instruction_access_per_mode.csv")
    breakdown_file = os.path.join(OUTPUT_DIR, "trace_breakdown_per_instruction.csv")

    all_instrs = sorted(
        instr
        for instr in set().union(*(fp.keys() for fp in footprint))
        if instr not in INSTR_SKIP_LIST and instr != ""
    )

    # Per-EL footprint CSVs (clean-path footprints only) -- same format as before
    # so unique_witness.py / minimal_cover.py keep working unchanged.
    for el in range(4):
        path = os.path.join(OUTPUT_DIR, fp_files[el])
        with open(path, 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(["Instruction", "Sysreg footprint"])
            for instr in all_instrs:
                w.writerow([instr] + footprint[el].get(instr, []))

    # Combined access CSV -- same format as before.
    with open(access_file, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(["Instruction"] + el_names)
        for instr in all_instrs:
            w.writerow([instr] + [access[el].get(instr, "No data") for el in range(4)])

    # New diagnostics: per-instruction, per-EL trace breakdown so a verdict is
    # explainable ("Not allowed (exception)" with 0 clean / 3 exception, etc.).
    with open(breakdown_file, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(["Instruction", "EL", "Clean", "Exception", "Undefined", "ExecErr", "Status"])
        for instr in all_instrs:
            for el in range(4):
                c = counts[el].get(instr)
                if c:
                    w.writerow([instr, el_names[el]] + c + [access[el].get(instr, "No data")])

    print(f"Successfully processed {len(all_instrs)} instructions inside {OUTPUT_DIR}/")
    for el in range(4):
        agg = [0, 0, 0, 0]
        for c in counts[el].values():
            for i in range(4):
                agg[i] += c[i]
        print(f"  {el_names[el]}: clean={agg[0]} exception={agg[1]} "
              f"undefined={agg[2]} execerr={agg[3]}")


if __name__ == "__main__":
    sysregs                    = load_sysreg_list(REGISTER_JSONpath)
    footprint, access, counts  = parse_traces(ISLA_TRACE_FILES, sysregs)
    write_csvs(footprint, access, counts)
