
import os
import sys
import csv
import re
import json
 
 
REGISTER_JSONpath  = '../AARCHMRS/Registers.json'
ISLA_TRACES_DIR    = '../arm_traces_output'
OUTPUT_DIR         = 'big_isla_traces_test'
 
INSTR_SKIP_LIST = set()
 
ISLA_TRACE_FILES = [
    "EL0_part_0001.txt",
     "EL1_part_0001.txt",
     "EL2_part_0001.txt",
     "EL3_part_0001.txt",
      
]
 

SYSREG_SKIP_EXACT = {
    'CCSIDR_EL1', 'CCSIDR2_EL1',
    'VMPIDR_EL2', 'VPIDR_EL2',
    'PSTATE',
}
SYSREG_SKIP_SUBSTRINGS = ['ALLINT', 'PM', 'S1_', 'S3_', 'SVCR']
 
ESR_REGS = {"(write-reg |ESR_EL1|", "(write-reg |ESR_EL2|", "(write-reg |ESR_EL3|"}
 


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
            print(name)
 
    print(f"Loaded {len(sysregs)} system registers from {json_path}")
    return sysregs
 
 
def classify(total, illegal):
    if total == 0:
        return "No traces"
    if illegal == 0:
        return "Allowed"
    if illegal < total:
        return "Conditional"
    if illegal == total:
        return "Not allowed"
    return "Undetermined"
 
 
def _is_illegal_esr(line):
    """Return True if the line is an ESR write whose EC field equals 0."""
    m = re.search(r'#x([0-9a-fA-F]+)', line)
    return bool(m and ((int(m.group(1), 16) >> 26) & 0x3F) == 0)


def parse_traces(trace_files, sysregs):
    footprint = [{}, {}, {}, {}]
    access    = [{}, {}, {}, {}]

    for filename in trace_files:
        el = next(
            (i for i, tok in enumerate(["el0", "el1", "el2", "el3"])
             if tok in filename.lower()),
            -1,
        )
        if el == -1:
            sys.exit(f"Error: could not determine EL from filename '{filename}'.")

        filepath = os.path.join(ISLA_TRACES_DIR, filename)
        with open(filepath) as f:
            lines = f.readlines()

        instr            = ""
        total_traces     = 0
        illegal_traces   = 0
        # Per-trace state
        trace_is_illegal = False
        trace_has_branch = False
        in_preamble      = True

        def close_trace():
            """Finalise the current trace: if it never branched, it's illegal."""
            nonlocal trace_is_illegal, illegal_traces
            if total_traces > 0 and not trace_has_branch:
                if not trace_is_illegal:
                    trace_is_illegal = True
                    illegal_traces += 1

        def commit():
            """Save classification for the current instruction block."""
            nonlocal instr
            close_trace()
            if instr:
                access[el][instr] = classify(total_traces, illegal_traces)
                print(total_traces,illegal_traces)

       
        for line in lines:

            # ── New instruction block ────────────────────────────────────────
            if "--- Instruction:" in line:

                new_instr            = line.split(":")[1].strip()
                if  new_instr != instr:
                    commit()
                    print("Instruction : ", instr, "Total traces", total_traces, "Illegal_traces", illegal_traces)
                    instr = new_instr
 
                    total_traces     = 0
                    illegal_traces   = 0
                    trace_is_illegal = False
                    trace_has_branch = False
                    in_preamble      = True
                    for i in range(4):
                        footprint[i].setdefault(instr, [])

            # ── New trace within current instruction ─────────────────────────
            elif "(trace" in line:
                close_trace()           # finalise the previous trace first
                trace_is_illegal = False
                trace_has_branch = False
                in_preamble      = True
                total_traces    += 1

            # ── Preamble ends at (cycle) ─────────────────────────────────────
            elif "(cycle)" in line:
                in_preamble = False

            # ── Successful execution: a branch address was committed ─────────
            elif "branch-address" in line and not in_preamble:
                trace_has_branch = True

            # ── Illegal instruction: ESR write with EC == 0 ──────────────────
            elif any(r in line for r in ESR_REGS):
                if _is_illegal_esr(line) and not trace_is_illegal:
                    trace_is_illegal = True
                    illegal_traces  += 1
                    print("GEM ALERT GEM ALERT!!!!!!!!! GEM ALERT !!!!!!!!!!")

            # ── Register read ────────────────────────────────────────────────
            elif "read-reg" in line and "field" not in line:
                parts = line.split("|")
                if len(parts) >= 2:
                    reg = parts[1]
                    if reg in sysregs and instr:
                        fp = footprint[el][instr]
                        if reg + " Read" not in fp and reg + " Write" not in fp:
                            fp.append(reg + " Read")

            # ── Register write ───────────────────────────────────────────────
            elif "write-reg" in line and "field" not in line:
                parts = line.split("|")
                if len(parts) >= 2:
                    reg = parts[1]
                    if reg in sysregs and instr:
                        fp = footprint[el][instr]
                        if reg + " Write" not in fp:
                            read_key = reg + " Read"
                            if read_key in fp:
                                fp[fp.index(read_key)] = reg + " Write"
                            else:
                                fp.append(reg + " Write")

        commit()   # finalise the last instruction in the file


    return footprint, access



 
def write_csvs(footprint, access):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
 
    el_names    = ["EL0", "EL1", "EL2", "EL3"]
    fp_files    = [f"sysreg_footprint_per_instruction_el{i}.csv" for i in range(4)]
    access_file = os.path.join(OUTPUT_DIR, "instruction_access_per_mode.csv")
    all_instrs = sorted(
        instr
        for instr in set().union(*(fp.keys() for fp in footprint))
        if instr not in INSTR_SKIP_LIST
    )
 
    # Per-EL footprint CSVs
    for el in range(4):
        path = os.path.join(OUTPUT_DIR, fp_files[el])
        with open(path, 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(["Instruction", "Sysreg footprint"])
            for instr in all_instrs:
                w.writerow([instr] + footprint[el].get(instr, []))
 
    # Combined access CSV
    with open(access_file, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(["Instruction"] + el_names)
        for instr in all_instrs:
            row = [access[el].get(instr, "No data") for el in range(4)]
            w.writerow([instr] + row)
 
    print(f"Written {len(all_instrs)} instructions to {OUTPUT_DIR}/")
 



if __name__ == "__main__":
    sysregs           = load_sysreg_list(REGISTER_JSONpath)
    footprint, access = parse_traces(ISLA_TRACE_FILES, sysregs)
    write_csvs(footprint, access)
