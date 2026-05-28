import os; 
import sys; 
import csv;
import re;
import json;


REGISTER_JSONpath =  '../AARCHMRS/Registers.json'
ISLA_TRACES_DIR = '../isla_traces_arm'
OUTPUT_DIR = '../isla_traces_arm'


INSTR_SKIP_LIST = set()


ISLA_TRACE_FILES =  [
   "el0_eret_simplified_trace.txt",
   "el1_eret_simplified_trace.txt",
   "el3_eret_simplified_trace.txt",
   ]


SYSREG_SKIP_EXACT = {
    'CCSIDR_EL1', 'CCSIDR2_EL1',
    'VMPIDR_EL2', 'VPIDR_EL2',
    'PSTATE',
}
SYSREG_SKIP_SUBSTRINGS = ['ALLINT', 'PM', 'S1_', 'S3_', 'SVCR']

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


EL_TOKENS = {"#b00": 0, "#b01": 1, "#b10": 2, "#b11": 3}
ESR_REGS  = {"(write-reg |ESR_EL1|", "(write-reg |ESR_EL2|", "(write-reg |ESR_EL3|"}



def parse_traces(trace_files, sysregs):
    footprint = [{}, {}, {}, {}]
    access    = [{}, {}, {}, {}]

    for filename in trace_files:
        # Derive EL directly from filename instead of scanning for
        # "(assume-reg |PSTATE| ((_ field |EL|))" inside every trace block.
        el = next((i for i, tok in enumerate(["el0","el1","el2","el3"])
                   if tok in filename.lower()), -1)
        if el == -1:
            sys.exit(f"Error: could not determine EL from filename '{filename}'.")

        filepath = os.path.join(ISLA_TRACES_DIR, filename)
        with open(filepath) as f:
            lines = f.readlines()

        instr          = ""
        total_traces   = 0
        illegal_traces = 0

        def commit():
            if instr:
                access[el][instr] = classify(total_traces, illegal_traces)

        for line in lines:

            if "INSTRUCTION CONSTRUCTED:" in line:
                commit()
                total_traces   = 0
                illegal_traces = 0
                instr = line.split(":")[1].strip()
                for i in range(4):
                    footprint[i].setdefault(instr, [])

            elif any(r in line for r in ESR_REGS):
                m = re.search(r'#x([0-9a-fA-F]+)', line)
                if m and ((int(m.group(1), 16) >> 26) & 0x3F) == 0:
                    illegal_traces += 1

            elif "read-reg" in line and "field" not in line:
                parts = line.split("|")
                if len(parts) >= 2:
                    reg = parts[1]
                    if reg in sysregs and instr:
                        fp = footprint[el][instr]
                        if reg + " Read" not in fp and reg + " Write" not in fp:
                            fp.append(reg + " Read")

            elif "write-reg" in line and "field" not in line:
                parts = line.split("|")
                if len(parts) >= 2:
                    reg = parts[1]
                    if reg in sysregs and instr:
                        fp = footprint[el][instr]
                        if reg + " Write" not in fp:
                            fp.append(reg + " Write")

            elif "(cycle)" in line or line.strip().startswith("(trace"):
                total_traces += 1

        commit()

    return footprint, access


def parse_tracesbis(trace_files, sysregs):
    """
    Returns:
        footprint[el][instr] = list of "REG Read" / "REG Write" strings
        access[el][instr]    = "Allowed" | "Conditional" | "Not allowed" |
                               "No traces" | "Undetermined"
    """
    footprint = [{}, {}, {}, {}] 
    access    = [{}, {}, {}, {}]

    for filename in trace_files:
        filepath = os.path.join(ISLA_TRACES_DIR, filename)
        with open(filepath) as f:
            lines = f.readlines()

        el              = -1
        instr           = ""
        total_traces    = 0
        illegal_traces  = 0

        def finalise():
            if el == -1 or not instr:
                return
            if total_traces == 0:
                access[el][instr] = "No traces"
            elif illegal_traces == 0:
                access[el][instr] = "Allowed"
            elif illegal_traces < total_traces:
                access[el][instr] = "Conditional"
            elif illegal_traces == total_traces:
                access[el][instr] = "Not allowed"
            else:
                access[el][instr] = "Undetermined"

        for line in lines:

            # -- Privilege level ------------------------------------------
            if "(assume-reg |PSTATE| ((_ field |EL|))" in line:
                el = {"#b00": 0, "#b01": 1, "#b10": 2, "#b11": 3}.get(
                    next((t for t in ["#b00","#b01","#b10","#b11"] if t in line), ""), -1
                )

            # -- New instruction -------------------------------------------
            elif "INSTRUCTION CONSTRUCTED:" in line:
                finalise()
                total_traces   = 0
                illegal_traces = 0
                instr = line.split(":")[1].strip()
                for i in range(4):
                    footprint[i].setdefault(instr, [])

            # -- Illegal instruction (ESR write with EC=0) -----------------
            elif any(r in line for r in
                     ["(write-reg |ESR_EL1|",
                      "(write-reg |ESR_EL2|",
                      "(write-reg |ESR_EL3|"]):
                m = re.search(r'#x([0-9a-fA-F]+)', line)
                if m and ((int(m.group(1), 16) >> 26) & 0x3F) == 0:
                    illegal_traces += 1

            # -- Register read --------------------------------------------
            elif "read-reg" in line and "field" not in line:
                parts = line.split("|")
                if len(parts) >= 2:
                    reg = parts[1]
                    if reg in sysregs and instr and el != -1:
                        fp = footprint[el][instr]
                        if reg + " Read" not in fp and reg + " Write" not in fp:
                            fp.append(reg + " Read")

            # -- Register write -------------------------------------------
            elif "write-reg" in line and "field" not in line:
                parts = line.split("|")
                if len(parts) >= 2:
                    reg = parts[1]
                    if reg in sysregs and instr and el != -1:
                        fp = footprint[el][instr]
                        if reg + " Write" not in fp:
                            fp.append(reg + " Write")

            # -- Trace counter --------------------------------------------
            elif "trace" in line:
                total_traces += 1

        finalise()

    return footprint, access

def write_csvs(footprint, access):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    el_names   = ["EL0", "EL1", "EL2", "EL3"]
    fp_files   = [f"sysreg_footprint_per_instruction_el{i}.csv" for i in range(4)]
    access_file = os.path.join(OUTPUT_DIR, "instruction_access_per_mode.csv")

    # Collect instructions that have access data for all four ELs
    all_instrs = sorted(
        instr for instr in footprint[0]
        if instr not in INSTR_SKIP_LIST
        and all(instr in access[el] for el in range(4))
    )

    # Per-EL footprint CSVs
    for el in range(4):
        with open(os.path.join(OUTPUT_DIR, fp_files[el]), 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(["Instruction", "Sysreg footprint"])
            for instr in all_instrs:
                w.writerow([instr] + footprint[el][instr])

    # Combined access CSV
    with open(access_file, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(["Instruction"] + el_names)
        for instr in all_instrs:
            w.writerow([instr] + [access[el][instr] for el in range(4)])

    print(f"Written {len(all_instrs)} instructions to {OUTPUT_DIR}/")



if __name__ == "__main__":
    sysregs          = load_sysreg_list(REGISTER_JSONpath)
    footprint, access = parse_traces(ISLA_TRACE_FILES, sysregs)
    write_csvs(footprint, access)
