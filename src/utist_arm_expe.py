import os
import sys
import csv
import re
import json

# ── Configuration ─────────────────────────────────────────────────────────────

REGISTER_JSON_PATH = '../AARCHMRS/Registers.json'
ISLA_TRACES_DIR    = '../arm_traces_output'
OUTPUT_DIR         = 'fig_isla_traces_test'

INSTR_SKIP_LIST = set()

ISLA_TRACE_FILES = sorted([
    os.path.basename(p)
    for p in __import__('glob').glob(os.path.join(ISLA_TRACES_DIR, 'EL*_part_*.txt'))
])

SYSREG_SKIP_EXACT = {
    'CCSIDR_EL1', 'CCSIDR2_EL1',
    'VMPIDR_EL2', 'VPIDR_EL2',
    'PSTATE',
}
SYSREG_SKIP_SUBSTRINGS = ['ALLINT', 'PM', 'S1_', 'S3_', 'SVCR']

ESR_REGS = {
    "(write-reg |ESR_EL1|",
    "(write-reg |ESR_EL2|",
    "(write-reg |ESR_EL3|",
}

# ── Sysreg loading ────────────────────────────────────────────────────────────

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

# ── Trap detection helpers ────────────────────────────────────────────────────

def _is_esr_write(line):
    """
    Any ESR write during execution signals a trap.
    We do NOT filter on EC field — any ESR write after (cycle) means
    the instruction triggered an exception handler path.
    """
    return any(r in line for r in ESR_REGS)


def _is_see_trap(line):
    """
    SEE is a Sail-internal syndrome staging register.
    SEE = -1 means 'no pending exception'.
    SEE = anything else means a syndrome was recorded.

    IMPORTANT: SEE is written on BOTH success and trap paths for some
    instructions (e.g. ERET writes SEE=203 before the EL privilege check,
    regardless of whether the check passes or fails).
    Never use this signal alone — only as a tiebreaker when no branch
    signal was observed.
    """
    if "(write-reg |SEE|" not in line:
        return False
    return "bv-1 " not in line

# ── Per-trace classification ──────────────────────────────────────────────────

def _classify(total, normal, trap, ambig):
    """
    Map trace outcome counts to an access classification string.

    Allowed     — every trace completed normally
    Conditional — mix of normal and trap/ambiguous outcomes
                  (behaviour depends on symbolic field values)
    Not allowed — every trace trapped or hit an UNDEFINED path
    Ambiguous   — all traces hit Sail UNDEFINED with no signal at all
                  (likely wrong encoding or missing config)
    No traces   — isla produced no output for this instruction
    """
    if total == 0:
        return "No traces"

    if ambig == total:
        # Every path returned with zero post-cycle events.
        # This is the Sail UNDEFINED fingerprint, not a real trap signal.
        return "Ambiguous"

    effective_trap = trap + ambig

    if effective_trap == 0:
        return "Allowed"
    if normal == 0:
        return "Not allowed"
    return "Conditional"

# ── Main parser ───────────────────────────────────────────────────────────────

def parse_traces(trace_files, sysregs):
    """
    Parse isla trace files and return:

        footprint[el][instr]  = list of "REG Read" / "REG Write" strings
        access[el][instr]     = classification string (see _classify)

    Terminal signal priority (evaluated per trace, post-cycle events only):

        1. write-reg |Branchtypetaken|   → normal
           The Sail model writes this register on every architectural branch,
           including ERET success, before the branch-address event.
           This is the most reliable success signal.

        2. branch-address event          → normal
           PC update committed. Catches all other non-exception branches.

        3. ESR write (any EL)            → trap
           Exception syndrome written — instruction caused a synchronous
           exception. EC field is not checked; any ESR write counts.

        4. SEE write (value != -1) with  → trap
           no branch signal observed
           SEE is written on both success and trap paths for some instructions
           (confirmed for ERET). Only used as tiebreaker.

        5. Zero post-cycle events        → ambiguous
           Exactly one event (PC read) then silence. This is the Sail
           UNDEFINED return fingerprint. Counts separately from traps.

        6. Post-cycle events but no      → trap (conservative)
           conclusive terminal signal
    """
    footprint = [{}, {}, {}, {}]
    access    = [{}, {}, {}, {}]

    for filename in trace_files:
        # ── Determine EL from filename ────────────────────────────────────────
        el = next(
            (i for i, tok in enumerate(["el0", "el1", "el2", "el3"])
             if tok in filename.lower()),
            -1,
        )
        if el == -1:
            sys.exit(
                f"Error: could not determine EL from filename '{filename}'.\n"
                f"Expected filename to contain 'el0', 'el1', 'el2', or 'el3'."
            )

        filepath = os.path.join(ISLA_TRACES_DIR, filename)
        print(f"Parsing: {filepath}")
        with open(filepath) as f:
            lines = f.readlines()

        # ── Per-instruction accumulators ──────────────────────────────────────
        instr         = ""
        total_traces  = 0
        normal_traces = 0
        trap_traces   = 0
        ambig_traces  = 0

        # ── Per-trace state ───────────────────────────────────────────────────
        past_cycle        = False
        has_branch        = False  # Branchtypetaken or branch-address post-cycle
        has_esr           = False  # ESR write post-cycle
        has_see_trap      = False  # SEE written to non-(-1) post-cycle
        post_cycle_events = 0      # count of any line seen after (cycle)

        # ── close_trace: finalise one symbolic execution path ─────────────────
        def close_trace():
            nonlocal normal_traces, trap_traces, ambig_traces
            nonlocal has_branch, has_esr, has_see_trap
            nonlocal past_cycle, post_cycle_events

            if total_traces == 0:
                return  # nothing opened yet

            if has_branch:
                # branch-address or Branchtypetaken — instruction completed
                normal_traces += 1

            elif has_esr:
                # ESR written, no branch — synchronous exception taken
                trap_traces += 1

            elif has_see_trap:
                # SEE staged a syndrome but no branch followed — trap path
                trap_traces += 1

            elif post_cycle_events <= 1:
                # Only a PC read (or nothing) after cycle — Sail UNDEFINED path.
                # post_cycle_events == 1 covers the single (read-reg |_PC| ...)
                # line that appears in the UNDEFINED fingerprint.
                ambig_traces += 1

            else:
                # Post-cycle events present but no conclusive terminal signal.
                # Conservative: treat as trap.
                trap_traces += 1

            # Reset per-trace flags
            has_branch        = False
            has_esr           = False
            has_see_trap      = False
            past_cycle        = False
            post_cycle_events = 0

        # ── commit: finalise instruction block and write classification ────────
        def commit():
            nonlocal instr, total_traces, normal_traces, trap_traces, ambig_traces

            close_trace()

            if instr:
                total = normal_traces + trap_traces + ambig_traces
                classification = _classify(
                    total, normal_traces, trap_traces, ambig_traces
                )
                access[el][instr] = classification
                print(
                    f"  [{filename}] {instr:40s} "
                    f"total={total:3d}  normal={normal_traces:3d}  "
                    f"trap={trap_traces:3d}  ambig={ambig_traces:3d}  "
                    f"→ {classification}"
                )

            total_traces  = 0
            normal_traces = 0
            trap_traces   = 0
            ambig_traces  = 0

        # ── Main line loop ────────────────────────────────────────────────────
        for line in lines:

            # ── New instruction block ─────────────────────────────────────────
            # Format: "--- Instruction: NAME | Mode: ELx ---"
            if "--- Instruction:" in line:
                commit()
                instr = line.split(":")[1].split("|")[0].strip()
                for i in range(4):
                    footprint[i].setdefault(instr, [])

            # ── New trace within current instruction ──────────────────────────
            elif "(trace" in line:
                close_trace()
                total_traces += 1
                past_cycle    = False

            # ── Preamble ends — real execution begins ─────────────────────────
            elif "(cycle)" in line:
                past_cycle        = True
                post_cycle_events = 0

            # ── All signals below are only meaningful post-cycle ──────────────
            elif past_cycle:
                post_cycle_events += 1

                # ── Signal 1: Branchtypetaken written ────────────────────────
                # Sail model writes this on every architectural branch before
                # the branch-address event. Covers ERET success, B, BL, RET, etc.
                if "(write-reg |Branchtypetaken|" in line:
                    has_branch = True

                # ── Signal 2: branch-address event ───────────────────────────
                elif "branch-address" in line:
                    has_branch = True

                # ── Signal 3: ESR write → trap ────────────────────────────────
                elif _is_esr_write(line):
                    has_esr = True

                # ── Signal 4: SEE staging → potential trap ────────────────────
                # Only used as tiebreaker; see docstring above.
                elif _is_see_trap(line):
                    has_see_trap = True

                # ── Footprint: whole-register reads ──────────────────────────
                # Skip field accesses — we only want architectural sysreg reads.
                elif "read-reg" in line and "field" not in line:
                    parts = line.split("|")
                    if len(parts) >= 2:
                        reg = parts[1]
                        if reg in sysregs and instr:
                            fp = footprint[el][instr]
                            if reg + " Read" not in fp and reg + " Write" not in fp:
                                fp.append(reg + " Read")

                # ── Footprint: whole-register writes ─────────────────────────
                # Upgrade Read → Write if we later see a write to the same reg.
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

        # Finalise the last instruction block in the file
        commit()

    return footprint, access

# ── CSV output ────────────────────────────────────────────────────────────────

def write_csvs(footprint, access):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    el_names = ["EL0", "EL1", "EL2", "EL3"]

    fp_files = [
        f"sysreg_footprint_per_instruction_el{i}.csv" for i in range(4)
    ]
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
        print(f"Written {path}")

    # Combined access CSV (one row per instruction, one column per EL)
    with open(access_file, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(["Instruction"] + el_names)
        for instr in all_instrs:
            row = [access[el].get(instr, "No data") for el in range(4)]
            w.writerow([instr] + row)
    print(f"Written {access_file}")

    print(f"\nDone — {len(all_instrs)} instructions across {OUTPUT_DIR}/")

    # Quick sanity summary
    print("\n── Access classification summary ──────────────────────────────")
    for el in range(4):
        counts = {}
        for instr in all_instrs:
            c = access[el].get(instr, "No data")
            counts[c] = counts.get(c, 0) + 1
        print(f"  {el_names[el]}: " +
              "  ".join(f"{k}={v}" for k, v in sorted(counts.items())))

# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not ISLA_TRACE_FILES:
        sys.exit(
            f"Error: no trace files found in '{ISLA_TRACES_DIR}'.\n"
            f"Expected files matching EL*_part_*.txt"
        )

    print(f"Found {len(ISLA_TRACE_FILES)} trace files:")
    for f in ISLA_TRACE_FILES:
        print(f"  {f}")
    print()

    sysregs           = load_sysreg_list(REGISTER_JSON_PATH)
    footprint, access = parse_traces(ISLA_TRACE_FILES, sysregs)
    write_csvs(footprint, access)
