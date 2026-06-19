#!/usr/bin/env python3
"""
unique_witness.py - coverage / redundancy analysis for Sailor-ARM sysreg footprints.

Consumes the per-EL footprint CSVs written by the trace parser
(sysreg_footprint_per_instruction_el{0..3}.csv) and answers the question we
agreed matters before shaving any instruction off the batch:

    "If I drop this instruction, do I orphan any system-register state, or is
     every state it touches also covered by something else?"

It produces three reports plus a console summary:

  * state_witness_index.csv  - for every (EL, state) the number of instructions
                               that witness it and the list of witnesses.
  * unique_witness_states.csv - the coverage-CRITICAL states: those with exactly
                               one witness. Dropping that one instruction creates
                               a blind spot in the security analysis.
  * instruction_status.csv   - per instruction, per EL and globally:
        MUST_KEEP            -> sole witness of >=1 state (never drop blindly)
        REDUNDANT            -> every state it touches is covered elsewhere
                                (SAFE to shave - this is your "unnecessary" set)
        NO_SYSREG_FOOTPRINT  -> touches no tracked sysreg state at all
                                (adds nothing to *this* deliverable; it may still
                                 touch GPRs/PSTATE, which this view does not track)

NOTE on scope: this only assesses instructions that were actually TRACED. An
instruction already filtered out in the Rust harness has no footprint here, so
its safety cannot be judged from this report - trace it once before deciding.

Optionally, drop a list of instruction names you are *considering* removing into
drop_candidates.txt (one per line, '#' comments allowed). The summary will then
tell you which candidates are MUST_KEEP and which states would be orphaned if all
of them were removed together (this catches the case where two instructions are
each other's only co-witness).
"""

import os
import csv
from collections import defaultdict

# Match the trace parser's output location and filenames.
FOOTPRINT_DIR = 'big_isla_traces_test'
FOOTPRINT_CSV = 'sysreg_footprint_per_instruction_el{el}.csv'
REPORT_DIR    = FOOTPRINT_DIR
EL_NAMES      = ['EL0', 'EL1', 'EL2', 'EL3']

DROP_CANDIDATES_FILE = 'drop_candidates.txt'


def load_footprints():
    """footprints[el] = { instr: set("REG Read" / "REG Write") }."""
    footprints = [dict() for _ in range(4)]
    for el in range(4):
        path = os.path.join(FOOTPRINT_DIR, FOOTPRINT_CSV.format(el=el))
        if not os.path.exists(path):
            print(f"Warning: {path} not found; EL{el} treated as empty.")
            continue
        with open(path, newline='') as fh:
            reader = csv.reader(fh)
            next(reader, None)  # header row
            for row in reader:
                if not row:
                    continue
                instr = row[0].strip()
                if not instr:
                    continue
                states = {c.strip() for c in row[1:] if c.strip()}
                footprints[el][instr] = states
    return footprints


def build_index(footprints):
    """witnesses[el][state] = set(instructions touching it at that EL)."""
    witnesses = [defaultdict(set) for _ in range(4)]
    for el in range(4):
        for instr, states in footprints[el].items():
            for st in states:
                witnesses[el][st].add(instr)
    return witnesses


def classify(footprints, witnesses):
    """status[(el, instr)] = (status_string, sorted list of solely-provided states)."""
    status = {}
    for el in range(4):
        for instr, states in footprints[el].items():
            if not states:
                status[(el, instr)] = ('NO_SYSREG_FOOTPRINT', [])
                continue
            unique = sorted(st for st in states if len(witnesses[el][st]) == 1)
            status[(el, instr)] = (('MUST_KEEP' if unique else 'REDUNDANT'), unique)
    return status


def global_status(footprints, status):
    """Roll the per-EL status up to a single verdict per instruction."""
    all_instrs = set()
    for el in range(4):
        all_instrs |= set(footprints[el].keys())
    g = {}
    for instr in all_instrs:
        per_el = [status.get((el, instr)) for el in range(4)]
        if any(s and s[0] == 'MUST_KEEP' for s in per_el):
            g[instr] = 'MUST_KEEP'
        elif any(s and s[0] == 'REDUNDANT' for s in per_el):
            g[instr] = 'REDUNDANT'
        else:
            g[instr] = 'NO_SYSREG_FOOTPRINT'
    return g, sorted(all_instrs)


def drop_impact(witnesses, drop_set):
    """States that lose ALL witnesses if every instruction in drop_set is removed."""
    orphaned = []  # (EL, state, witnesses_that_would_be_lost)
    for el in range(4):
        for st, insset in witnesses[el].items():
            if insset and not (insset - drop_set):
                orphaned.append((EL_NAMES[el], st, sorted(insset)))
    return orphaned


def write_reports(footprints, witnesses, status, g, all_instrs):
    os.makedirs(REPORT_DIR, exist_ok=True)

    # 1) Per-instruction status across ELs.
    with open(os.path.join(REPORT_DIR, 'instruction_status.csv'), 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['Instruction', 'EL0', 'EL1', 'EL2', 'EL3',
                    'Global', 'UniqueStateCount', 'UniqueStates'])
        for instr in all_instrs:
            per_el, uniq = [], set()
            for el in range(4):
                s = status.get((el, instr))
                if s is None:
                    per_el.append('-')
                else:
                    per_el.append(s[0])
                    uniq.update(f'{EL_NAMES[el]}:{u}' for u in s[1])
            w.writerow([instr] + per_el + [g[instr], len(uniq), '; '.join(sorted(uniq))])

    # 2) Coverage-critical single-witness states.
    with open(os.path.join(REPORT_DIR, 'unique_witness_states.csv'), 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['EL', 'State', 'SoleWitness'])
        for el in range(4):
            for st, insset in sorted(witnesses[el].items()):
                if len(insset) == 1:
                    w.writerow([EL_NAMES[el], st, next(iter(insset))])

    # 3) Full witness index.
    with open(os.path.join(REPORT_DIR, 'state_witness_index.csv'), 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['EL', 'State', 'WitnessCount', 'Witnesses'])
        for el in range(4):
            for st, insset in sorted(witnesses[el].items()):
                w.writerow([EL_NAMES[el], st, len(insset), '; '.join(sorted(insset))])


def main():
    footprints = load_footprints()
    witnesses  = build_index(footprints)
    status     = classify(footprints, witnesses)
    g, all_instrs = global_status(footprints, status)

    write_reports(footprints, witnesses, status, g, all_instrs)

    must  = [i for i in all_instrs if g[i] == 'MUST_KEEP']
    redun = [i for i in all_instrs if g[i] == 'REDUNDANT']
    none_ = [i for i in all_instrs if g[i] == 'NO_SYSREG_FOOTPRINT']

    print("\n=== Sailor-ARM coverage analysis ===")
    print(f"Instructions seen in footprints           : {len(all_instrs)}")
    print(f"  MUST_KEEP  (sole witness of >=1 state)  : {len(must)}")
    print(f"  REDUNDANT  (safe to shave, no state lost): {len(redun)}")
    print(f"  NO_SYSREG_FOOTPRINT (no tracked sysreg)  : {len(none_)}")

    total_unique = sum(1 for el in range(4)
                       for st, s in witnesses[el].items() if len(s) == 1)
    print(f"Coverage-critical (single-witness) states  : {total_unique}")

    if os.path.exists(DROP_CANDIDATES_FILE):
        with open(DROP_CANDIDATES_FILE) as fh:
            drop_set = {ln.strip() for ln in fh
                        if ln.strip() and not ln.lstrip().startswith('#')}
        orphaned = drop_impact(witnesses, drop_set)
        unsafe = {i for i in drop_set if g.get(i) == 'MUST_KEEP'}
        print(f"\n--- Drop-candidate impact ({len(drop_set)} candidates) ---")
        print(f"  Unsafe candidates (MUST_KEEP) : {len(unsafe)}")
        for i in sorted(unsafe):
            print(f"      {i}")
        print(f"  States orphaned if all dropped: {len(orphaned)}")
        for el, st, lost in orphaned:
            print(f"      {el:4} {st:30} (only witness: {', '.join(lost)})")

    print(f"\nReports written to {REPORT_DIR}/")


if __name__ == '__main__':
    main()
