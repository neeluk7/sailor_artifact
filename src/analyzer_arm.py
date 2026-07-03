#!/usr/bin/env python3
# ------------------------------------------------------------------------- #
# Sailor-ARM context-switch security analyzer (AArch64 / EL0..EL3)
#
# --------------------------------------------------
# Inputs (all from --in directory, default "."):
#     instruction_access_per_mode.csv
#         header: Instruction,EL0,EL1,EL2,EL3
#     sysreg_footprint_per_instruction_el{0,1,2,3}.csv
#         header: Instruction,Sysreg footprint
#         rows  : <instr>,<REG Read|REG Write>,<...>
#
# Output (to --out directory): one switch-from-EL{s}-to-EL{t}.csv per ordered
# EL pair requested, plus an optional *-detail.csv naming the channel for each
# sensitive register.
# ------------------------------------------------------------------------- #

import argparse
import csv
import os
import sys

EL_NAMES = ["EL0", "EL1", "EL2", "EL3"]
MRS_PREFIX = "MRS_RS_systemmove@"
MSR_PREFIX = "MSR_SR_systemmove@"


def accessible(value):
    """An access-table cell counts as 'this runs / is reachable' iff it is
    Allowed or Conditional. 'Not allowed (undefined)', 'Not allowed
    (exception)' and 'No data' all count as not-accessible."""
    v = (value or "").strip()
    return v.startswith("Allowed") or v.startswith("Conditional")


# --------------------------------------------------------------------------- #
# Loaders
# --------------------------------------------------------------------------- #
def load_access(path):
    """instruction_access_per_mode.csv -> {instr: [EL0, EL1, EL2, EL3]}"""
    table = {}
    with open(path, newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            key = row[0].strip()
            if key == "" or key == "Instruction":
                continue
            cells = [c.strip() for c in row[1:5]]
            while len(cells) < 4:
                cells.append("No data")
            table[key] = cells
    return table


def load_footprint(path):
    """sysreg_footprint_per_instruction_elN.csv
       -> {instr: set((REG, 'Read'|'Write'))}.
       Missing file -> empty dict (handled by caller with a warning)."""
    fp = {}
    if not os.path.exists(path):
        return fp
    with open(path, newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            key = row[0].strip()
            if key == "" or key == "Instruction":
                continue
            entries = set()
            for tok in row[1:]:
                tok = tok.strip()
                if not tok:
                    continue
                parts = tok.rsplit(" ", 1)
                if len(parts) == 2 and parts[1] in ("Read", "Write"):
                    entries.add((parts[0].strip(), parts[1]))
                else:
                    # unannotated reg as a read
                    entries.add((tok, "Read"))
            fp.setdefault(key, set()).update(entries)
    return fp


def derive_direct_access(access_table):
    """Returns (read_access, write_access) where each is
       [el_index] -> {reg: cell_string}."""
    read_access = [dict() for _ in EL_NAMES]
    write_access = [dict() for _ in EL_NAMES]
    for instr, cells in access_table.items():
        if instr.startswith(MRS_PREFIX):
            reg = instr[len(MRS_PREFIX):]
            for el in range(4):
                read_access[el][reg] = cells[el]
        elif instr.startswith(MSR_PREFIX):
            reg = instr[len(MSR_PREFIX):]
            for el in range(4):
                write_access[el][reg] = cells[el]
    return read_access, write_access


def collect_sysregs(footprints, read_access, write_access, extra=None, banned=None):
    """Universe of registers to analyze: everything that appears in any
    footprint, plus everything covered by the MRS/MSR sweep, plus any names
    from an optional config file -- minus anything on the ban list."""
    regs = set()
    for fp in footprints:
        for entries in fp.values():
            for (reg, _rw) in entries:
                regs.add(reg)
    for el in range(4):
        regs.update(read_access[el].keys())
        regs.update(write_access[el].keys())
    if extra:
        regs.update(extra)
    if banned:
        regs.difference_update(banned)
    return sorted(regs)


def source_affects(reg, s, access_table, footprints, write_access):
    """Source EL can change REG: directly (MSR REG runs at s) or indirectly
    (some instruction runnable at s writes REG as a side effect)."""
    if accessible(write_access[s].get(reg, "No data")):
        return True, "direct-write (MSR runs at %s)" % EL_NAMES[s]
    for instr, entries in footprints[s].items():
        if (reg, "Write") in entries and accessible(
            access_table.get(instr, ["No data"] * 4)[s]
        ):
            return True, "indirect-write via %s" % instr
    return False, None


def source_depends(reg, s, access_table, footprints, read_access):
    """Source EL execution is influenced by REG: directly (MRS REG runs at s)
    or indirectly (some instruction runnable at s reads REG)."""
    if accessible(read_access[s].get(reg, "No data")):
        return True, "direct-read (MRS runs at %s)" % EL_NAMES[s]
    for instr, entries in footprints[s].items():
        if (reg, "Read") in entries and accessible(
            access_table.get(instr, ["No data"] * 4)[s]
        ):
            return True, "indirect-read via %s" % instr
    return False, None


def target_observes(reg, t, access_table, footprints, read_access):
    """Target EL can observe REG: directly (MRS REG runs at t) or indirectly
    (some instruction runnable at t reads REG in the target's own footprint).
    NOTE: the RISC-V original checked the SOURCE footprint here; that is a bug
    -- per-EL footprints differ -- so we use the target's footprint."""
    if accessible(read_access[t].get(reg, "No data")):
        return True, "direct-read (MRS runs at %s)" % EL_NAMES[t]
    for instr, entries in footprints[t].items():
        if (reg, "Read") in entries and accessible(
            access_table.get(instr, ["No data"] * 4)[t]
        ):
            return True, "indirect-read via %s" % instr
    return False, None


def analyze_switch(s, t, sysregs, access_table, footprints,
                   read_access, write_access, strict=False):
    """Returns (sensitive, not_sensitive, detail).
       sensitive/not_sensitive are lists of register names.
       detail maps reg -> (source_reason, target_reason).

       There is no longer an "unknown"/"unprobed" bucket. A register the
       source can change (measured: direct MSR, or an instruction at the
       source writes it) is now classified SENSITIVE by default whenever the
       target's ability to read it was never measured (the register is
       absent from the MRS/MSR sweep AND read by no instruction in the
       target's footprint) -- this is exactly the old DISR_EL1 / MDCCSR_EL0
       case (written indirectly by ESB at EL0, but never swept, so we cannot
       prove EL1 can't read it). Rather than surface that as a separate
       coverage-gap column, we now fail SAFE: an unprobed target read is
       treated as a positive read, and the register is reported sensitive.
       Only a register whose target read-access WAS actually measured (it's
       in the sweep, or read by some target-side instruction) and measured
       negative is reported not_sensitive. The definitive fix for a register
       that lands here via the unprobed path is still to add it to the
       sweep -- see the "UNPROBED" note baked into its detail entry."""
    sensitive, not_sensitive, detail = [], [], {}
    for reg in sysregs:
        aff, aff_why = source_affects(reg, s, access_table, footprints, write_access)
        dep, dep_why = source_depends(reg, s, access_table, footprints, read_access)

        # strict: a genuine source->target leak needs the source to be able to
        # SET the register; read-only-by-both registers (e.g. SCR_EL3 consulted
        # by every load's trap check) are fixed constants, not channels.
        trigger = aff if strict else (aff or dep)
        if not trigger:
            not_sensitive.append(reg)
            continue

        obs, obs_why = target_observes(reg, t, access_table, footprints, read_access)
        if obs:
            sensitive.append(reg)
            detail[reg] = (aff_why or dep_why, obs_why)
        elif reg not in read_access[t]:
            # Source can change it, target never observed reading it, AND the
            # target's direct read-access was never probed (reg not in the
            # sweep) -> fail-safe: treat as sensitive rather than silently
            # calling it safe.
            sensitive.append(reg)
            detail[reg] = (aff_why or dep_why,
                           "UNPROBED: %s not in MRS sweep and no instruction "
                           "reads it at %s -- treated as sensitive (fail-safe)"
                           % (reg, EL_NAMES[t]))
        else:
            # Target read-access WAS measured (reg is in the sweep) and is not
            # accessible, and nothing reads it indirectly -> measured safe.
            not_sensitive.append(reg)
    return sensitive, not_sensitive, detail


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def write_pair_csv(out_dir, s, t, sensitive, not_sensitive, detail, detailed):
    base = "switch-from-%s-to-%s" % (EL_NAMES[s], EL_NAMES[t])
    path = os.path.join(out_dir, base + ".csv")

    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Security Sensitive", "Not Security Sensitive"])
        for i in range(max(len(sensitive), len(not_sensitive))):
            w.writerow([
                sensitive[i] if i < len(sensitive) else "",
                not_sensitive[i] if i < len(not_sensitive) else "",
            ])

    if detailed:
        dpath = os.path.join(out_dir, base + "-detail.csv")
        with open(dpath, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Sysreg", "Why source affects/depends", "How target observes"])
            for reg in sensitive:
                src_why, tgt_why = detail[reg]
                w.writerow([reg, src_why, tgt_why])
    return path


def main():
    ap = argparse.ArgumentParser(
        description="ARM (AArch64) context-switch security analyzer.")
    ap.add_argument("--in", dest="indir", default="../results",
                    help="directory holding the Sailor-ARM CSVs (default .)")
    ap.add_argument("--out", dest="outdir", default=None,
                    help="output directory (default = --in)")
    ap.add_argument("--source", default=None,
                    help="source EL (EL0..EL3). Omit to sweep all ordered pairs.")
    ap.add_argument("--target", default=None,
                    help="target EL (EL0..EL3). Omit to sweep all ordered pairs.")
    ap.add_argument("--strict", dest="strict", action="store_true", default=False,
                    help="OPT-IN narrower view: a register counts only if the "
                         "SOURCE EL can WRITE it (direct MSR, or an instruction at "
                         "the source whose footprint writes it) -- i.e. drop the "
                         "Source_Dependent term. This removes read-only-by-both "
                         "'constants' (e.g. SCR_EL3 / trap-check registers) but it "
                         "ALSO removes legitimately context-bound registers the "
                         "source only reads, such as TTBR0_EL1 for an EL0->EL0 "
                         "switch. NOT the default.")
    ap.add_argument("--faithful", dest="strict", action="store_false",
                    help="(default) implement the full sensitivity rule: "
                         "(Source_Direct_Write OR Source_Indirect_Write OR "
                         "Source_Dependent) AND (Target_Dependent OR "
                         "Target_Direct_Read). The Source_Dependent term is what "
                         "flags registers the source only READS (e.g. every EL0 "
                         "load reads TTBR0_EL1 during translation), so TTBR0_EL1 is "
                         "correctly sensitive for EL0->EL0. Applied uniformly, "
                         "including same-EL switches.")
    ap.add_argument("--sysreg-list", default=None,
                    help="optional file of extra register names to force into "
                         "the universe (one per line, '#' comments ok).")
    ap.add_argument("--sysreg-ban-list", default=None,
                    help="optional file of register names to force OUT of the "
                         "universe -- these are dropped from `sysregs` entirely "
                         "before analysis and so never appear in either "
                         "'Security Sensitive' or 'Not Security Sensitive' "
                         "(one per line, '#' comments ok). Applied after "
                         "--sysreg-list, so a name in both files is banned.")
    ap.add_argument("--detail", action="store_true",
                    help="also emit *-detail.csv naming the channel per sysreg.")
    args = ap.parse_args()

    indir = args.indir
    outdir = args.outdir or indir
    os.makedirs(outdir, exist_ok=True)

    access_path = os.path.join(indir, "instruction_access_per_mode.csv")
    if not os.path.exists(access_path):
        sys.exit("ERROR: %s not found" % access_path)
    access_table = load_access(access_path)

    footprints = []
    for el in range(4):
        fp_path = os.path.join(
            indir, "sysreg_footprint_per_instruction_el%d.csv" % el)
        fp = load_footprint(fp_path)
        if not fp:
            print("WARNING: no footprint data for %s (%s missing/empty) -- "
                  "indirect channels at %s cannot be detected."
                  % (EL_NAMES[el], os.path.basename(fp_path), EL_NAMES[el]))
        footprints.append(fp)

    for el in range(4):
        nod = sum(1 for c in access_table.values() if c[el].strip() == "No data")
        if nod:
            print("NOTE: %s has %d 'No data' cells in the access table -- that "
                  "EL pass looks incomplete; its results will be under-counted."
                  % (EL_NAMES[el], nod))

    read_access, write_access = derive_direct_access(access_table)

    extra = None
    if args.sysreg_list and os.path.exists(args.sysreg_list):
        with open(args.sysreg_list) as f:
            extra = [l.strip() for l in f
                     if l.strip() and not l.strip().startswith("#")]

    banned = None
    if args.sysreg_ban_list and os.path.exists(args.sysreg_ban_list):
        with open(args.sysreg_ban_list) as f:
            banned = {l.strip() for l in f
                      if l.strip() and not l.strip().startswith("#")}

    sysregs = collect_sysregs(footprints, read_access, write_access, extra, banned)
    print("Analyzing %d candidate system registers across %s.%s\n"
          % (len(sysregs), ", ".join(EL_NAMES),
             ("  (%d banned via --sysreg-ban-list)" % len(banned)) if banned else ""))

    if args.source and args.target:
        pairs = [(EL_NAMES.index(args.source), EL_NAMES.index(args.target))]
    else:
        pairs = [(s, t) for s in range(4) for t in range(4)]

    for (s, t) in pairs:
        # The full rule (Source_Write OR Source_Dependent) AND (Target_Read OR
        # Target_Dependent) is applied UNIFORMLY, including same-EL switches.
        # For s == t the Source_Dependent term is essential, not degenerate: it
        # is what makes context-bound state the EL only READS -- e.g. TTBR0_EL1,
        # which every EL0 load reads during translation -- sensitive for an
        # EL0->EL0 switch (two EL0 contexts whose page tables differ). --strict
        # drops that term and is left to the caller as an explicit narrower view.
        pair_strict = args.strict
        sensitive, not_sensitive, detail = analyze_switch(
            s, t, sysregs, access_table, footprints,
            read_access, write_access, strict=pair_strict)
        path = write_pair_csv(outdir, s, t, sensitive, not_sensitive,
                              detail, args.detail)
        print("%s -> %s : %d sensitive, %d not  (%s)"
              % (EL_NAMES[s], EL_NAMES[t], len(sensitive),
                 len(not_sensitive), os.path.basename(path)))
        if args.source and args.target:
            print("\n  Security-sensitive:")
            for reg in sensitive:
                src_why, tgt_why = detail[reg]
                print("    %-22s  [source: %s] [target: %s]"
                      % (reg, src_why, tgt_why))


if __name__ == "__main__":
    main()
