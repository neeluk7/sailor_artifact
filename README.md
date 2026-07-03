# Sailor: Automated ISA-Inspection and Test-Generation for Secure Context Switching

## Arm (AArch64)

This is the Arm port of Sailor, extending the original RISC-V tool to the Arm A-profile
architecture (EL0-EL3). It uses Isla to symbolically execute the Sail Arm model over every
instruction, parses the resulting traces into per-instruction register footprints, and
classifies which system registers are security-sensitive for a given Exception-Level
context switch.

## IBM ACE RISC-V

This project is a part of IBM's [ACE RISC-V](https://github.com/IBM/ACE-RISCV) Confidential
Computing Project. The work here extends the original RISC-V tooling to Arm.

Directory Structure
-------------------
- isla                      // Isla symbolic execution tool for Sail, extended with a batch
                                mode (`isla-footprint`) that sweeps every Arm instruction
                                across all four Exception Levels
  - configs                 // Isla TOML configs, e.g. `armv9p4_mmu_on.toml`
- sail-arm                  // Sail Arm model, compiled into the `.ir` archive Isla loads
- configs                   // Compiled Sail Arm IR (`armv9p4.ir`)
- AARCHMRS                  // Arm's machine-readable architecture spec: `Registers.json`
                                (the system-register catalogue) and `Instructions.json`
                                (the instruction-encoding blueprints, batch input to
                                `isla-footprint -n`)
- src                        // Python scripts
  - parse_arm.py            // ISA Inspector: parses raw Isla traces into per-instruction,
                                per-EL register footprints and access tables
  - analyzer_arm.py         // Analyzer: implements the classifier algorithm and produces
                                one `switch-from-EL{s}-to-EL{t}.csv` per ordered EL pair
- scripts
  - run_sailor_arm.sh       // Runs the full pipeline end-to-end: trace generation, parsing,
                                and analysis
- arm_traces_output         // Raw Isla traces (`EL{0..3}_part_NNNN.txt`), written here by
                                `isla-footprint` (hardcoded output directory)
- sailor_artifacts/results  // Default output location for both `parse_arm.py` and
                                `analyzer_arm.py` (footprint/access CSVs in, sensitivity
                                CSVs out)
- patches
  - isla-patch               // Patch applied to Isla (in the `isla` dir)

Getting started
---------------
## Setup dependencies
Same toolchain as the RISC-V build (Rust for Isla, opam/OCaml for Sail), plus the Arm Sail
model and the AARCHMRS JSON exports. See `make setup-dependencies` and the `scripts/`
directory for the individual build steps.

## Building isla-footprint
```
make setup-isla
```
This builds the extended Isla tool, including the `isla-footprint` batch binary at
`isla/target/release/isla-footprint`.

## Generating traces
`isla-footprint` sweeps every instruction in `AARCHMRS/Instructions.json` across all four
Exception Levels in a single run. The exact command:

```
isla/target/release/isla-footprint \
  -A configs/armv9p4.ir \
  -C isla/configs/armv9p4_mmu_on.toml \
  -i "passcheck" \
  -n AARCHMRS/Instructions.json \
  --timeout 30 \
  -T 2 \
  -s \
  --high-va-probe \
  --armv8-page-tables "identity 0x600000;"
```

- `-A` / `-C` — the compiled Sail Arm IR and the Isla TOML config (stage-1 MMU on, minimal
  register pins -- see the project report for what's pinned and why).
- `-n` — batch mode: process every instruction listed in the given JSON file.
- `--timeout` — per-instruction Isla/solver timeout, in seconds.
- `-T` — worker thread count.
- `-s` — simplify each instruction's footprint.
- `--high-va-probe` — extra pass per memory instruction with GPRs/SPs pinned into the
  TTBR1 region, so the high-half walk (and `TTBR1_ELx`) also shows up in the footprint.
- `--armv8-page-tables` — sets up the stage-1 identity-mapped page tables the walk needs.

Run `isla/target/release/isla-footprint --help` for the full flag reference.

Traces land in `arm_traces_output/EL{0..3}_part_NNNN.txt` (this directory name is
hardcoded in the tool, not configurable via a flag).

## Running Sailor
```
python3 src/parse_arm.py
python3 src/analyzer_arm.py
```
`parse_arm.py` reads from `arm_traces_output/` and writes the parsed footprint/access CSVs
to `sailor_artifacts/results/` by default. `analyzer_arm.py` reads from and writes to
`sailor_artifacts/results/` by default too, producing one
`switch-from-EL{s}-to-EL{t}.csv` per ordered EL pair (16 files total; pass `--source`/
`--target` to restrict to a single pair, or `--detail` to also emit the per-register
channel breakdown).

Both scripts' input/output locations can be overridden -- `parse_arm.py` via the
`SAILOR_TRACES_DIR` / `SAILOR_OUTPUT_DIR` / `SAILOR_REGISTERS_JSON` environment variables,
`analyzer_arm.py` via `--in` / `--out`.

## Running everything at once
`scripts/run_sailor_arm.sh` runs the full pipeline -- trace generation, parsing, and
analysis -- in one call:
```
./scripts/run_sailor_arm.sh
```
See the script header for options (thread count, timeout, skipping trace generation if
`arm_traces_output/` is already populated, etc.).

# License
This repository is distributed under the terms of the Apache 2.0 License, see
[LICENSE](LICENSE).
