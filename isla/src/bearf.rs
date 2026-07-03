// BSD 2-Clause License
//
// Copyright (c) 2020 Alasdair Armstrong
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use crossbeam::queue::SegQueue;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::process::exit;
use std::sync::Arc;
use std::time::Instant;

use isla_axiomatic::footprint_analysis::footprint_analysis;
use isla_axiomatic::litmus::assemble_instruction;
use isla_axiomatic::page_table;
use isla_axiomatic::page_table::setup::PageTableSetup;
use isla_elf::arch::AArch64;
use isla_elf::elf;
use isla_elf::relocation_types::SymbolicRelocation;
use isla_lib::bitvector::{b129::B129, BV};
use isla_lib::error::IslaError;
use isla_lib::executor;
use isla_lib::executor::{LocalFrame, StopAction, StopConditions, TaskId, TaskState};
use isla_lib::init::{initialize_architecture, InitArchWithConfig};
use isla_lib::ir::*;
use isla_lib::log;
use isla_lib::memory::Memory;
use isla_lib::register::Register;
use isla_lib::simplify;
use isla_lib::simplify::{EventTree, WriteOpts};
use isla_lib::smt;
use isla_lib::smt::{smtlib, Checkpoint, EvPath, Event, Solver};
use isla_lib::smt_parser;
use isla_lib::source_loc::SourceLoc;
use isla_lib::zencode;

mod opts;
use opts::CommonOpts;

use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Instructions { pub instructions: Vec<InstructionSet>, pub _meta: Meta }
#[derive(Debug, Deserialize, Clone)]
pub struct Meta { pub license: License }
#[derive(Debug, Deserialize, Clone)]
pub struct License { pub copyright: String, pub info: String }
#[derive(Debug, Deserialize, Clone)]
pub struct InstructionSet { pub children: Vec<InstructionGroupOrInstruction>, pub encoding: Encodeset, pub name: String }
#[derive(Debug, Deserialize, Clone)]
pub struct InstructionGroup { pub children: Vec<InstructionGroupOrInstruction>, pub encoding: Encodeset, pub name: String }
#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "_type")]
pub enum InstructionGroupOrInstruction {
    #[serde(rename = "Instruction.InstructionGroup")] InstructionGroup(InstructionGroup),
    #[serde(rename = "Instruction.Instruction")] Instruction(Instruction),
    #[serde(rename = "Instruction.InstructionAlias")] InstructionAlias(InstructionAlias),
}
#[derive(Debug, Deserialize, Clone)]
pub struct Encodeset { pub values: Vec<Encode> }
#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "_type")]
pub enum Encode {
    #[serde(rename = "Instruction.Encodeset.Field")] Field(Field),
    #[serde(rename = "Instruction.Encodeset.Bits")] Bits(Bits),
}
#[derive(Debug, Deserialize, Clone)]
pub struct Field { pub name: String, pub range: Range, pub should_be_mask: Value, pub value: Value }
#[derive(Debug, Deserialize, Clone)]
pub struct Bits { pub range: Range, pub should_be_mask: Value, pub value: Value }
#[derive(Copy, Clone, Debug, Deserialize)]
pub struct Range { pub start: u32, pub width: u32 }
#[derive(Debug, Deserialize, Clone)]
pub struct Value { pub value: String }
impl Value {
    pub fn as_str(&self) -> Option<&str> {
        if self.value.starts_with('\'') && self.value.ends_with('\'') {
            Some(self.value.split_at(self.value.len() - 1).0.split_at(1).1)
        } else { None }
    }
}
#[derive(Debug, Deserialize, Clone)]
pub struct Instruction {
    pub encoding: Encodeset, pub name: String, pub operation_id: String,
    #[serde(default)] pub children: Vec<InstructionGroupOrInstruction>,
}
#[derive(Debug, Deserialize, Clone)]
pub struct InstructionAlias {
    pub name: String, pub operation_id: String,
    #[serde(default)] pub children: Vec<InstructionGroupOrInstruction>,
}


fn extract_all_instructions(nodes: &[InstructionGroupOrInstruction], out: &mut Vec<Instruction>) {
    for node in nodes {
        match node {
            InstructionGroupOrInstruction::InstructionGroup(g) => {
                let group_name = g.name.to_lowercase();
                // If the group belongs to SVE, SME drop it.
                if !group_name.contains("sve") && !group_name.contains("sme") {
                    extract_all_instructions(&g.children, out);
                }
            },
            InstructionGroupOrInstruction::Instruction(i) => {
                out.push(i.clone());
                extract_all_instructions(&i.children, out);
            }
            InstructionGroupOrInstruction::InstructionAlias(_) => {}
        }
    }
}

// Does this instruction translate a data virtual address (i.e. is it a
// load/store whose effective address goes through the stage-1 walk)? Only such
// instructions benefit from the --high-va-probe second pass; running the extra
// pass for non-memory ops would just double their cost with an identical
// footprint. Matched on the ARM-MRS encoding name / operation_id, which use the
// `_ldst*` group tag for the addressing form plus the standard load/store
// mnemonics and the atomic / exclusive / acquire-release families (all of which
// translate an address). Kept deliberately broad: a false positive only wastes
// one extra pass, while a false negative silently misses a TTBR1 read.
fn is_memory_instruction(inst: &Instruction) -> bool {
    let name = inst.name.to_lowercase();
    let op_id = inst.operation_id.to_lowercase();

    // Addressing-form group tags used by the ARM-MRS JSON for memory ops.
    if name.contains("ldst") || op_id.contains("ldst")
        || op_id.contains("memop") || op_id.contains("comswap")
        || op_id.contains("ldstord") || op_id.contains("exclusive")
        || op_id.contains("atomic")
    {
        return true;
    }

    // Mnemonic prefixes that always address memory. ld*/st* covers LDR/STR,
    // LDP/STP, LDUR/STUR, LDAR/STLR, LDAPR/STLUR, LDXR/STXR, LDADD/LDCLR/...
    // (atomics), LDAPUR, etc. CAS*/SWP* are compare-swap / swap atomics.
    // PRFM/PRFUM are prefetches that still translate. RCW* are read-check-write.
    for p in &["ld", "st", "cas", "swp", "prfm", "prfum", "rcw"] {
        if name.starts_with(p) {
            return true;
        }
    }
    false
}



fn instruction_to_segments(inst: &Instruction) -> Result<Vec<InstructionSegment<B129>>, String> {
    let mut segments = Vec::new();
    let mut encodes: Vec<&Encode> = inst.encoding.values.iter().collect();
    encodes.sort_by(|a, b| {
        let r_a = match a { Encode::Field(f) => f.range, Encode::Bits(b) => b.range };
        let r_b = match b { Encode::Field(f) => f.range, Encode::Bits(b) => b.range };
        r_b.start.cmp(&r_a.start)
    });
    let mut current_bit = 32;
    for enc in encodes {
        let (range, _is_bits, _val_str, _name) = match enc {
            Encode::Bits(b) => (b.range, true, b.value.as_str().unwrap_or(""), ""),
            Encode::Field(f) => (f.range, false, "", f.name.as_str()),
        };
        if current_bit > range.start + range.width {
            let gap = current_bit - (range.start + range.width);
            segments.push(InstructionSegment::Symbolic(String::from("ignored"), gap));
            current_bit -= gap;
        }
        match enc {
            Encode::Bits(b) => {
                let val_str = b.value.as_str().unwrap_or("");
                let val = u64::from_str_radix(val_str, 2).unwrap_or(0);
                segments.push(InstructionSegment::Concrete(B129::new(val, range.width)));
            },
            Encode::Field(f) => {
                // Check if the JSON enforces a concrete value for this field (like sf=0)
                if let Some(val_str) = f.value.as_str() {
                    if !val_str.is_empty() && !val_str.contains('x') {
                        let val = u64::from_str_radix(val_str, 2).unwrap_or(0);
                        segments.push(InstructionSegment::Concrete(B129::new(val, f.range.width)));
                        current_bit -= range.width;
                        continue;
                    }
                }
                segments.push(InstructionSegment::Symbolic(f.name.to_string(), f.range.width));
            }
        }
        current_bit -= range.width;
    }
    if current_bit > 0 { segments.push(InstructionSegment::Symbolic(String::from("ignored"), current_bit)); }
    Ok(segments)
}

fn main() {
    let code = isla_main();
    unsafe { isla_lib::smt::finalize_solver() };
    exit(code)
}

pub fn hex_bytes(s: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16)).collect()
}

#[derive(Clone, Debug)]
enum InstructionSegment<B> {
    Concrete(B),
    Symbolic(String, u32),
}

impl<B: BV> std::fmt::Display for InstructionSegment<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            InstructionSegment::Concrete(bv) => write!(f, "{}", bv),
            InstructionSegment::Symbolic(s, len) => write!(f, "{}:{}", s, len),
        }
    }
}

fn instruction_to_string<B: BV>(opcode: &[InstructionSegment<B>]) -> String {
    let mut s = "".to_string();
    for seg in opcode {
        s += &format!("{} ", seg);
    }
    s
}

fn instruction_to_val<B: BV>(
    opcode: &[InstructionSegment<B>],
    constraints: &[String],
    solver: &mut Solver<B>,
) -> Val<B> {
    match opcode {
        [InstructionSegment::Concrete(bv)] => Val::Bits(*bv),
        _ => {
            print!("(segments");
            let mut var_map = HashMap::new();
            let val = Val::MixedBits(
                opcode
                    .iter()
                    .map(|segment| match segment {
                        InstructionSegment::Concrete(bv) => BitsSegment::Concrete(*bv),
                        InstructionSegment::Symbolic(name, size) => {
                            if let Some((size2, v)) = var_map.get(name) {
                                if size == size2 {
                                    BitsSegment::Symbolic(*v)
                                } else {
                                    panic!(
                                        "{} appears in instruction with different sizes, {} and {}",
                                        name, size, size2
                                    )
                                }
                            } else {
                                let v = solver.declare_const(smtlib::Ty::BitVec(*size), SourceLoc::unknown());
                                print!("\n  (|{}| {} v{})", name, size, v);
                                var_map.insert(name, (*size, v));
                                BitsSegment::Symbolic(v)
                            }
                        }
                    })
                    .collect(),
            );
            println!(")");
            for constraint in constraints {
                let mut lookup = |loc: &Loc<String>| match loc {
                    Loc::Id(name) => match var_map.get(&zencode::decode(name)) {
                        Some((_size, v)) => Ok(smtlib::Exp::Var(*v)),
                        None => Err(format!("No variable {} in constraint", name)),
                    },
                    _ => Err(format!("Only names can appear in instruction constraints, not {}", loc)),
                };
                let assertion = smt_parser::ExpParser::new().parse(constraint).expect("Bad instruction constraint");
                solver.add_event(Event::Assume(assertion.clone()));
                let assertion_exp = assertion.map_var(&mut lookup).expect("Bad instruction constraint");
                solver.add(smtlib::Def::Assert(assertion_exp));
            }
            val
        }
    }
}

fn opcode_bytes<B: BV>(opcode: Vec<u8>, little_endian: bool) -> B {
    if opcode.len() > 8 {
        eprintln!("Currently instructions greater than 8 bytes in length are not supported");
        exit(1);
    }

    if opcode.len() == 2 {
        let opcode: Box<[u8; 2]> = opcode.into_boxed_slice().try_into().unwrap();
        B::from_u16(if little_endian { u16::from_le_bytes(*opcode) } else { u16::from_be_bytes(*opcode) })
    } else if opcode.len() == 4 {
        let opcode: Box<[u8; 4]> = opcode.into_boxed_slice().try_into().unwrap();
        B::from_u32(if little_endian { u32::from_le_bytes(*opcode) } else { u32::from_be_bytes(*opcode) })
    } else {
        B::from_bytes(&opcode)
    }
}

fn parse_elf_function_offset(input: &str) -> Option<(&str, u64)> {
    let (symbol, offset) = input.split_once(':')?;

    match offset.parse::<u64>() {
        Ok(offset) => Some((symbol, offset)),
        Err(_) => {
            let bv = B129::from_str(offset)?;
            Some((symbol, bv.lower_u64()))
        }
    }
}

#[allow(dead_code)]
struct OpcodeInfo<'a, B> {
    call: Name,
    args: Vec<&'a str>,
    bits: B,
    mask: B,
    slice: Vec<(&'a str, u32, u32)>,
    see: Option<i64>,
}

impl<'a, B: BV> OpcodeInfo<'a, B> {
    fn parse<'b>(value: &'a toml::Value, symtab: &'b Symtab) -> Result<Self, String> {
        let Some(call_str) = value.get("call").and_then(toml::Value::as_str) else {
            return Err("Could not parse call field as string in opcode info".to_string());
        };

        let Some(call) = symtab.get(&zencode::encode(call_str)) else {
            return Err(format!("Could not find function {}", call_str));
        };

        let Some(args) = value
            .get("args")
            .and_then(toml::Value::as_array)
            .and_then(|arr| arr.iter().map(toml::Value::as_str).collect::<Option<Vec<_>>>())
        else {
            return Err(format!("Could not parse args field in opcode info for {}", call_str));
        };

        let bits = match value.get("bits").and_then(toml::Value::as_str) {
            Some(hex_str) => match hex_bytes(hex_str) {
                Ok(bytes) => opcode_bytes(bytes, false),
                Err(e) => return Err(format!("Could not parse hexadecimal bits {} for {}: {}", hex_str, call_str, e)),
            },
            None => return Err(format!("Expected string value for bits field in opcode info for {}", call_str)),
        };

        let mask = match value.get("mask").and_then(toml::Value::as_str) {
            Some(hex_str) => match hex_bytes(hex_str) {
                Ok(bytes) => opcode_bytes(bytes, false),
                Err(e) => return Err(format!("Could not parse hexadecimal mask {} for {}: {}", hex_str, call_str, e)),
            },
            None => return Err(format!("Expected string value for mask field in opcode info for {}", call_str)),
        };

        let slice = match value.get("slice").and_then(toml::Value::as_table) {
            Some(table) => {
                let mut slice = Vec::new();
                for (arg, indices) in table.iter() {
                    if let Some(ix) = indices.as_array() {
                        if ix.len() == 1 || ix.len() == 2 {
                            let Some(hi) = ix[0].as_integer().and_then(|i| u32::try_from(i).ok()) else {
                                return Err(format!("Failed to parse integer slice index {} for {}", arg, call_str));
                            };
                            let Some(lo) = ix[ix.len() - 1].as_integer().and_then(|i| u32::try_from(i).ok()) else {
                                return Err(format!("Failed to parse integer slice index {} for {}", arg, call_str));
                            };
                            slice.push((arg.as_str(), hi, lo))
                        } else {
                            return Err(format!("Incorrect slice length {} for {}", arg, call_str));
                        }
                    }
                }
                slice
            }
            None => return Err(format!("Expected table value for slice field in opcode info for {}", call_str)),
        };

        let see = match value.get("see") {
            Some(v) => {
                if let Some(i) = v.as_integer() {
                    Some(i)
                } else {
                    return Err(format!("Could not parse see field in opcode info for {}", call_str));
                }
            }
            None => None,
        };

        Ok(OpcodeInfo { call, args, bits, mask, slice, see })
    }

    fn to_instruction_segments(&self, constraints: &mut Vec<String>) -> Vec<InstructionSegment<B>> {
        let length = self.bits.len();
        let mut current = length - 1;

        let mut ordered_slices = self.slice.clone();
        ordered_slices.sort_by(|(_, hi1, _), (_, hi2, _)| hi2.cmp(hi1));

        let mut segments = Vec::new();
        for (field, hi, lo) in ordered_slices {
            if current > hi {
                segments.push(InstructionSegment::Concrete(self.bits.extract(current, hi + 1).unwrap()))
            }
            let bits = self.bits.extract(hi, lo).unwrap();
            let mask = self.mask.extract(hi, lo).unwrap();
            if mask == B::ones((hi - lo) + 1) {
                segments.push(InstructionSegment::Concrete(bits))
            } else if mask.is_zero() {
                segments.push(InstructionSegment::Symbolic(field.to_string(), (hi - lo) + 1))
            } else {
                segments.push(InstructionSegment::Symbolic(field.to_string(), (hi - lo) + 1));
                constraints.push(format!("(= (bvand {} {}) {})", field, mask, bits));
            }
            current = lo - 1
        }
        if current != u32::MAX {
            segments.push(InstructionSegment::Concrete(self.bits.extract(current, 0).unwrap()))
        }

        segments
    }
}

pub fn isla_main() -> i32 {
    let now = Instant::now();
    let mut opts = opts::common_opts();
    opts.reqopt("i", "instruction", "display footprint of instruction", "<instruction>");
    opts.reqopt("n", "arm-json", "batch processing of all arm instruction from json", "<files>");
    opts.optopt("e", "endianness", "instruction encoding endianness (default: little)", "big/little");
    opts.optopt("", "elf", "load an elf file, and use instructions from it", "<file>");
    opts.optflag("d", "dependency", "view instruction dependency info");
    opts.optflag("x", "hex", "parse instruction as hexadecimal opcode, rather than assembly");
    opts.optflag("s", "simplify", "simplify instruction footprint");
    opts.optflag("", "simplify-registers", "simplify register accesses in traces");
    opts.optflag("", "hide", "hide uninteresting trace elements");
    opts.optflag("t", "tree", "combine traces into tree");
    opts.optopt("f", "function", "use a custom footprint function", "<identifer>");
    opts.optflag("c", "continue-on-error", "continue generating traces upon encountering an error");
    opts.optopt("", "armv8-page-tables", "set up page tables with provided constraints", "<constraints>");
    opts.optflag("", "zero-memory", "treat all memory as being zero");
    opts.optflag("", "mmu-on", "batch path only: install a minimal identity-mapped stage-1 page table (one 1GB block) and back code/data at/above 0x400000 with zero, leaving the table pages just below it intact. Use with an MMU-on config (SCTLR_ELx.M=1, TTBR0 -> 0x300000). Do NOT combine with --zero-memory.");
    opts.optmulti("", "only", "batch path only: restrict the run to instructions whose name matches (case-insensitive, repeatable). For quick iteration/validation, e.g. --only LDR_64_ldst_pos. Applied after the filter.", "<instr>");
    opts.optflag("", "high-va-probe", "batch path only: for every memory-access instruction, run an ADDITIONAL pass with all GPRs/SPs pinned to a high (TTBR1-region) virtual address so the stage-1 walk selects and READS the TTBR1 base (surfacing TTBR1_ELx in the per-instruction footprint). The extra trace is written under the SAME instruction name (with a ` | VA: high` header tag) so its register reads merge into that instruction's footprint. REQUIRES a config + setup that make the high half walkable (see --high-va-base).");
    opts.optopt("", "high-va-base", "batch path only: base virtual address used by --high-va-probe (hex, e.g. 0xFFFF000000600000). Default 0xFFFF000000600000. For the high-VA walk to COMPLETE CLEANLY (a faulting pass is discarded by the parser, so its TTBR1 read would not be recorded) the run must also: (1) set TCR_ELx.T1SZ to a valid value (e.g. 16) and EPD1=0 in the config so TTBR1 walks are enabled, and (2) map this VA to a backing page via the page-table builder (--armv8-page-tables), e.g. an entry that points this TTBR1-region VA at an existing low PA. Confirm the builder's VA|->PA syntax in isla-axiomatic setup_parser.lalrpop.", "<hex>");
    opts.optflag("", "partial", "parse instruction as binary with unknown bits");
    opts.optopt("", "from-file", "parse instruction from opcodes file", "<file>");
    opts.optmulti("", "instruction-constraint", "add constraint on variables in a partial instruction", "<constraint>");
    opts.optflag("", "eval-carefully", "during simplification check the results of symbolic evaluation");
    opts.optmulti(
        "k",
        "kill-at",
        "stop executions early and discard if they reach this function (with optional context)",
        "<function name[, function_name]>",
    );
    opts.optmulti(
        "",
        "stop-at",
        "stop executions early and keep trace if they reach this function (with optional context)",
        "<function name[, function_name]>",
    );
    opts.optflag("", "pessimistic", "fail on any assertion that is not necessarily true");
    opts.optopt("", "timeout", "Add a timeout (in seconds)", "<n>");
    opts.optflag("", "executable", "make trace executable");
    let mut hasher = Sha256::new();
    let (matches, arch) = opts::parse(&mut hasher, &opts);
    if !matches.free.is_empty() {
        eprintln!("Unexpected arguments: {}", matches.free.join(" "));
        exit(1)
    }
    let CommonOpts { num_threads, mut arch, symtab, type_info, isa_config, source_path } =
        opts::parse_with_arch(&mut hasher, &opts, &matches, &arch);
    let assertion_mode =
        if matches.opt_present("pessimistic") { AssertionMode::Pessimistic } else { AssertionMode::Optimistic };
    let use_model_reg_init = !matches.opt_present("no-model-reg-init");
    let iarch = initialize_architecture(&mut arch, symtab, type_info, &isa_config, assertion_mode, use_model_reg_init);
    let iarch_config = InitArchWithConfig::from_initialized(&iarch, &isa_config);
    let regs = &iarch.regs;
    let lets = &iarch.lets;
    let shared_state = &&iarch.shared_state;
    log!(log::VERBOSE, &format!("Parsing took: {}ms", now.elapsed().as_millis()));
    let little_endian = match matches.opt_str("endianness").as_deref() {
        Some("little") | None => true,
        Some("big") => false,
        Some(_) => {
            eprintln!("--endianness argument must be one of either `big` or `little`");
            exit(1)
        }
    };
    let timeout: Option<u64> = match matches.opt_get("timeout") {
        Ok(timeout) => timeout,
        Err(e) => {
            eprintln!("Failed to parse --timeout: {}", e);
            return 1;
        }
    };
    let instruction = matches.opt_str("instruction").unwrap_or_else(|| "".to_string());
    let mut reset_registers: HashMap<Loc<Name>, Reset<B129>> = HashMap::new();
    let mut constraints: Vec<String> = matches.opt_strs("instruction-constraint");

    let opcode: Vec<InstructionSegment<B129>> = if matches.opt_present("n") {
        vec![]
    } else if matches.opt_present("partial") {
        instruction
            .split_ascii_whitespace()
            .map(|s| {
                B129::from_str(&format!("0b{}", s))
                    .map(InstructionSegment::Concrete)
                    .or_else(|| {
                        let mut it = s.split(':');
                        let name = it.next()?;
                        let size = it.next()?;
                        size.parse().ok().map(|size| InstructionSegment::Symbolic(name.to_string(), size))
                    })
                    .unwrap_or_else(|| {
                        eprintln!("Unable to parse instruction segment {}", s);
                        exit(1)
                    })
            })
            .collect()
    } else if let Some(opcode_file) = matches.opt_str("from-file").as_deref() {
        let mut contents = String::new();
        match File::open(opcode_file) {
            Ok(mut handle) => match handle.read_to_string(&mut contents) {
                Ok(_) => (),
                Err(e) => {
                    eprintln!("Unexpected error when reading opcode from {}: {}", opcode_file, e);
                    return 1;
                }
            },
            Err(e) => {
                eprintln!("Failed to open opcode file: {}", e);
                return 1;
            }
        }
        let opcodes = match contents.parse::<toml::Value>() {
            Ok(toml) => {
                if let toml::Value::Table(mut tbl) = toml {
                    match tbl.remove("opcode") {
                        Some(toml::Value::Array(opcodes)) => opcodes,
                        _ => {
                            eprintln!("Expected a sequence of [[opcode]] items");
                            return 1;
                        }
                    }
                } else {
                    eprintln!("Invalid opcodes file");
                    return 1;
                }
            }
            Err(e) => {
                eprintln!("Error when parsing configuration: {}", e);
                return 1;
            }
        };
        let opcodes = opcodes
            .iter()
            .map(|value| OpcodeInfo::<B129>::parse(value, &shared_state.symtab))
            .collect::<Result<Vec<_>, _>>();
        if let Err(msg) = opcodes {
            eprintln!("{}", msg);
            return 1;
        }
        let opcodes = opcodes.unwrap();
        let (instruction, n, explicit_n): (&str, usize, bool) = match instruction.split_once(':') {
            Some((instruction, n)) => {
                let Ok(n) = usize::from_str_radix(n, 10) else {
                    eprintln!("Could not parse instruction index");
                    return 1;
                };
                (instruction, n, true)
            }
            None => (&instruction, 0, false),
        };
        let call = shared_state.symtab.lookup(&zencode::encode(instruction));
        let opcode_infos: Vec<&OpcodeInfo<B129>> = opcodes.iter().filter(|op| op.call == call).collect();
        if !explicit_n && opcode_infos.len() > 1 {
            eprintln!(
                "{} has {} decode clauses. Use -i/--instruction {}:<n> to choose one",
                instruction,
                opcode_infos.len(),
                instruction
            );
            return 1;
        } else if opcode_infos.is_empty() {
            eprintln!("Could not find opcode info for {}", instruction);
            return 1;
        }
        let Some(opcode_info) = opcode_infos.get(n) else {
            eprintln!("{} has {} decode clauses. Index {} is out of bounds", instruction, opcode_infos.len(), n);
            return 1;
        };
        if let Some(see) = opcode_info.see {
            let see_reg = shared_state.symtab.lookup("zSEE");
            reset_registers.insert(Loc::Id(see_reg), Arc::new(move |_, _, _| Ok(Val::I128(see as i128 - 1))));
        }
        opcode_info.to_instruction_segments(&mut constraints)
    } else if matches.opt_present("hex") {
        match hex_bytes(&instruction) {
            Ok(opcode) => vec![InstructionSegment::Concrete(opcode_bytes(opcode, little_endian))],
            Err(e) => {
                eprintln!("Could not parse hexadecimal opcode: {}", e);
                exit(1)
            }
        }
    } else if matches.opt_present("elf") {
        Vec::new()
    } else {
        match assemble_instruction(&instruction, &isa_config) {
            Ok(opcode) => vec![InstructionSegment::Concrete(opcode_bytes(opcode, little_endian))],
            Err(msg) => {
                eprintln!("{}", msg);
                return 1;
            }
        }
    };

    if !matches.opt_present("elf") && !matches.opt_present("n") {
        log!(log::VERBOSE, &format!("opcode: {}", instruction_to_string(&opcode)));
    }

    let kill_conditions = StopConditions::parse(matches.opt_strs("kill-at"), shared_state, StopAction::Kill);
    let abstract_conditions = StopConditions::parse(matches.opt_strs("stop-at"), shared_state, StopAction::Abstract);
    let stop_conditions = kill_conditions.union(&abstract_conditions);

    let mut memory = Memory::new();
    let PageTableSetup { memory_checkpoint, .. } = if let Some(setup) = matches.opt_str("armv8-page-tables") {
        let lexer = page_table::setup_lexer::SetupLexer::new(&setup);
        let constraints = match page_table::setup_parser::SetupParser::new()
            .parse(&isa_config, lexer)
            .map_err(|error| error.to_string())
        {
            Ok(constraints) => constraints,
            Err(msg) => {
                eprintln!("{}", msg);
                return 1;
            }
        };
        page_table::setup::armv8_page_tables(&mut memory, HashMap::new(), 0, &constraints, &isa_config).unwrap()
    } else {
        PageTableSetup {
            memory_checkpoint: Checkpoint::new(),
            all_addrs: HashMap::new(),
            physical_addrs: HashMap::new(),
            initial_physical_addrs: HashMap::new(),
            tables: HashMap::new(),
            maybe_mapped: HashSet::new(),
        }
    };

    let (elf_checkpoint, have_elf, elf_opcode_val) = if let Some(file) = matches.opt_str("elf") {
        let (symbol, offset) = match parse_elf_function_offset(instruction.as_ref()) {
            Some((symbol, offset)) => (symbol, offset),
            None => {
                eprintln!("Could not parse elf instruction argument {}. Format is 'symbol:offset'", instruction);
                eprintln!("'offset' can be decimal [0-9]+, hexadecimal 0x[0-9a-fA-F]+, or binary 0b[0-1]+");
                return 1;
            }
        };
        match std::fs::read(&file) {
            Ok(buf) => {
                if let Some((_endianness, elf, _dwarf)) = elf::parse_elf_with_debug_info(&buf) {
                    if let Some(func) = elf::elf_function::<AArch64>(&elf, &buf, symbol) {
                        eprintln!("{:?}", func);
                        let instr = func.get_instruction_at_section_offset(offset).unwrap();
                        eprintln!("opcode: {:?}", instr);
                        let solver_cfg = smt::Config::new();
                        let solver_ctx = smt::Context::new(solver_cfg);
                        let mut solver = Solver::from_checkpoint(&solver_ctx, memory_checkpoint);
                        let SymbolicRelocation { symbol, place, opcode } =
                            instr.relocate_symbolic::<AArch64, B129>(&mut solver, SourceLoc::unknown()).unwrap();
                        eprintln!("Symbol = v{}, Place = v{}", symbol, place);
                        (smt::checkpoint(&mut solver), true, Some(opcode))
                    } else {
                        eprintln!("Failed to get function {} from ELF file {}", symbol, file);
                        return 1;
                    }
                } else {
                    eprintln!("Failed to parse ELF file {}", file);
                    return 1;
                }
            }
            Err(err) => {
                eprintln!("Could not read ELF file {}: {}", file, err);
                return 1;
            }
        }
    } else {
        (memory_checkpoint, false, None)
    };

    if matches.opt_present("zero-memory") {
        memory.add_zero_region(0x0..0xffff_ffff_ffff_ffff);
    }

    let footprint_function = match matches.opt_str("function") {
        Some(id) => zencode::encode(&id),
        None => "zisla_footprint".to_string(),
    };

    // ---------------------------------------------------------------------
    // BATCH PROCESSING FOR ARM V9.4 JSON (SPLIT BY EXCEPTION LEVEL)
    // ---------------------------------------------------------------------
    if let Some(arm_json_file) = matches.opt_str("n").as_deref() {
        // --high-va-probe configuration (Step 5: surface TTBR1_ELx). When set,
        // every memory-access instruction is executed a SECOND time with all
        // GPRs/SPs pinned to a high (TTBR1-region) VA so the stage-1 walk
        // selects and reads the TTBR1 base. The low base remains
        // LOW_VA_BASE (0x600000, TTBR0 region) for the first pass.
        let high_va_probe = matches.opt_present("high-va-probe");
        let high_va_base: u64 = match matches.opt_str("high-va-base") {
            Some(s) => {
                let t = s.trim();
                let parsed = if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    u64::from_str_radix(hex, 16)
                } else {
                    t.parse::<u64>()
                };
                match parsed {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Failed to parse --high-va-base '{}': {}", s, e);
                        return 1;
                    }
                }
            }
            // Default: TTBR1 region (top 16 VA bits set) mirroring the low data
            // base's page offset, for a 48-bit VA / T1SZ=16 layout.
            None => 0xFFFF_0000_0060_0000,
        };
        if high_va_probe {
            println!(
                "--high-va-probe active: memory instructions get an extra TTBR1-region pass at base {:#018x}",
                high_va_base
            );
        }

        // The batch path pins every GPR to a concrete, page-aligned address
        // (STEP 3), so it needs a concrete backing store for those addresses
        // to resolve to definite data rather than forking the read.
        //
        // Two regimes:
        //
        //  * --mmu-on (MMU enabled in the config): a load/store now performs a
        //    real stage-1 translation-table walk, so TTBR0_ELx / MAIR_ELx and
        //    the descriptors are actually read -- this is what surfaces the
        //    translation registers in the per-instruction footprints (fixes the
        //    `*->EL0` TTBR0_EL1/TTBR1_EL1/MAIR_EL1 false negatives). For the walk
        //    to succeed we install a minimal identity map: one L0 table entry
        //    pointing at one L1 1GB *block* descriptor that maps [0, 1GB)
        //    identity as Normal (MAIR Attr0), AF=1, AP=EL0/EL1 RW, executable.
        //    That single block covers the table pages, the code/PC region and
        //    the pinned data base (0x600000) regardless of their exact address,
        //    as long as they live in the first GB (they do). TTBR0 must resolve
        //    to the L0 table base 0x300000 (config: TTBR0_NS/_HTTBR = 0x300000).
        //
        //    The descriptor pages live in [0x300000, 0x302000). We must NOT drop
        //    a blanket zero region over them or the walk would read zeroed
        //    (invalid) descriptors and translation-fault. So we back only
        //    [0x400000, end) with zero -- code (0x400000) and data (0x600000)
        //    sit above the tables, giving a precedence-independent layout with
        //    no overlap between the concrete table region and the zero region.
        //
        //  * otherwise (MMU off, the previous default): every access is flat, so
        //    a full zero region is the correct concrete backing store.
        if matches.opt_present("mmu-on") {
            // --- L0[0]: table descriptor -> L1 table at PA 0x301000 ---------
            //   bits[1:0] = 0b11 (valid, table)
            //   bits[47:12] = next-level table addr (0x301000 >> 12 = 0x301)
            //   => 0x301000 | 0x3 = 0x0000_0000_0030_1003
            //
            // --- L1[0]: 1GB block descriptor, identity [0,1GB) --------------
            //   bits[1:0]   = 0b01  (valid, block at L1)
            //   bits[4:2]   = 0b000 AttrIndx -> MAIR_EL1 Attr0 = 0xFF (Normal WB)
            //   bits[7:6]   = 0b01  AP -> EL1 *and* EL0 read/write
            //   bits[9:8]   = 0b11  SH -> Inner Shareable
            //   bit[10]     = 1     AF (FEAT_HAFDBS off, so AF must be preset)
            //   bits[54,53] = 0,0   UXN/PXN -> executable at EL0 and EL1
            //   output addr = 0     (block base PA 0)
            //   => 0x400 | 0x300 | 0x40 | 0x1 = 0x0000_0000_0000_0741
            let mut descriptors: HashMap<u64, u8> = HashMap::new();
            for (i, b) in 0x0000_0000_0030_1003u64.to_le_bytes().iter().enumerate() {
                descriptors.insert(0x0030_0000u64 + i as u64, *b);
            }
            for (i, b) in 0x0000_0000_0000_0741u64.to_le_bytes().iter().enumerate() {
                descriptors.insert(0x0030_1000u64 + i as u64, *b);
            }
            // NOTE(verify-against-your-isla): the single isla-version-specific
            // line. `Memory::add_concrete_region(Range<u64>, HashMap<u64,u8>)`
            // is the isla-lib API for a fixed concrete byte region (the concrete
            // sibling of `add_zero_region` used below). If your tree names it
            // differently, this is the only call to adjust; it must place the 16
            // descriptor bytes above at 0x300000/0x301000.
            memory.add_concrete_region(0x0030_0000..0x0030_2000, descriptors);
            memory.add_zero_region(0x0040_0000..0xffff_ffff_ffff_ffff);
        } else if !matches.opt_present("zero-memory") {
            memory.add_zero_region(0x0..0xffff_ffff_ffff_ffff);
        }

        println!("Loading ARM v9.4 JSON Instructions from: {}", arm_json_file);
        let file_contents = std::fs::read_to_string(arm_json_file).expect("Failed to read JSON file");

        println!("\n--- PARSED STRUCT DATA ---");
        let root: Instructions = serde_json::from_str(&file_contents).expect("Failed to parse JSON");
        println!("Metadata: {:#?}", root._meta);

        if let Some(first_iset) = root.instructions.first() {
            println!("First Instruction Set Name: {}", first_iset.name);
            println!("First Instruction Set Details: {:#?}", first_iset);
        }
        println!("--------------------------\n");

        ////////
        // Working only on the base set here
        ///////

        let mut all_instructions = Vec::new();
        for iset in root.instructions {
            // The ARM-MRS JSON ships the A64, A32 and T32 instruction sets in a
            // single file. We execute at PSTATE.nRW = 0 (AArch64), so any
            // AArch32/T32 encoding is fed to the A64 decoder and ALIASES onto an
            // unrelated A64 op: e.g. SRSIA_A1_AS surfaced as a bogus
            // APDBKey_EL1 reader and threw at builtins.sail:52 (Error_Exception-
            // Taken). Restrict to the A64 set at the source so those aliases
            // never enter the corpus. Print each set name so the "a64" match can
            // be confirmed against the actual JSON labels.
            let set_name = iset.name.to_lowercase();
            println!("Instruction set in JSON: '{}'", iset.name);
            if !set_name.contains("a64") {
                println!("  -> skipping non-A64 set (AArch32/T32 aliases under the A64 decoder)");
                continue;
            }
            extract_all_instructions(&iset.children, &mut all_instructions);
        }

        println!("Found {} A64 instructions. Filtering...", all_instructions.len());

        let original_count = all_instructions.len();

        // -----------------------------------------------------------------
        // UNIFIED FILTER
        //
        // Two distinct categories are dropped here:
        //
        //  (1) Instructions that are expensive/impossible to execute
        //      symbolically (path explosion, uninitialised key state, ...).
        //
        //  (2) Instructions that CANNOT decode in the sail-arm `arm-v9.4-a`
        //      model because the extension is simply absent from it
        //      (FEAT_CMPBR, FEAT_LSUI, FEAT_LSFE, FEAT_CPA): they threw
        //      Error_Undefined in decode_end.sail identically at all four
        //      ELs and carried no EL-sensitivity information. If you move to
        //      a newer model snapshot, revisit category (2).
        // -----------------------------------------------------------------

        all_instructions.retain(|inst| {
            let name  = inst.name.to_lowercase();
            let op_id = inst.operation_id.to_lowercase();

            // SVE / SME: also caught at group level in extract_all_instructions,
            // but catches any stragglers that come through via aliases or op_id.
            if name.contains("_z_")  || name.contains("_p_")   || name.contains("_zz_")
            || name.contains("_z__") || name.contains("_zzz_") || name.contains("_zi_")
            || name.ends_with("_z")  || name.ends_with("_p")
            || name.starts_with("sve_")
            || op_id.starts_with("sve_") || op_id.starts_with("sme_")
            {
                return false;
            }

            // PAC / Pointer Authentication: require key registers
            // (APIAKey_EL1 etc.) that are not initialised in the default
            // isla config.
            for prefix in &["pac", "aut", "xpac", "reta", "braa", "brab",
                             "blraa", "blrab", "ereta", "ldraa", "ldrab"] {
                if name.starts_with(prefix) { return false; }
            }

            // Exception-generating instructions: unconditionally diverge into
            // exception-handler paths and never reach normal symbolic completion.
            for ex in &["svc", "hvc", "smc", "brk", "hlt",
                         "dcps1", "dcps2", "dcps3", "udf",
                         "wfi", "wfe", "sev", "sevl", "yield_", "hint"] {
                if name == *ex || name.starts_with(&format!("{}_", ex)) { return false; }
            }

            // Generic SYS / SYSL. The previous `name == "sys"` exact-match never
            // fired (real names are sys_cr_systeminstrs / sysl_rc_systeminstrs),
            // so both slipped through and threw at sysregs.sail:937. Match the
            // encoded prefix. SYSP (128-bit) is covered in the misc block below.
            if name.starts_with("sys_") || name.starts_with("sysl_") { return false; }

            // Cache / TLB / instruction-cache maintenance (DC, IC, AT, TLBI):
            // involve address-translation paths that are prohibitively expensive
            // to symbolically execute.
            if op_id.contains("_dc_") || op_id.contains("_ic_")
            || op_id.contains("_at_") || op_id.contains("_tlbi_")
            || name.starts_with("dc_") || name.starts_with("ic_")
            || name.starts_with("at_") || name.starts_with("tlbi_")
            {
                return false;
            }

            // Cryptographic extension instructions (AES, SHA-1/256/512/3,
            // SM3/4, PMULL, BCAX, EOR3, RAX1, XAR): require optional
            // FEAT_AES/SHA*/SM* features and touch SIMD state in ways that
            // may not be initialised in the default config.
            for prefix in &[
                "aese", "aesd", "aesmc", "aesimc",
                "sha1c", "sha1p", "sha1m", "sha1su0", "sha1su1", "sha1h",
                "sha256h", "sha256h2", "sha256su0", "sha256su1",
                "sha512h", "sha512h2", "sha512su0", "sha512su1",
                "sm3tt1a", "sm3tt1b", "sm3tt2a", "sm3tt2b",
                "sm3partw1", "sm3partw2", "sm4e", "sm4ekey",
                "pmull", "pmull2", "bcax", "eor3", "rax1", "xar",
            ] {
                if name.starts_with(prefix) { return false; }
            }

            // Advanced SIMD / NEON (vector operations on full 128-bit V regs):
            // detected via operation_id — the ARMv9.4 JSON uses "AdvSIMD" as a
            // prefix for all NEON instructions. Scalar FP (FEAT_FP) operates on
            // only 32/64 bits of a V register and is allowed through.
            if op_id.contains("advsim") || op_id.contains("advsimd") {
                return false;
            }

            // TME (Transactional Memory Extension).
            for prefix in &["tstart", "ttest", "tcancel", "tcommit"] {
                if name.starts_with(prefix) { return false; }
            }

            // RNDR / RNDRRS: non-deterministic by design.
            if name == "rndr" || name == "rndrrs" { return false; }

            // 128-bit compare-and-swap pair.
            if name.starts_with("casp")
                && (name.ends_with("_128") || name.contains("pair"))
            {
                return false;
            }

            // Debug instructions.
            if name.starts_with("bkpt") || op_id.contains("debug") { return false; }

            // -------------------------------------------------------------
            // Category (2): not decodable in arm-v9.4-a, or stubbed.
            // These previously produced identical throws at all four ELs:
            //   decode_end.sail:47  __DecodeA64_BranchExcSys  fall-through
            //   decode_end.sail:48  __DecodeA64_LoadStore     fall-through
            //   decode_end.sail:49  __DecodeA64_DataProcReg   fall-through
            // plus a handful of instrs64.sail feature gates / helper stubs.
            // -------------------------------------------------------------

            // FEAT_LSUI: unprivileged load/store variants
            // (LDT*/STT*/SWPT*/CAS*T/LDATXR/STLTXR/...)
            if name.ends_with("_unpriv") || op_id.ends_with("_unpriv") { return false; }
            for p in &["ldtnp", "ldtp", "sttnp", "sttp"] {
                if name.starts_with(p) { return false; }
            }

            // FEAT_CMPBR compare-and-branch (CBEQ/CBNE/CBB*/CBH*/... — the
            // legacy CBZ/CBNZ are *_compbranch and survive this check).
            if name.starts_with("cb") && !name.contains("compbranch") { return false; }

            // FEAT_LSFE / BF16 floating-point atomics.
            for p in &["ldfadd", "ldfmax", "ldfmin", "ldbf", "stbf",
                       "stfadd", "stfmax", "stfmin"] {
                if name.starts_with(p) { return false; }
            }

            // FEAT_MOPS "GO" memset variants (absent from the model; the
            // plain SETP/SETM/SETE and CPY* families DO exist and run once
            // FEAT_MOPS is enabled in the config and registers are allowed
            // to be pairwise distinct — see STEP 2).
            if name.contains("memset_go") { return false; }

            // FEAT_MTE tag arithmetic: HaveMTEExt() gates throw because
            // FEAT_MTE is deliberately disabled in armv9p4.toml (symbolic
            // addresses + tags cause spurious-abort explosion). Drop here;
            // re-enable in the config if you accept the cost.
            for p in &["addg", "subg", "gmi", "irg", "subp",
                       "stg", "st2g", "stzg", "stz2g", "ldg"] {
                if name.starts_with(p) { return false; }
            }

            // FEAT_CPA pointer-arithmetic checking.
            for p in &["addpt", "subpt", "maddpt", "msubpt"] {
                if name.starts_with(p) { return false; }
            }

            // Misc: LRCPC3 pair forms / LS64 / GCS / 128-bit sysreg moves /
            // TME-like state changes / debug-state return / hint stubs that
            // hit unimplemented helpers in the snapshot.
            for p in &["ldapp", "ldap_", "stlp", "ldiapp", "stilp",
                       "ld64b", "st64b",
                       "gcs",
                       "mrrs", "msrr", "sysp",
                       "tchange", "tenter", "texit",
                       "drps",
                       "psb", "stshh", "shuh", "stcph"] {
                if name.starts_with(p) { return false; }
            }

            // -------------------------------------------------------------
            // STRUCTURALLY DEAD families — observed unusable at EVERY EL in
            // the access classification and dead for reasons NO config/
            // register fix changes (so they are dropped here rather than
            // discovered via a keep-list each run).
            //
            // UPDATE: the computational FP family (FADD/FSUB/FMUL/FDIV/FNMUL,
            // FMADD/FMSUB/FNMADD/FNMSUB, FMAX*/FMIN*, FSQRT, FRINT*, FCMP/FCMPE,
            // FCVT*/SCVTF/UCVTF/FJCVTZS/BFCVT) is now dropped too. It was kept
            // on the theory that CPACR_EL1 + the V0..V31 pin would let it
            // complete, but a full MMU-on run shows every one of these is STILL
            // Timeout/ExecErr at all four ELs -- the per-register V0..V31 pin is
            // a no-op on this model (SIMD state is a single `_V` vector, so the
            // V{i} lookups return None), leaving the FP operands symbolic and
            // the FP solver intractable. Dropping them removes the dominant
            // cost of a run (~timeout x 4 ELs x ~190 ops). The NON-computational
            // FP ops that DO complete are deliberately kept: FABS/FNEG (sign-bit
            // only), FMOV (incl. _float2int register moves), FCSEL (_floatsel),
            // FCCMP/FCCMPE (_floatccmp) -- none of these match the prefixes below.
            // To re-attempt recovery, pin the `_V` vector register instead of
            // V0..V31 and remove the prefix drop.
            // -------------------------------------------------------------

            // 128-bit pair atomics (LDCLRP/LDSETP/SWPP/RCW*P ..._memop_128):
            // always Timeout/ExecErr -- the 128-bit RMW is intractable for the
            // solver and unaffected by the FP/memory fixes.
            if name.ends_with("_memop_128") { return false; }

            // RCW pair compare-swap (..._rcwcomswappr): always Error_Undefined
            // (the pair form is not decodable in the snapshot). The non-pair
            // RCW forms (_rcwcomswap, _memop) are fine and kept.
            if name.contains("comswappr") { return false; }

            // Scalar-SIMD FP-convert encodings (FCVT*/SCVTF/UCVTF "_sisd"):
            // always Error_Undefined (reserved/unsupported encoding), not an
            // FP-access trap, so the CPACR fix does not recover them.
            if name.contains("_sisd") { return false; }

            // AdvSIMD forms that slipped past the op_id AdvSIMD filter
            // (e.g. FMMLA_asimd_*): always Error_Undefined.
            if name.contains("_asimd") { return false; }

            // MOPS SET* family (SET/SETG prologue+main+epilogue, _SET_memcms):
            // always "Not allowed (mixed)" -- needs the prologue->main->epilogue
            // PSTATE sequencing that cannot exist for a single isolated op.
            if name.contains("_set_memcms") { return false; }

            // MOPS CPY *epilogue* variants (CPYE*/CPYFE*): always undefined/
            // mixed for the same sequencing reason. The CPY *prologue/main*
            // variants (CPYP*/CPYM*/CPYFP*/CPYFM*) are usable at EL2/EL3 and
            // are intentionally kept.
            if name.starts_with("cpye") || name.starts_with("cpyfe") { return false; }

            // Integer divide (SDIV/UDIV): always Timeout/ExecErr -- the divide
            // builtin is intractable for the solver here. (Recoverable in
            // principle with a much larger --timeout; dropped by default since
            // their sysreg footprint is empty anyway.)
            if name.starts_with("sdiv") || name.starts_with("udiv") { return false; }

            // Computational FP family: always Timeout/ExecErr at every EL (see
            // the STRUCTURALLY DEAD note above). Matched by mnemonic prefix so
            // the non-computational FP ops that DO complete are preserved:
            //   kept -> fabs, fneg, fmov (incl. fmov *_float2int), fcsel
            //           (floatsel), fccmp/fccmpe (floatccmp)
            //   dropped (below):
            for p in &[
                "fadd", "fsub", "fmul", "fnmul", "fdiv",     // floatdp2 arithmetic
                "fmadd", "fmsub", "fnmadd", "fnmsub",        // floatdp3 fused
                "fmax", "fmin",                              // floatdp2 min/max (+nm)
                "fsqrt", "frint",                            // floatdp1 sqrt / round
                "fcmp",                                      // floatcmp (NOT fccmp)
                "fcvt", "scvtf", "ucvtf", "fjcvt", "bfcvt",  // converts (NOT fmov)
            ] {
                if name.starts_with(p) { return false; }
            }

            true
        });

        println!(
            "Dropped {} instructions. Generating traces for {} instructions...",
            original_count - all_instructions.len(),
            all_instructions.len()
        );

        // Debugging / fast-iteration: if --only is given, keep only the named
        // instructions (case-insensitive exact match). Lets a single run target
        // e.g. one load to validate the MMU walk without the full sweep.
        let only_list: Vec<String> = matches.opt_strs("only");
        if !only_list.is_empty() {
            all_instructions
                .retain(|inst| only_list.iter().any(|o| o.eq_ignore_ascii_case(&inst.name)));
            println!(
                "--only active: restricted to {} instruction(s) [{}]",
                all_instructions.len(),
                only_list.join(", ")
            );
        }

        let write_opts = WriteOpts {
            define_enum: !matches.opt_present("simplify"),
            hide_uninteresting: matches.opt_present("hide"),
            ..WriteOpts::default()
        };

        // ARM Exception Levels: (name, value, bit-width)
        let exception_levels: Vec<(&str, u64, u32)> = vec![
            ("EL0", 0, 2),
            ("EL1", 1, 2),
            ("EL2", 2, 2),
            ("EL3", 3, 2),
        ];

        let output_dir = "arm_traces_output";
        std::fs::create_dir_all(output_dir).expect("Failed to create output directory");

        for (el_name, el_val, el_width) in exception_levels {
            println!("\n=======================================================");
            println!("GENERATING TRACES FOR ARM EXCEPTION LEVEL: {}", el_name);
            println!("=======================================================");

            for (file_idx, chunk) in all_instructions.chunks(15).enumerate() {
                println!(
                    "  [{}] Processing File {}/{} ({} instructions)",
                    el_name,
                    file_idx + 1,
                    (all_instructions.len() / 15) + 1,
                    chunk.len()
                );

                let file_name = format!("{}/{}_part_{:04}.txt", output_dir, el_name, file_idx + 1);
                let output_file = File::create(&file_name).expect("Could not create output file");
                let mut handle = BufWriter::with_capacity(5 * usize::pow(2, 20), output_file);

                'inst_loop: for inst in chunk {
                    // ---------------------------------------------------------
                    // STEP 1: Build the instruction segments.
                    //
                    //  • Uses i64 for current_bit to catch underflow correctly.
                    //  • should_be_mask all-ones  -> Concrete (avoids exploring
                    //    architecturally UNDEFINED encodings).
                    //  • Bits.value with 'x'      -> Symbolic (don't-care bits).
                    //  • Duplicate field names with different widths -> concrete
                    //    zero (instruction_to_val cannot share one name at two
                    //    widths).
                    //  • Validates total width == 32 and skips otherwise.
                    // ---------------------------------------------------------
                    let segments: Vec<InstructionSegment<B129>> = {
                        let mut segs = Vec::new();
                        let mut encodes: Vec<&Encode> = inst.encoding.values.iter().collect();
                        encodes.sort_by(|a, b| {
                            let r_a = match a { Encode::Field(f) => f.range, Encode::Bits(b) => b.range };
                            let r_b = match b { Encode::Field(f) => f.range, Encode::Bits(b) => b.range };
                            r_b.start.cmp(&r_a.start)
                        });

                        let mut current_bit: i64 = 32;
                        let mut seen_fields: HashMap<String, u32> = HashMap::new();
                        let mut bad = false;

                        for enc in &encodes {
                            let range = match enc {
                                Encode::Field(f) => f.range,
                                Encode::Bits(b)  => b.range,
                            };
                            let enc_top = (range.start + range.width) as i64;

                            if enc_top > 32 {
                                eprintln!(
                                    "Skipping {}: field at bit {} width {} exceeds 32",
                                    inst.name, range.start, range.width
                                );
                                bad = true;
                                break;
                            }

                            // Fill any gap above this field.
                            if current_bit > enc_top {
                                let gap = (current_bit - enc_top) as u32;
                                segs.push(InstructionSegment::Symbolic(String::from("ignored"), gap));
                                current_bit -= gap as i64;
                            }

                            if current_bit < enc_top {
                                eprintln!(
                                    "Skipping {}: overlapping field near bit {}",
                                    inst.name, current_bit
                                );
                                bad = true;
                                break;
                            }

                            match enc {
                                Encode::Bits(b) => {
                                    let val_str = b.value.as_str().unwrap_or("");
                                    if val_str.contains('x') || val_str.is_empty() {
                                        // Don't-care bits: emit symbolic rather than
                                        // silently zero-ing them via unwrap_or(0).
                                        segs.push(InstructionSegment::Symbolic(
                                            format!("bits_{}", range.start),
                                            range.width,
                                        ));
                                    } else {
                                        match u64::from_str_radix(val_str, 2) {
                                            Ok(val) => segs.push(InstructionSegment::Concrete(
                                                B129::new(val, range.width),
                                            )),
                                            Err(_) => {
                                                eprintln!(
                                                    "Skipping {}: bad Bits value '{}'",
                                                    inst.name, val_str
                                                );
                                                bad = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                                Encode::Field(f) => {
                                    let mask_str = f.should_be_mask.as_str().unwrap_or("");
                                    let val_str  = f.value.as_str().unwrap_or("");

                                    // A field is architecturally forced concrete when:
                                    //   (a) should_be_mask is all-ones for the width, OR
                                    //   (b) the value string is fully specified (no 'x').
                                    let mask_forces_concrete = !mask_str.is_empty()
                                        && mask_str.len() == f.range.width as usize
                                        && mask_str.chars().all(|c| c == '1');

                                    let val_fully_specified = !val_str.is_empty()
                                        && !val_str.contains('x')
                                        && val_str.len() == f.range.width as usize;

                                    if mask_forces_concrete || val_fully_specified {
                                        if val_str.is_empty() || val_str.contains('x') {
                                            // Mask forces concrete but value is not clean: use 0.
                                            segs.push(InstructionSegment::Concrete(
                                                B129::new(0, f.range.width),
                                            ));
                                        } else {
                                            match u64::from_str_radix(val_str, 2) {
                                                Ok(val) => segs.push(InstructionSegment::Concrete(
                                                    B129::new(val, f.range.width),
                                                )),
                                                Err(_) => {
                                                    eprintln!(
                                                        "Skipping {}: bad Field value '{}' for {}",
                                                        inst.name, val_str, f.name
                                                    );
                                                    bad = true;
                                                    break;
                                                }
                                            }
                                        }
                                    } else {
                                        // Symbolic field. Detect duplicate name with a different
                                        // width, which would panic in instruction_to_val.
                                        let field_name = f.name.to_string();
                                        if let Some(&prev_width) = seen_fields.get(&field_name) {
                                            if prev_width != f.range.width {
                                                // Different width: concrete-zero to avoid the panic.
                                                segs.push(InstructionSegment::Concrete(
                                                    B129::new(0, f.range.width),
                                                ));
                                                current_bit -= f.range.width as i64;
                                                continue;
                                            }
                                            // Same width duplicate shares the SMT variable — OK.
                                        } else {
                                            seen_fields.insert(field_name, f.range.width);
                                        }
                                        segs.push(InstructionSegment::Symbolic(
                                            f.name.to_string(),
                                            f.range.width,
                                        ));
                                    }
                                }
                            }

                            current_bit -= range.width as i64;
                        }

                        // Fill any remaining bits down to bit 0.
                        if !bad && current_bit > 0 {
                            segs.push(InstructionSegment::Symbolic(
                                String::from("ignored"),
                                current_bit as u32,
                            ));
                        }

                        if bad {
                            continue 'inst_loop;
                        }

                        // Validate total width is exactly 32 bits.
                        let total: u32 = segs.iter().map(|s| match s {
                            InstructionSegment::Concrete(bv) => bv.len(),
                            InstructionSegment::Symbolic(_, w) => *w,
                        }).sum();

                        if total != 32 {
                            eprintln!(
                                "Skipping {}: segment total is {} bits, expected 32",
                                inst.name, total
                            );
                            continue 'inst_loop;
                        }

                        segs
                    };

                    // --- Human-friendly debug output ---
                    println!("\n=======================================================");
                    println!("INSTRUCTION: {} | MODE: {}", inst.name, el_name);
                    let mut bits_constructed = 0u32;
                    for seg in &segments {
                        match seg {
                            InstructionSegment::Concrete(bv) => {
                                println!("    - Concrete: {} (len: {})", bv, bv.len());
                                bits_constructed += bv.len();
                            }
                            InstructionSegment::Symbolic(name, size) => {
                                println!("    - Symbolic: {} (len: {})", name, size);
                                bits_constructed += size;
                            }
                        }
                    }
                    println!("    -> Total Bits: {}", bits_constructed);
                    println!("=======================================================");

                    // ---------------------------------------------------------
                    // ---------------------------------------------------------
                    // MRS/MSR SWEEP: instead of pinning the system-register
                    // selector to one register (NZCV), expand each systemmove
                    // instruction into one variant per curated context-switch
                    // register. Each variant pins (op0,op1,CRn,CRm,op2) to that
                    // register and is written under its own synthetic name
                    // ("MRS_RS_systemmove@TTBR0_EL1", ...), so the parser records
                    // each register's per-EL accessibility and footprint
                    // separately. Every non-systemmove instruction runs as a
                    // single pass-through variant.
                    //
                    // (label, op0, op1, CRn, CRm, op2). op0 is 2 or 3; the
                    // encoding's o0 field is op0 & 1.
                    let cs_sysregs: &[(&str, u64, u64, u64, u64, u64)] = &[
                        // EL0/EL1 context
                        ("NZCV",          3, 3, 4,  2, 0),
                        ("DAIF",          3, 3, 4,  2, 1),
                        ("FPCR",          3, 3, 4,  4, 0),
                        ("FPSR",          3, 3, 4,  4, 1),
                        ("TPIDR_EL0",     3, 3, 13, 0, 2),
                        ("TPIDRRO_EL0",   3, 3, 13, 0, 3),
                        ("SCTLR_EL1",     3, 0, 1,  0, 0),
                        ("CPACR_EL1",     3, 0, 1,  0, 2),
                        ("TTBR0_EL1",     3, 0, 2,  0, 0),
                        ("TTBR1_EL1",     3, 0, 2,  0, 1),
                        ("TCR_EL1",       3, 0, 2,  0, 2),
                        ("SPSR_EL1",      3, 0, 4,  0, 0),
                        ("ELR_EL1",       3, 0, 4,  0, 1),
                        ("SP_EL0",        3, 0, 4,  1, 0),
                        ("ESR_EL1",       3, 0, 5,  2, 0),
                        ("FAR_EL1",       3, 0, 6,  0, 0),
                        ("MAIR_EL1",      3, 0, 10, 2, 0),
                        ("AMAIR_EL1",     3, 0, 10, 3, 0),
                        ("VBAR_EL1",      3, 0, 12, 0, 0),
                        ("CONTEXTIDR_EL1",3, 0, 13, 0, 1),
                        ("TPIDR_EL1",     3, 0, 13, 0, 4),
                        ("MDSCR_EL1",     2, 0, 0,  2, 2),
                        // EL2 context
                        ("SCTLR_EL2",     3, 4, 1,  0, 0),
                        ("HCR_EL2",       3, 4, 1,  1, 0),
                        ("MDCR_EL2",      3, 4, 1,  1, 1),
                        ("CPTR_EL2",      3, 4, 1,  1, 2),
                        ("TTBR0_EL2",     3, 4, 2,  0, 0),
                        ("TCR_EL2",       3, 4, 2,  0, 2),
                        ("VTTBR_EL2",     3, 4, 2,  1, 0),
                        ("VTCR_EL2",      3, 4, 2,  1, 2),
                        ("SPSR_EL2",      3, 4, 4,  0, 0),
                        ("ELR_EL2",       3, 4, 4,  0, 1),
                        ("SP_EL1",        3, 4, 4,  1, 0),
                        ("ESR_EL2",       3, 4, 5,  2, 0),
                        ("FAR_EL2",       3, 4, 6,  0, 0),
                        ("MAIR_EL2",      3, 4, 10, 2, 0),
                        ("VBAR_EL2",      3, 4, 12, 0, 0),
                        // EL3 context
                        ("SCTLR_EL3",     3, 6, 1,  0, 0),
                        ("SCR_EL3",       3, 6, 1,  1, 0),
                        ("CPTR_EL3",      3, 6, 1,  1, 2),
                        ("TTBR0_EL3",     3, 6, 2,  0, 0),
                        ("TCR_EL3",       3, 6, 2,  0, 2),
                        ("SPSR_EL3",      3, 6, 4,  0, 0),
                        ("ELR_EL3",       3, 6, 4,  0, 1),
                        ("SP_EL2",        3, 6, 4,  1, 0),
                        ("ESR_EL3",       3, 6, 5,  2, 0),
                        ("FAR_EL3",       3, 6, 6,  0, 0),
                        ("MAIR_EL3",      3, 6, 10, 2, 0),
                        ("VBAR_EL3",      3, 6, 12, 0, 0),
                    ];
                    let inst_is_sysmove = inst.name.to_lowercase().contains("systemmove");

                    // Each run variant carries: (name-suffix, sysreg-selector,
                    // GPR base address, header VA-tag). The name-suffix is only
                    // non-empty for the MRS/MSR sweep (the parser keys
                    // MRS_RS_systemmove@REG on it); the VA-tag is a header-only
                    // annotation (NOT part of the name) so the high-VA pass's
                    // register reads merge into the SAME instruction footprint.
                    const LOW_VA_BASE: u64 = 0x0060_0000; // TTBR0 region (top VA bit 0)
                    let variants: Vec<(String, Option<(u64, u64, u64, u64, u64)>, u64, &'static str)> =
                        if inst_is_sysmove {
                            // System-register move: one variant per curated reg,
                            // always at the low base (MRS/MSR translate no data
                            // address, so the high-VA pass would add nothing).
                            cs_sysregs
                                .iter()
                                .map(|(lbl, op0, op1, crn, crm, op2)| {
                                    (format!("@{}", lbl), Some((*op0 & 1, *op1, *crn, *crm, *op2)), LOW_VA_BASE, "")
                                })
                                .collect()
                        } else if high_va_probe && is_memory_instruction(inst) {
                            // Memory instruction with the probe on: run it twice.
                            // Pass 1 (low base) exercises the TTBR0 walk; pass 2
                            // (high base) exercises the TTBR1 walk so TTBR1_ELx is
                            // read. Same name => both passes' reads merge.
                            vec![
                                (String::new(), None, LOW_VA_BASE, ""),
                                (String::new(), None, high_va_base, " | VA: high"),
                            ]
                        } else {
                            vec![(String::new(), None, LOW_VA_BASE, "")]
                        };

                    for (variant_label, selector, variant_base, va_tag) in &variants {

                    // STEP 2: Build per-instruction SMT constraints and
                    // concretize fields that cause path explosion or UNDEFINED
                    // decode paths when left fully symbolic.
                    //
                    //  (1) MRS/MSR system-register operand fields -> NZCV
                    //      (S3_3_C4_C2_0), readable/writable from every EL, not
                    //      the unallocated all-zero register (which threw
                    //      Error_Undefined at sysregs.sail:937 at all ELs).
                    //  (2) `option` -> 0b011 (LSL/UXTX); option<1>=='0' is
                    //      UNALLOCATED for register-offset addressing forms.
                    //  (3) Register-index fields -> {x0,x1,x2}. Three values keep
                    //      the path count low while still satisfying the pairwise-
                    //      distinct requirements of SETP/SETM/SETE/CPY*.
                    //  (4) Load/store offset immediates (imm7/imm9/imm12) -> 0 so
                    //      the effective address equals the (now-concrete, aligned)
                    //      base register. Footprint-invariant; eliminates the
                    //      Device-memory alignment fork that throws at
                    //      builtins.sail:52.
                    //  (5) Rt2 added to the constrained register set so paired
                    //      loads/stores don't leave the second transfer register
                    //      fully symbolic (or get silently zeroed into Rt).
                    // ---------------------------------------------------------
                    let mut local_constraints = constraints.clone();
                    let mut modified_segments: Vec<InstructionSegment<B129>> = Vec::new();
                    // Track which symbolic names have already been concretized so
                    // that duplicate field names are handled consistently.
                    let mut concretized: std::collections::HashSet<String> =
                        std::collections::HashSet::new();

                    let is_sysmove = inst.name.to_lowercase().contains("systemmove");

                    for seg in &segments {
                        match seg {
                            InstructionSegment::Concrete(_) => {
                                modified_segments.push(seg.clone());
                            }
                            InstructionSegment::Symbolic(name, size) => {
                                let n = name.to_lowercase();

                                if concretized.contains(name) {
                                    modified_segments.push(InstructionSegment::Concrete(
                                        B129::new(0, *size),
                                    ));
                                    continue;
                                }

                                // (1) MRS/MSR system-register selector. For a
                                // sysmove sweep variant, pin (op0,op1,CRn,CRm,op2)
                                // to the curated register this variant targets.
                                // The encoding's o0 field is op0 & 1; a full "op0"
                                // field (if present) is 1:o0 = o0 | 0b10.
                                if is_sysmove {
                                    if let Some((o0, op1v, crnv, crmv, op2v)) = selector {
                                        let v: Option<u64> = match n.as_str() {
                                            "o0"  => Some(*o0),
                                            "op0" => Some(*o0 | 0b10),
                                            "op1" => Some(*op1v),
                                            "op2" => Some(*op2v),
                                            "crn" => Some(*crnv),
                                            "crm" => Some(*crmv),
                                            _ => None,
                                        };
                                        if let Some(v) = v {
                                            modified_segments.push(InstructionSegment::Concrete(
                                                B129::new(v, *size),
                                            ));
                                            concretized.insert(name.clone());
                                            continue;
                                        }
                                    }
                                }

                                // (2) option (extend type) in register-offset
                                // loads/stores: option<1>=='0' is UNALLOCATED.
                                if n == "option" && *size == 3 {
                                    modified_segments.push(InstructionSegment::Concrete(
                                        B129::new(0b011, 3),
                                    ));
                                    concretized.insert(name.clone());
                                    continue;
                                }

                                // Fields concrete-zeroed to prevent path explosion
                                // or UNDEFINED decode forks:
                                //
                                //  op0/op1/op2/op3/opc  — system-register op fields
                                //    OUTSIDE the MRS/MSR case above (e.g. MSR-imm).
                                //  crn/crm              — same, non-systemmove cases.
                                //  imms/immr/imm6/shift — bitfield immediate indexes;
                                //    out-of-range values produce UNDEFINED decode.
                                //  cond                 — condition code (keeps 1 path).
                                //  imm7/imm9/imm12      — load/store offsets, so the
                                //    effective address == aligned base register.
                                let must_concrete_zero = matches!(
                                    n.as_str(),
                                    "o0" | "op0" | "op1" | "op2" | "op3" | "opc"
                                    | "crn" | "crm"
                                    | "imms" | "immr" | "imm6" | "shift"
                                    | "cond"
                                    | "imm7" | "imm9" | "imm12"
                                );

                                if must_concrete_zero {
                                    modified_segments.push(InstructionSegment::Concrete(
                                        B129::new(0, *size),
                                    ));
                                    concretized.insert(name.clone());
                                    continue;
                                }

                                // (3)+(5) Register-index fields at width 5
                                // (Rn/Rm/Rt/Rt2/Ra/Rs/Rd): constrain to {x0,x1,x2}.
                                // Register 31 (XZR/SP) has special decoding in many
                                // instructions and is deliberately excluded.
                                if *size == 5
                                    && matches!(n.as_str(),
                                        "rn" | "rm" | "rt" | "rt2" | "ra" | "rs" | "rd")
                                {
                                    local_constraints.push(format!(
                                        "(or (= {} #b00000) (= {} #b00001) (= {} #b00010))",
                                        name, name, name
                                    ));
                                    modified_segments.push(seg.clone());
                                    continue;
                                }

                                // All other fields pass through as symbolic.
                                modified_segments.push(seg.clone());
                            }
                        }
                    }

                    // ---------------------------------------------------------
                    // STEP 3: Set up PSTATE / exception level and auxiliary
                    // system register state for clean symbolic execution.
                    //
                    // CPACR_EL1 (FP/SIMD enable), CPTR_EL2/3, SCTLR_ELx and the
                    // FEAT_*/vXApY feature switches live in the ISA config
                    // (armv9p4.toml) — the proper place for whole-register
                    // defaults applied before symbolic execution starts.
                    // ---------------------------------------------------------
                    let pstate_reg = shared_state.symtab.lookup(&zencode::encode("PSTATE"));
                    let el_field   = shared_state.symtab.lookup(&zencode::encode("EL"));

                    let mut local_reset_registers = reset_registers.clone();

                    // Set the exception level being tested.
                    local_reset_registers.insert(
                        Loc::Field(Box::new(Loc::Id(pstate_reg)), el_field),
                        Arc::new(move |_, _, _| Ok(Val::Bits(B129::new(el_val, el_width)))),
                    );

                    // PSTATE.PAN = 0  (Privileged Access Never)
                    let pan_field = shared_state.symtab.lookup(&zencode::encode("PAN"));
                    local_reset_registers.insert(
                        Loc::Field(Box::new(Loc::Id(pstate_reg)), pan_field),
                        Arc::new(|_, _, _| Ok(Val::Bits(B129::new(0, 1)))),
                    );

                    // PSTATE.UAO = 0  (User Access Override)
                    let uao_field = shared_state.symtab.lookup(&zencode::encode("UAO"));
                    local_reset_registers.insert(
                        Loc::Field(Box::new(Loc::Id(pstate_reg)), uao_field),
                        Arc::new(|_, _, _| Ok(Val::Bits(B129::new(0, 1)))),
                    );

                    // PSTATE.SSBS = 1  (Speculative Store Bypass Safe)
                    let ssbs_field = shared_state.symtab.lookup(&zencode::encode("SSBS"));
                    local_reset_registers.insert(
                        Loc::Field(Box::new(Loc::Id(pstate_reg)), ssbs_field),
                        Arc::new(|_, _, _| Ok(Val::Bits(B129::new(1, 1)))),
                    );

                    // Pin every GPR (and the per-EL stack pointers) to a single
                    // page-aligned, mapped address. With the MMU off, data
                    // accesses are Device-nGnRnE and alignment-strict regardless
                    // of SCTLR.A, so a symbolic base forks an Alignment-fault path
                    // that throws at builtins.sail:52. A fixed aligned base (plus
                    // the imm7/imm9/imm12 -> 0 concretization in STEP 2) removes
                    // that fork without changing which registers the instruction
                    // reads/writes. The zero region (guaranteed above) makes the
                    // backing data concrete.
                    //
                    // STEP 5: the base is per-variant. The low base (TTBR0 region)
                    // is used for every instruction; --high-va-probe adds a second
                    // pass for memory ops with a TTBR1-region base so the walk
                    // reads TTBR1_ELx. `*variant_base` is LOW_VA_BASE or
                    // high_va_base depending on the variant.
                    let data_base: u64 = *variant_base; // 4 KiB-aligned, mapped
                    for i in 0..=30u32 {
                        let r = shared_state.symtab.lookup(&zencode::encode(&format!("R{}", i)));
                        local_reset_registers.insert(
                            Loc::Id(r),
                            Arc::new(move |_, _, _| Ok(Val::Bits(B129::new(data_base, 64)))),
                        );
                    }
                    for sp in &["SP_EL0", "SP_EL1", "SP_EL2", "SP_EL3"] {
                        if let Some(r) = shared_state.symtab.get(&zencode::encode(sp)) {
                            local_reset_registers.insert(
                                Loc::Id(r),
                                Arc::new(move |_, _, _| Ok(Val::Bits(B129::new(data_base, 64)))),
                            );
                        }
                    }

                    // Pin the SIMD/FP register file to a concrete value. Symbolic
                    // FP arithmetic blows up the SMT solver (the FADD/FMUL/FDIV/
                    // FSQRT/FCVT families showed up as Timeout/ExecErr at the ELs
                    // where FP was actually enabled). Concrete inputs make those
                    // ops complete and expose their real sysreg footprint (FPCR
                    // read / FPSR write -- both context-switch state).
                    //
                    // NOTE: this assumes the model exposes individual V0..V31 as
                    // bits(128) registers. If your model stores SIMD state as a
                    // single `_V` vector register, these lookups return None and
                    // do nothing -- the vector register would have to be pinned
                    // instead (tell me its name and I'll adjust this loop).
                    for i in 0..=31u32 {
                        if let Some(r) =
                            shared_state.symtab.get(&zencode::encode(&format!("V{}", i)))
                        {
                            local_reset_registers.insert(
                                Loc::Id(r),
                                Arc::new(|_, _, _| Ok(Val::Bits(B129::new(0, 128)))),
                            );
                        }
                    }

                    // ---------------------------------------------------------
                    // STEP 4: Build the SMT solver state and record register
                    // assumptions. PSTATE is skipped so our per-EL reset_registers
                    // settings take precedence over the model's defaults.
                    // ---------------------------------------------------------
                    let (initial_checkpoint, opcode_val) = {
                        let solver_cfg = smt::Config::new();
                        let solver_ctx = smt::Context::new(solver_cfg);
                        let mut solver =
                            Solver::from_checkpoint(&solver_ctx, elf_checkpoint.clone());

                        let opcode_val = instruction_to_val(
                            &modified_segments,
                            &local_constraints,
                            &mut solver,
                        );

                        let mut sorted_regs: Vec<(&Name, &Register<_>)> =
                            regs.iter().collect();
                        sorted_regs.sort_by_key(|(name, _)| *name);

                        for (name, reg) in sorted_regs {
                            // Skip the global PSTATE assumption so our EL/flag
                            // settings don't conflict with the model's defaults.
                            if *name != pstate_reg {
                                if let Some(value) = reg.read_last_if_initialized() {
                                    solver.add_event(Event::AssumeReg(
                                        *name,
                                        vec![],
                                        value.clone(),
                                    ));
                                }
                            }
                        }

                        (smt::checkpoint(&mut solver), opcode_val)
                    };

                    // ---------------------------------------------------------
                    // STEP 5: Execute and collect traces.
                    // ---------------------------------------------------------
                    let function_id = shared_state.symtab.lookup(&footprint_function);
                    let (args, ret_ty, instrs) =
                        shared_state.functions.get(&function_id).unwrap();

                    let task_state =
                        TaskState::new().with_reset_registers(local_reset_registers);

                    let mut task = LocalFrame::new(
                        function_id,
                        args,
                        ret_ty,
                        Some(&[opcode_val.clone()]),
                        instrs,
                    )
                    .add_lets(lets)
                    .add_regs(regs)
                    .set_memory(memory.clone())
                    .task_with_checkpoint(TaskId::fresh(), &task_state, initial_checkpoint);

                    task.set_stop_conditions(&stop_conditions);

                    let queue = Arc::new(SegQueue::new());
                    executor::start_multi(
                        num_threads,
                        timeout,
                        vec![task],
                        shared_state,
                        queue.clone(),
                        &executor::trace_collector,
                    );

                    loop {
                        match queue.pop() {
                            Some(Ok((_, mut events))) => {
                                let throw_location: Option<String> = events.iter().find_map(|e| {
                                    if let Event::WriteReg(name, _, Val::String(s)) = e {
                                        if *name == isla_lib::ir::THROW_LOCATION { return Some(s.clone()); }
                                    }
                                    None
                                });

                                if matches.opt_present("simplify") {
                                    simplify::hide_initialization(&mut events);
                                    simplify::remove_unused(&mut events);
                                    simplify::propagate_forwards_used_once(&mut events);
                                    simplify::commute_extract(&mut events);
                                    simplify::eval(&mut events);
                                }
                                let events: Vec<Event<B129>> = events.drain(..).rev().collect();
                                writeln!(
                                    &mut handle,
                                    "\n--- Instruction: {}{} | Mode: {}{} | throw_at: {:?} ---",
                                    inst.name, variant_label, el_name, va_tag, throw_location
                                )
                                .unwrap();
                                simplify::write_events_with_opts(
                                    &mut handle,
                                    &events,
                                    shared_state,
                                    &write_opts,
                                )
                                .unwrap();
                                handle.flush().unwrap();
                            }
                            // Executor failures (timeouts, internal errors, dead
                            // tasks) are NOT model throws. Label them EXEC_ERR so
                            // downstream CSV aggregation can distinguish "the model
                            // raised an architectural exception" (throw_at above)
                            // from "isla could not finish this path".
                            Some(Err(err)) => {
                                writeln!(
                                    &mut handle,
                                    "\n--- Instruction: {}{} | Mode: {}{} | EXEC_ERR: {} ---",
                                    inst.name, variant_label, el_name, va_tag, err
                                ).unwrap();
                                handle.flush().unwrap();
                            }
                            None => break,
                        }
                    }
                    } // end variant loop (MRS/MSR sweep + low/high-VA address probe)
                } // 'inst_loop
            }
        }

        println!("All EL processing done");
        return 0;
    }
    // ---------------------------------------------------------------------
    // SINGLE-INSTRUCTION PATH (unchanged)
    // ---------------------------------------------------------------------

    let (initial_checkpoint, opcode_val) = {
        let solver_cfg = smt::Config::new();
        let solver_ctx = smt::Context::new(solver_cfg);
        let mut solver = Solver::from_checkpoint(&solver_ctx, elf_checkpoint);
        let opcode_val =
            if have_elf { elf_opcode_val.unwrap() } else { instruction_to_val(&opcode, &constraints, &mut solver) };
        let mut sorted_regs: Vec<(&Name, &Register<_>)> = regs.iter().collect();
        sorted_regs.sort_by_key(|(name, _)| *name);
        for (name, reg) in sorted_regs {
            if let Some(value) = reg.read_last_if_initialized() {
                solver.add_event(Event::AssumeReg(*name, vec![], value.clone()))
            }
        }
        (smt::checkpoint(&mut solver), opcode_val)
    };
    let function_id = shared_state.symtab.lookup(&footprint_function);
    let (args, ret_ty, instrs) = shared_state.functions.get(&function_id).unwrap();
    let task_state = TaskState::new().with_reset_registers(reset_registers);
    let mut task = LocalFrame::new(function_id, args, ret_ty, Some(&[opcode_val.clone()]), instrs)
        .add_lets(lets)
        .add_regs(regs)
        .set_memory(memory)
        .task_with_checkpoint(TaskId::fresh(), &task_state, initial_checkpoint);
    task.set_stop_conditions(&stop_conditions);
    let queue = Arc::new(SegQueue::new());
    let now = Instant::now();
    executor::start_multi(num_threads, timeout, vec![task], shared_state, queue.clone(), &executor::trace_collector);
    log!(log::VERBOSE, &format!("Execution took: {}ms", now.elapsed().as_millis()));
    let mut paths = Vec::new();
    let mut evtree: Option<EventTree<B129>> = None;
    let write_opts = WriteOpts {
        define_enum: !matches.opt_present("simplify"),
        hide_uninteresting: matches.opt_present("hide"),
        ..WriteOpts::default()
    };
    loop {
        match queue.pop() {
            Some(Ok((_, mut events))) if matches.opt_present("dependency") => {
                let mut events: EvPath<B129> = events
                    .drain(..)
                    .rev()
                    .filter(|ev| {
                        (ev.is_memory_read_or_write() && !ev.is_ifetch())
                            || ev.is_smt()
                            || ev.is_instr()
                            || ev.is_cycle()
                            || ev.is_write_reg()
                    })
                    .collect();
                simplify::remove_unused(&mut events);
                events.push(Event::Instr(opcode_val.clone()));
                paths.push(events)
            }
            Some(Ok((_, mut events))) if matches.opt_present("tree") => {
                let events: Vec<Event<B129>> = events.drain(..).rev().collect();
                if let Some(ref mut evtree) = evtree {
                    evtree.add_events(&events)
                } else {
                    evtree = Some(EventTree::from_events(&events))
                }
            }
            Some(Ok((_, mut events))) => {
                if matches.opt_present("simplify") {
                    simplify::hide_initialization(&mut events);
                    if matches.opt_present("simplify-registers") {
                        simplify::remove_extra_register_fields(&mut events);
                        simplify::remove_repeated_register_reads(&mut events);
                        simplify::remove_unused_register_assumptions(&mut events);
                    }
                    simplify::remove_unused(&mut events);
                    simplify::propagate_forwards_used_once(&mut events);
                    simplify::commute_extract(&mut events);
                    if matches.opt_present("eval-carefully") {
                        simplify::eval_carefully(&mut events);
                    } else {
                        simplify::eval(&mut events);
                    }
                }
                let events: Vec<Event<B129>> = events.drain(..).rev().collect();
                let stdout = std::io::stdout();
                let mut handle = BufWriter::with_capacity(5 * usize::pow(2, 20), stdout.lock());
                simplify::write_events_with_opts(&mut handle, &events, shared_state, &write_opts).unwrap();
                handle.flush().unwrap()
            }
            Some(Err(err)) => {
                let msg = format!("{}", err);
                eprintln!(
                    "{}",
                    err.source_loc().message(source_path.as_ref(), shared_state.symtab.files(), &msg, true, true)
                );
                if !matches.opt_present("continue-on-error") {
                    return 1;
                }
            }
            None => break,
        }
    }
    if matches.opt_present("tree") {
        if let Some(ref mut evtree) = evtree {
            evtree.sort();
            evtree.renumber();
            if matches.opt_present("simplify") {
                simplify::hide_initialization_tree(evtree);
                if matches.opt_present("simplify-registers") {
                    simplify::remove_extra_register_fields_tree(evtree);
                    simplify::remove_repeated_register_reads_tree(evtree);
                    simplify::remove_unused_register_assumptions_tree(evtree);
                }
                simplify::remove_unused_tree(evtree);
                simplify::propagate_forwards_used_once_tree(evtree);
                simplify::commute_extract_tree(evtree);
                if matches.opt_present("eval-carefully") {
                    simplify::eval_carefully_tree(evtree);
                } else {
                    simplify::eval_tree(evtree);
                }
            }
            if matches.opt_present("executable") {
                evtree.make_executable()
            }
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            simplify::write_event_tree(&mut handle, evtree, shared_state, &write_opts);
            writeln!(&mut handle).unwrap();
        }
    }
    if matches.opt_present("dependency") {
        match footprint_analysis(num_threads, &[paths], &iarch_config, None) {
            Ok(footprints) => {
                for (_, footprint) in footprints {
                    {
                        let stdout = std::io::stdout();
                        let mut handle = stdout.lock();
                        let _ = footprint.pretty(&mut handle, &shared_state.symtab);
                    }
                }
            }
            Err(footprint_error) => {
                eprintln!("{:?}", footprint_error);
                return 1;
            }
        }
    }
    0
}
