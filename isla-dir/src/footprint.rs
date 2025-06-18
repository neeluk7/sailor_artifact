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
use sha2::digest::generic_array::iter;
use sha2::{Digest, Sha256};
use core::num;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::process::exit;
use std::str::Split;
use std::sync::Arc;
use std::time::Instant;

use isla_axiomatic::footprint_analysis::footprint_analysis;
use isla_axiomatic::footprint_analysis::{Footprint, Footprintkey};
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
use isla_lib::simplify::{EventTree, WriteOpts, EventReferences};
use isla_lib::smt;
use isla_lib::smt::{smtlib, Checkpoint, EvPath, Event, Solver, Sym};
use isla_lib::smt_parser;
use isla_lib::source_loc::SourceLoc;
use isla_lib::zencode;

//use isla::sailor::{generate_rvi_itype_opcode_vec, generate_rvi_rtype_opcode_vec};

mod opts;
use opts::CommonOpts;

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

fn create_opcode_from_vec_rtype(opcode_vec: Vec<u64>) -> Vec<InstructionSegment<B129>> {
    (vec![InstructionSegment::Concrete(B129::new(opcode_vec[6], 7)), InstructionSegment::Concrete(B129::new(opcode_vec[5], 5)), InstructionSegment::Concrete(B129::new(opcode_vec[4], 5)), InstructionSegment::Concrete(B129::new(opcode_vec[3], 3)), InstructionSegment::Concrete(B129::new(opcode_vec[2], 5)),  InstructionSegment::Concrete(B129::new(opcode_vec[1], 5)), InstructionSegment::Concrete(B129::new(opcode_vec[0], 2))])
}

fn create_opcode_from_vec_itype(opcode_vec: Vec<u64>) -> Vec<InstructionSegment<B129>> {
    (vec![InstructionSegment::Concrete(B129::new(opcode_vec[5], 12)), InstructionSegment::Concrete(B129::new(opcode_vec[4], 5)), InstructionSegment::Concrete(B129::new(opcode_vec[3], 3)), InstructionSegment::Concrete(B129::new(opcode_vec[2], 5)),  InstructionSegment::Concrete(B129::new(opcode_vec[1], 5)), InstructionSegment::Concrete(B129::new(opcode_vec[0], 2))])
}


fn is_binary_string(s: &str) -> bool {
    s.chars().all(|c| c == '0' || c == '1')
}

fn extract_integers(s: &str) -> Vec<u64> {
    let mut numbers = Vec::new();
    let mut current_number = String::new();

    for c in s.chars() {
        if c.is_digit(10) {
            current_number.push(c);
        } else if !current_number.is_empty() {
            numbers.push(current_number.parse::<u64>().unwrap());
            current_number.clear();
        }
    }

    if !current_number.is_empty() {
        numbers.push(current_number.parse::<u64>().unwrap());
    }
    for num in &numbers {
        println!("Number for imm: {}", num);
    }
    numbers
}

fn find_min_max(numbers: &[u64]) -> (u64, u64) {
    let mut min = 33;
    let mut max = 0;

    for num in numbers {
        if *num < min {
            min = *num;
        }
        if *num > max {
            max = *num;
        }
    }
    (min, max)
}

fn find_imm_len(s: &str) -> u64 {

    if s.contains(",") {
        let mut imm_len: u64 = 0;
        let split_str = s.split(",");
        for st in split_str {
            let numbers = extract_integers(st);
            if numbers.len() == 1 {
                imm_len = imm_len + 1;
            }
            else {
                let (min, max) = find_min_max(&numbers);
                imm_len = imm_len + max - min + 1;
            }
        }

        (imm_len)

    } else {
        let (min, max) = find_min_max(&extract_integers(s));
        (max - min + 1)
    }
}

fn parse_opcode_from_spec(line: &str) -> Vec<Vec<InstructionSegment<B129>>> {
    let mut opcodes: Vec<Vec<InstructionSegment<B129>>> = vec![];

    let words: Vec<&str> = line.split("|").collect();
    let mut instr_name: &str = words[words.len()-1];
    let mut has_rd: bool = false;   // always at 7-11
    let mut has_rs1: bool = false;  // always at 15-19
    let mut has_rs2: bool = false;  // always at 20-24
    let mut has_rs3: bool = false;  // always at 27-31
    let mut has_fm: bool = false;   // always at 28-31
    let mut imm_id: u64 = 0;
    let mut has_rm: bool = false;   // always at 12-14
    // let has_imm: bool = false;  // always closer towards the msb, msb is the sign bit
    // let imm_start: u64 = 0;
    // let imm_end: u64 = 0;
    // let has_second_imm: bool = false;
    // let second_imm_start: u64 = 0;
    // let second_imm_end: u64 = 0;
    // let has_shamt: u64 = 0;     // It has to be the lower imm... always starting from 20...

    let mut bits_constructed: u64 = 0;

    let mut constructed_opcode: Vec<InstructionSegment<B129>> = vec![];

    // Need a bit of preprocessing..... for the ones with imm [ | | | ]


    for i in (0..words.len()-1) {
        let words_split: Vec<&str> = words[i].split(" ").collect();
        let field: &str = words_split[0];
        println!("{}",field);

        if is_binary_string(field) {
            // calc len and add concrete segment
            // opcode... vs. funct3... vs. funct7...
            let val = match u64::from_str_radix(field, 2) {
                Ok(int_val) => (int_val),
                Err(_) => 0,
            };
            constructed_opcode.push(InstructionSegment::Concrete((B129::new(val, field.len().try_into().unwrap()))));
            bits_constructed = bits_constructed + (field.len() as u64);

            if bits_constructed == 32 {
                break;
            }

        } else if field.contains("imm") {
            // decode the size and add symbolic segment

            // let indices = extract_integers(field);
            // let (min, max) = find_min_max(&indices);

            // println!(" min: {} max: {}", min, max);

            let imm_len = find_imm_len(field);

            constructed_opcode.push(InstructionSegment::Symbolic(String::from("imm".to_owned()+&(imm_id.to_string())), (imm_len).try_into().unwrap()));
            bits_constructed = bits_constructed + (imm_len);
            imm_id = imm_id + 1;

        } // RD, RS1, and RS2 are always at fixed places in the instruction... i.e. 7..11, 15..19, 20..24.
        else if field.contains("rd") {
            println!("Bits: {}",bits_constructed);
            assert!(32 - bits_constructed == 12);
            has_rd = true;
            constructed_opcode.push(InstructionSegment::Concrete((B129::new(0x0, 5))));
            bits_constructed = bits_constructed + 5;

        } else if field.contains("rs1") {
            println!("Bits: {}",bits_constructed);
            assert!(32 - bits_constructed == 20);
            has_rs1 = true;
            constructed_opcode.push(InstructionSegment::Concrete((B129::new(0x0, 5))));
            bits_constructed = bits_constructed + 5;

        } else if field.contains("rs2") {
            println!("Bits: {}",bits_constructed);
            assert!(32 - bits_constructed == 25);
            has_rs2 = true;
            constructed_opcode.push(InstructionSegment::Concrete((B129::new(0x0, 5))));
            bits_constructed = bits_constructed + 5;

        } else if field.contains("shamt") {
            if bits_constructed == 6 {
                constructed_opcode.push(InstructionSegment::Symbolic(String::from("shamt"), 6));
                bits_constructed = bits_constructed + 6;
            } else if bits_constructed == 7 {
                constructed_opcode.push(InstructionSegment::Symbolic(String::from("shamt"), 5));
                bits_constructed = bits_constructed + 5;
            } else {
                println!("{}",instr_name);
                assert!(false);
            }

        } else if field.contains("aq") {
            assert!(bits_constructed == 5);
            constructed_opcode.push(InstructionSegment::Symbolic(String::from("aquire"), 1));
            bits_constructed = bits_constructed + 1;

        } else if field.contains("rl") {
            assert!(bits_constructed == 6);
            constructed_opcode.push(InstructionSegment::Symbolic(String::from("release"), 1));
            bits_constructed = bits_constructed + 1;

        } else if field.contains("fm") {
            assert!(bits_constructed == 0);
            has_fm = true;
            constructed_opcode.push(InstructionSegment::Concrete((B129::new(0x0, 4))));
            bits_constructed = bits_constructed + 4;
            //assert!(false); // TODO

        } else if field.contains("pred") {
            assert!(bits_constructed == 4);
            constructed_opcode.push(InstructionSegment::Symbolic(String::from("pred"), 4));
            bits_constructed = bits_constructed + 4;
            //assert!(false); // TODO

        } else if field.contains("succ") {
            assert!(bits_constructed == 8);
            constructed_opcode.push(InstructionSegment::Symbolic(String::from("succ"), 4));
            bits_constructed = bits_constructed + 4;
            //assert!(false); // TODO

        } else if field.contains("rs3") {
            assert!(bits_constructed == 0);
            has_rs3 = true;
            constructed_opcode.push(InstructionSegment::Concrete((B129::new(0x0, 5))));
            bits_constructed = bits_constructed + 5;

        } else if field.contains("rm") {
            //assert!(bits_constructed == 5);
            has_rm = true;
            constructed_opcode.push(InstructionSegment::Concrete((B129::new(0x0, 3))));
            bits_constructed = bits_constructed + 3;
        } else if field.contains("uimm") {
            assert!(false); // TODO
        }

    }

    if bits_constructed != 32 {
        println!("Instruction: {}",instr_name);
        println!("Bits: {}",bits_constructed);
        assert!(false);
    }

    opcodes.push(constructed_opcode.clone());

    if has_rd {
        // complete for x10
        let mut new_opcode = constructed_opcode.clone();
        new_opcode[constructed_opcode.len() - 2] = InstructionSegment::Concrete((B129::new(0xa, 5)));
        opcodes.push(new_opcode);
    }

    if has_rs1 {
        // complete for x0 - this is not needed... it's already happening with the previous condition.
        // for opcode in opcodes {
        //     if opcode == constructed_opcode {
        //         continue;
        //     }
        //     let mut new_opcode = opcode.clone();
        //     new_opcode[new_opcode.len() - 4] = InstructionSegment::Concrete((B129::new(0x0, 5)));
        //     opcodes.push(new_opcode);
        // }
        // complete for x11
        for opcode in opcodes.clone() {
            let mut new_opcode = opcode.clone();
            new_opcode[opcode.len() - 4] = InstructionSegment::Concrete((B129::new(0xb, 5)));
            opcodes.push(new_opcode);
        }
    }

    if has_rs2 {
        for opcode in opcodes.clone() {
            let mut new_opcode = opcode.clone();
            new_opcode[opcode.len() - 5] = InstructionSegment::Concrete((B129::new(0xc, 5)));
            opcodes.push(new_opcode);
        }
    }

    if has_rs3 {
        for opcode in opcodes.clone() {
            let mut new_opcode = opcode.clone();
            new_opcode[0] = InstructionSegment::Concrete((B129::new(0xd, 5)));
            opcodes.push(new_opcode);
        }
    }

    if has_fm {
        for opcode in opcodes.clone() {
            let mut new_opcode = opcode.clone();
            new_opcode[0] = InstructionSegment::Concrete((B129::new(0b1000, 4)));   //TSO ...
            opcodes.push(new_opcode);
        }
    }

    if has_rm {
        let rm_values = [0x1, 0x2, 0x3, 0x4];
        let mut new_opcodes: Vec<Vec<InstructionSegment<B129>>> = vec![];
        for val in rm_values {
            for opcode in opcodes.clone() {
                let mut new_opcode = opcode.clone();
                new_opcode[opcode.len() - 3] = InstructionSegment::Concrete((B129::new(val, 3)));
                new_opcodes.push(new_opcode);
            }
        }
        for opcode in new_opcodes {
            opcodes.push(opcode);
        }
    }

    println!("INSTRUCTION CONSTRUCTED: {}: rd: {} rs1: {} rs2: {} rs3: {} fm: {} opcodes_vec_len: {}", instr_name, has_rd, has_rs1, has_rs2, has_rs3, has_fm, opcodes.len());

    (opcodes)
}

fn isla_main() -> i32
{
    let now = Instant::now();

    let mut opts = opts::common_opts();
    opts.reqopt("i", "instruction", "display footprint of instruction", "<instruction>");
    opts.optopt("n", "all_rv_i_instructions", "display footprint of all rv_i instructions", "<riscv-opcodes file>");
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

    // Note this is the opposite default to other tools
    let assertion_mode =
        if matches.opt_present("pessimistic") { AssertionMode::Pessimistic } else { AssertionMode::Optimistic };

    let use_model_reg_init = !matches.opt_present("no-model-reg-init");
    let iarch = initialize_architecture(&mut arch, symtab, type_info, &isa_config, assertion_mode, use_model_reg_init);
    let iarch_config = InitArchWithConfig::from_initialized(&iarch, &isa_config);
    let regs = &iarch.regs;
    let lets = &iarch.lets;
    let shared_state = &&iarch.shared_state;

    // println!("Assinging cur_priv...\n");
    // regs.assign(cur_privilege, "Supervisor", *shared_state);
    // println!("Done assinging cur_priv...\n");

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

    let instruction = matches.opt_str("instruction").unwrap();

    let mut reset_registers: HashMap<Loc<Name>, Reset<B129>> = HashMap::new();
    let mut constraints: Vec<String> = matches.opt_strs("instruction-constraint");

    let mut instrs_lines = "".split("");
    let mut opcode: Vec<InstructionSegment<B129>> = vec![InstructionSegment::Concrete(B129::new(0x30200073, 32))];  //Neelu: default value = mret!
    let mut contents = String::new();

    if let Some(rv_i_opcode_file) = matches.opt_str("n").as_deref() {
        println!("RV_I option selected!");
        //exit(0);
        match File::open(rv_i_opcode_file) {
            Ok(mut handle) => match handle.read_to_string(&mut contents) {
                Ok(_) => {
                    // Temporary...
                    //println!("{}", contents);
                    instrs_lines = contents.split("\n");
                    // for line in instrs_lines {
                    //     println!("{}", line);
                    //     println!("..");
                    // }
                    //(vec![InstructionSegment::Concrete(B129::new(0x4, 12)), InstructionSegment::Concrete(B129::new(0xb, 5)), InstructionSegment::Concrete(B129::new(0x0, 3)), InstructionSegment::Concrete(B129::new(0xa, 5)),  InstructionSegment::Concrete(B129::new(0xb, 7))])
                },
                Err(e) => {
                    eprintln!("Unexpected error when reading opcode from {}: {}", rv_i_opcode_file, e);
                    return 1;
                }
            },
            Err(e) => {
                eprintln!("Failed to open opcode file: {}", e);
                return 1;
            }
        }

    } else {
        opcode = if matches.opt_present("partial") {
        println!("opcodes partial.");
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
        println!("opcodes from file.");
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
        println!("opcodes hex.");
        match hex_bytes(&instruction) {
            Ok(opcode) => vec![InstructionSegment::Concrete(opcode_bytes(opcode, little_endian))],
            Err(e) => {
                eprintln!("Could not parse hexadecimal opcode: {}", e);
                exit(1)
            }
        }
    } else if matches.opt_present("elf") {
        println!("opcodes elf.");
        Vec::new()
    }
    // else if let Some(rv_i_opcode_file) = matches.opt_str("n").as_deref() {
    //     println!("RV_I option selected!");
    //     //exit(0);
    //     let mut contents = String::new();
    //     match File::open(rv_i_opcode_file) {
    //         Ok(mut handle) => match handle.read_to_string(&mut contents) {
    //             Ok(_) => {
    //                 // Temporary...
    //                 //println!("{}", contents);
    //                 let instrs_lines = contents.split("\n");
    //                 for line in instrs_lines {
    //                     println!("{}", line);
    //                     println!("..");
    //                 }
    //                 //(vec![InstructionSegment::Concrete(B129::new(0x4, 12)), InstructionSegment::Concrete(B129::new(0xb, 5)), InstructionSegment::Concrete(B129::new(0x0, 3)), InstructionSegment::Concrete(B129::new(0xa, 5)),  InstructionSegment::Concrete(B129::new(0xb, 7))])
    //             },
    //             Err(e) => {
    //                 eprintln!("Unexpected error when reading opcode from {}: {}", rv_i_opcode_file, e);
    //                 return 1;
    //             }
    //         },
    //         Err(e) => {
    //             eprintln!("Failed to open opcode file: {}", e);
    //             return 1;
    //         }
    //     }

    //     //println!("{}", contents);

    //     // Temporary...
    //     (vec![InstructionSegment::Concrete(B129::new(0x4, 12)), InstructionSegment::Concrete(B129::new(0xb, 5)), InstructionSegment::Concrete(B129::new(0x0, 3)), InstructionSegment::Concrete(B129::new(0xa, 5)),  InstructionSegment::Concrete(B129::new(0xb, 7))])

    // }
    else {
        print!("Assembling instruction!");
        match assemble_instruction(&instruction, &isa_config) {
            Ok(opcode) => vec![InstructionSegment::Concrete(opcode_bytes(opcode, little_endian))],
            //Ok(opcode) => vec![InstructionSegment::Concrete(B129::new(0x3020007, 28)), InstructionSegment::Symbolic(String::from("ins"), 2), InstructionSegment::Concrete(B129::new(0x3, 2))], // This works for mret.

            //Ok(opcode) => vec![InstructionSegment::Symbolic(String::from("imm"), 12), InstructionSegment::Concrete(B129::new(0xb, 5)), InstructionSegment::Concrete(B129::new(0x0, 3)), InstructionSegment::Concrete(B129::new(0xa, 5)),  InstructionSegment::Concrete(B129::new(0xb, 7))],
            //Ok(opcode) => vec![InstructionSegment::Symbolic(String::from("imm"), 12), InstructionSegment::Symbolic(String::from("rs1"), 5), InstructionSegment::Concrete(B129::new(0x0, 3)), InstructionSegment::Concrete(B129::new(0xa, 5)),  InstructionSegment::Concrete(B129::new(0xb, 7))],

            // All symbolic
            //Ok(opcode) => vec![InstructionSegment::Symbolic(String::from("imm"), 12), InstructionSegment::Symbolic(String::from("rs1"), 5), InstructionSegment::Concrete(B129::new(0x0, 3)), InstructionSegment::Symbolic(String::from("rd"), 5),  InstructionSegment::Concrete(B129::new(0b0010011, 7))],

            //Ok(opcode) => vec![InstructionSegment::Concrete(B129::new(0x4, 12)), InstructionSegment::Concrete(B129::new(0xb, 5)), InstructionSegment::Concrete(B129::new(0x0, 3)), InstructionSegment::Concrete(B129::new(0xa, 5)),  InstructionSegment::Concrete(B129::new(0xb, 7))],

            //Ok(opcode) => vec![InstructionSegment::Symbolic(String::from("ins"), 17), InstructionSegment::Concrete(B129::new(0xb, 15))], // --- too big of a search space
            //Ok(opcode) => vec![InstructionSegment::Symbolic(String::from("ins"), 1), InstructionSegment::Concrete(B129::new(0x30200073, 31))], // 0..14 == 0xb -- addi // --- nope
            Err(msg) => {
                eprintln!("{}", msg);
                return 1;
            }
        }
    };
    }

    // if matches.opt_present("n") {
    //     println!("RV_I option selected!");
    // }

    if !matches.opt_present("elf") {
        log!(log::VERBOSE, &format!("opcode: {}", instruction_to_string(&opcode)));
        println!("opcode: {}", instruction_to_string(&opcode));
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

    //// This if not -n
    if !matches.opt_present("n") {
    let (initial_checkpoint, opcode_val) = {
        let solver_cfg = smt::Config::new();
        let solver_ctx = smt::Context::new(solver_cfg);
        let mut solver = Solver::from_checkpoint(&solver_ctx, elf_checkpoint);
        let opcode_val =
            if have_elf { elf_opcode_val.unwrap() } else { instruction_to_val(&opcode, &constraints, &mut solver) };
        // Record register assumptions from defaults; others are recorded at reset-registers
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
                // Traces can be large, so use a 5MB buffer
                let mut handle = BufWriter::with_capacity(5 * usize::pow(2, 20), stdout.lock());
                simplify::write_events_with_opts(&mut handle, &events, shared_state, &write_opts).unwrap();
                handle.flush().unwrap()
            }
            // Error during execution
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
            // Empty queue
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
                println!("Cannot print footprint pretty.");
                eprintln!("{:?}", footprint_error);
                return 1;
            }
        }
    }
    } else {
        //// Loop the above if -n is used... the following is for riscv-opcodes/extensions/rv_i, etc. files.
        // for line in instrs_lines {

        //     let mut opcode_vec;

        //     if line.contains("1..0") {
        //         if line.contains("pseudo_op") {
        //             continue;
        //         } else if line.contains("31..25") {
        //             opcode_vec = generate_rvi_rtype_opcode_vec(line);
        //             opcode = create_opcode_from_vec_rtype(opcode_vec);
        //         } else if line.contains("14..12") {
        //             opcode_vec = generate_rvi_itype_opcode_vec(line);
        //             opcode = create_opcode_from_vec_itype(opcode_vec);
        //         }
        //         else {
        //             continue;
        //         }
        //         // So in some cases the above will generate errors.. e.g. j-type
        //     } else {
        //         continue;
        //     }

        //     let (initial_checkpoint, opcode_val) = {
        //         let solver_cfg = smt::Config::new();
        //         let solver_ctx = smt::Context::new(solver_cfg);
        //         let mut solver = Solver::from_checkpoint(&solver_ctx, elf_checkpoint.clone());
        //         let opcode_val = instruction_to_val(&opcode, &constraints, &mut solver);
        //         // Record register assumptions from defaults; others are recorded at reset-registers
        //         let mut sorted_regs: Vec<(&Name, &Register<_>)> = regs.iter().collect();
        //         sorted_regs.sort_by_key(|(name, _)| *name);
        //         for (name, reg) in sorted_regs {
        //             if let Some(value) = reg.read_last_if_initialized() {
        //                 solver.add_event(Event::AssumeReg(*name, vec![], value.clone()))
        //             }
        //         }
        //         (smt::checkpoint(&mut solver), opcode_val)
        //     };

        //     let function_id = shared_state.symtab.lookup(&footprint_function);
        //     let (args, ret_ty, instrs) = shared_state.functions.get(&function_id).unwrap();
        //     let task_state = TaskState::new().with_reset_registers(reset_registers.clone());
        //     let mut task = LocalFrame::new(function_id, args, ret_ty, Some(&[opcode_val.clone()]), instrs)
        //         .add_lets(lets)
        //         .add_regs(regs)
        //         .set_memory(memory.clone())
        //         .task_with_checkpoint(TaskId::fresh(), &task_state, initial_checkpoint);
        //     task.set_stop_conditions(&stop_conditions);

        //     let queue = Arc::new(SegQueue::new());

        //     let now = Instant::now();
        //     executor::start_multi(num_threads, timeout, vec![task], shared_state, queue.clone(), &executor::trace_collector);
        //     log!(log::VERBOSE, &format!("Execution took: {}ms", now.elapsed().as_millis()));

        //     let mut paths = Vec::new();
        //     let mut evtree: Option<EventTree<B129>> = None;

        //     let write_opts = WriteOpts {
        //         define_enum: !matches.opt_present("simplify"),
        //         hide_uninteresting: matches.opt_present("hide"),
        //         ..WriteOpts::default()
        //     };

        //     loop {
        //         match queue.pop() {
        //             Some(Ok((_, mut events))) if matches.opt_present("dependency") => {
        //                 let mut events: EvPath<B129> = events
        //                     .drain(..)
        //                     .rev()
        //                     .filter(|ev| {
        //                         (ev.is_memory_read_or_write() && !ev.is_ifetch())
        //                             || ev.is_smt()
        //                             || ev.is_instr()
        //                             || ev.is_cycle()
        //                             || ev.is_write_reg()
        //                     })
        //                     .collect();
        //                 simplify::remove_unused(&mut events);
        //                 events.push(Event::Instr(opcode_val.clone()));
        //                 paths.push(events)
        //             }
        //             Some(Ok((_, mut events))) if matches.opt_present("tree") => {
        //                 let events: Vec<Event<B129>> = events.drain(..).rev().collect();
        //                 if let Some(ref mut evtree) = evtree {
        //                     evtree.add_events(&events)
        //                 } else {
        //                     evtree = Some(EventTree::from_events(&events))
        //                 }
        //             }
        //             Some(Ok((_, mut events))) => {
        //                 if matches.opt_present("simplify") {
        //                     simplify::hide_initialization(&mut events);
        //                     if matches.opt_present("simplify-registers") {
        //                         simplify::remove_extra_register_fields(&mut events);
        //                         simplify::remove_repeated_register_reads(&mut events);
        //                         simplify::remove_unused_register_assumptions(&mut events);
        //                     }
        //                     simplify::remove_unused(&mut events);
        //                     simplify::propagate_forwards_used_once(&mut events);
        //                     simplify::commute_extract(&mut events);
        //                     if matches.opt_present("eval-carefully") {
        //                         simplify::eval_carefully(&mut events);
        //                     } else {
        //                         simplify::eval(&mut events);
        //                     }
        //                 }
        //                 let events: Vec<Event<B129>> = events.drain(..).rev().collect();
        //                 let stdout = std::io::stdout();
        //                 // Traces can be large, so use a 5MB buffer
        //                 let mut handle = BufWriter::with_capacity(5 * usize::pow(2, 20), stdout.lock());
        //                 simplify::write_events_with_opts(&mut handle, &events, shared_state, &write_opts).unwrap();
        //                 handle.flush().unwrap()
        //             }
        //             // Error during execution
        //             Some(Err(err)) => {
        //                 let msg = format!("{}", err);
        //                 eprintln!(
        //                     "{}",
        //                     err.source_loc().message(source_path.as_ref(), shared_state.symtab.files(), &msg, true, true)
        //                 );
        //                 if !matches.opt_present("continue-on-error") {
        //                     return 1;
        //                 }
        //             }
        //             // Empty queue
        //             None => break,
        //         }
        //     }

        //     if matches.opt_present("tree") {
        //         if let Some(ref mut evtree) = evtree {
        //             evtree.sort();
        //             evtree.renumber();
        //             if matches.opt_present("simplify") {
        //                 simplify::hide_initialization_tree(evtree);
        //                 if matches.opt_present("simplify-registers") {
        //                     simplify::remove_extra_register_fields_tree(evtree);
        //                     simplify::remove_repeated_register_reads_tree(evtree);
        //                     simplify::remove_unused_register_assumptions_tree(evtree);
        //                 }
        //                 simplify::remove_unused_tree(evtree);
        //                 simplify::propagate_forwards_used_once_tree(evtree);
        //                 simplify::commute_extract_tree(evtree);
        //                 if matches.opt_present("eval-carefully") {
        //                     simplify::eval_carefully_tree(evtree);
        //                 } else {
        //                     simplify::eval_tree(evtree);
        //                 }
        //             }
        //             if matches.opt_present("executable") {
        //                 evtree.make_executable()
        //             }
        //             let stdout = std::io::stdout();
        //             let mut handle = stdout.lock();
        //             simplify::write_event_tree(&mut handle, evtree, shared_state, &write_opts);
        //             writeln!(&mut handle).unwrap();
        //         }
        //     }

        //     if matches.opt_present("dependency") {
        //         match footprint_analysis(num_threads, &[paths], &iarch_config, None) {
        //             Ok(footprints) => {
        //                 for (_, footprint) in footprints {
        //                     {
        //                         let stdout = std::io::stdout();
        //                         let mut handle = stdout.lock();
        //                         let _ = footprint.pretty(&mut handle, &shared_state.symtab);
        //                     }
        //                 }
        //             }
        //             Err(footprint_error) => {
        //                 println!("Cannot print footprint pretty.");
        //                 eprintln!("{:?}", footprint_error);
        //                 return 1;
        //             }
        //         }
        //     }

        // }

        //println!("Len of instruction_lines: {} ",instrs_lines.clone().count());
        let mut iterations = instrs_lines.clone().count();
        for line in instrs_lines {

            iterations = iterations - 1;
            if iterations == 0 {
                break;
            }

            println!("{}",line);
            let processed_line = line.replace("\\|", ",");
            println!("INSTR-LINE: {}", processed_line);
            let opcodes_to_explore: Vec<Vec<InstructionSegment<B129>>> = parse_opcode_from_spec(&processed_line);

            for opcode in opcodes_to_explore {

            let (initial_checkpoint, opcode_val) = {
                let solver_cfg = smt::Config::new();
                let solver_ctx = smt::Context::new(solver_cfg);
                let mut solver = Solver::from_checkpoint(&solver_ctx, elf_checkpoint.clone());
                let opcode_val = instruction_to_val(&opcode, &constraints, &mut solver);
                // Record register assumptions from defaults; others are recorded at reset-registers
                let mut sorted_regs: Vec<(&Name, &Register<_>)> = regs.iter().collect();
                sorted_regs.sort_by_key(|(name, _)| *name);
                for (name, reg) in sorted_regs {
                    if let Some(value) = reg.read_last_if_initialized() {
                        println!("Adding AssumeReg event for {}", *name);
                        solver.add_event(Event::AssumeReg(*name, vec![], value.clone()))
                    }
                }
                (smt::checkpoint(&mut solver), opcode_val)
            };

            let function_id = shared_state.symtab.lookup(&footprint_function);
            let (args, ret_ty, instrs) = shared_state.functions.get(&function_id).unwrap();
            let task_state = TaskState::new().with_reset_registers(reset_registers.clone());
            let mut task = LocalFrame::new(function_id, args, ret_ty, Some(&[opcode_val.clone()]), instrs)
                .add_lets(lets)
                .add_regs(regs)
                .set_memory(memory.clone())
                .task_with_checkpoint(TaskId::fresh(), &task_state, initial_checkpoint);
            task.set_stop_conditions(&stop_conditions);

            //let mut B = BV::new(0, 32); // Neelu: IDK if this is correct!

            //let mut footprint_buckets: Vec<Vec<EvPath<B>>> = vec![Vec::new(); 1];   //there is only 1 task

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
                        //footprint_buckets[opcode_val.clone()].push(events);
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
                                println!(" **** Simplifying registers **** ");
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
                        // Traces can be large, so use a 5MB buffer
                        let mut handle = BufWriter::with_capacity(5 * usize::pow(2, 20), stdout.lock());
                        simplify::write_events_with_opts(&mut handle, &events, shared_state, &write_opts).unwrap();
                        handle.flush().unwrap()
                    }
                    // Error during execution
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
                    // Empty queue
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

            // if matches.opt_present("dependency") {
            //     let mut footprints = HashMap::new();
            //     let num_footprints: usize = footprint_buckets.iter().map(|instr_paths| instr_paths.len()).sum();
            //     log!(log::VERBOSE, &format!("There are {} footprints", num_footprints));

            //     for (i, paths) in footprint_buckets.iter().enumerate() {
            //         let opcode = opcode_val;
            //         log!(log::VERBOSE, &format!("{:?}", opcode));

            //         let mut footprint = Footprint::new();

            //         for events in paths {
            //             let evrefs = EventReferences::from_events(events);
            //             let mut forks: Vec<Sym> = Vec::new();
            //             let mut intrinsic_data: HashMap<Sym, HashSet<RegisterField>> = HashMap::new();
            //             let mut intrinsic_ctrl: HashSet<RegisterField> = HashSet::new();
            //             for event in events {
            //                 match event {
            //                     // Event::Smt(smtlib::Def::DefineConst(v, exp), _, _) => {
            //                     //     let mut register_data: HashSet<RegisterField> = HashSet::new();
            //                     //     for v in exp.variables() {
            //                     //         register_data.extend(intrinsic_data.get(&v).into_iter().flatten().cloned())
            //                     //     }
            //                     //     intrinsic_data.insert(*v, register_data);
            //                     // }
            //                     // Event::Fork(_, v, _, _) => {
            //                     //     forks.push(*v);
            //                     //     intrinsic_ctrl.extend(intrinsic_data.get(v).into_iter().flatten().cloned());
            //                     // }
            //                     Event::ReadReg(rd_reg, accessor, val) if !iarch_config.isa_config.ignored_registers.contains(&rd_reg) => {
            //                         footprint.register_reads.insert((*rd_reg, accessor.clone()));
            //                         // let vars = val.symbolic_variables();
            //                         // for v in vars {
            //                         //     let reg_taints = intrinsic_data.entry(v).or_default();
            //                         //     reg_taints.insert((*rd_reg, accessor.clone()));
            //                         // }
            //                     }
            //                     Event::WriteReg(wr_reg, accessor, data) if !iarch_config.isa_config.ignored_registers.contains(&wr_reg) => {
            //                         footprint.register_writes.insert((*wr_reg, accessor.clone()));
            //                         // If the data written to the register is tainted by a value read
            //                         // from memory record this fact.
            //                         if evrefs.value_taints(data, events).memory {
            //                             footprint.register_writes_tainted.insert((*wr_reg, accessor.clone()));
            //                         }
            //                     }
            //                     Event::MarkReg { regs, mark } => {
            //                         if mark == "pick" && regs.len() == 1 {
            //                             let picks = footprint.register_pick_deps.entry(regs[0]).or_default();
            //                             picks.extend(intrinsic_ctrl.iter().cloned())
            //                         } else if mark == "ignore_write" && regs.len() == 1 {
            //                             footprint.register_writes_ignored.insert((None, regs[0]));
            //                         } else if mark == "ignore_edge" && regs.len() == 2 {
            //                             footprint.register_writes_ignored.insert((Some(regs[0]), regs[1]));
            //                         }
            //                     }
            //                     Event::ReadMem { address, .. } => {
            //                         footprint.is_load = true;
            //                         if event.is_exclusive() {
            //                             footprint.is_exclusive = true;
            //                         }
            //                         evrefs.collect_value_taints(address, events, &mut footprint.mem_addr_taints)
            //                     }
            //                     Event::WriteMem { address, data, .. } => {
            //                         footprint.is_store = true;
            //                         if event.is_exclusive() {
            //                             footprint.is_exclusive = true;
            //                         }
            //                         evrefs.collect_value_taints(address, events, &mut footprint.mem_addr_taints);
            //                         evrefs.collect_value_taints(data, events, &mut footprint.write_data_taints);
            //                     }
            //                     Event::AddressAnnounce { address } => {
            //                         evrefs.collect_value_taints(address, events, &mut footprint.mem_addr_taints);
            //                     }
            //                     Event::Branch { address } => {
            //                         footprint.is_branch = true;
            //                         evrefs.collect_value_taints(address, events, &mut footprint.branch_addr_taints);
            //                         for v in &forks {
            //                             evrefs.collect_taints(*v, events, &mut footprint.branch_addr_taints)
            //                         }
            //                     }
            //                     Event::Abstract { name, .. }
            //                         if iarch_config.shared_state.symtab.to_str(*name) == "zsail_system_register_write" =>
            //                     {
            //                         footprint.is_system_register_write = true
            //                     }
            //                     _ => (),
            //                 }
            //             }
            //         }

            //         footprints.insert(opcode, footprint);
            //     }
            //     for (_, footprint) in footprints {
            //         {
            //             let stdout = std::io::stdout();
            //             let mut handle = stdout.lock();
            //             let _ = footprint.pretty(&mut handle, &shared_state.symtab);
            //         }
            //     }
            // }

            }
        }

    }

    0
}
