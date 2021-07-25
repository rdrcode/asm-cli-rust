use keystone::*;
use std::collections::HashMap;
use unicorn::{Cpu, CpuX86};
use capstone::prelude::*;

use super::interface::Machine;
use maplit::hashmap;
use std::convert::TryFrom;

use crate::hexprint::Printer;
use crate::hexprint::BorderStyle;

const CODE_ADDR: u64 = 0x00400000;
const CODE_SIZE: u64 = 0x00100000;
const DATA_ADDR: u64 = CODE_ADDR + CODE_SIZE;
const DATA_SIZE: u64 = 0x00100000;
const STACK_ADDR: u64 = DATA_ADDR + DATA_SIZE;
const STACK_SIZE: u64 = 0x00100000;
const STACK_TOP:  u64 = STACK_ADDR + STACK_SIZE;
const WORD_SIZE: usize = 8;


pub fn new() -> Machine<'static> {
    let reg_map = init_register_map();
    let reg_names = sorted_reg_names();
    let cpu = unicorn_vm();
    let previous_reg_val_map = previous_reg_value_map(&cpu);
    let capstone = capstone_engine().unwrap();
    let keystone = keystone_engine().unwrap();

    Machine {
        register_map: reg_map,
        keystone,
        capstone,
        emu: cpu,
        sorted_reg_names: reg_names,
        word_size: WORD_SIZE,
        previous_reg_value: previous_reg_val_map,
        sp: unicorn::RegisterX86::RSP,
        ip: unicorn::RegisterX86::RIP,
        previous_inst_addr: vec![CODE_ADDR],
        code_addr: CODE_ADDR,
        code_size: CODE_SIZE,
        data_addr: DATA_ADDR,
        data_size: DATA_SIZE,
        stack_top: STACK_TOP,
        printer: Printer::new(true, BorderStyle::Unicode, false),
    }
}

fn unicorn_vm() -> CpuX86 {
    let cpu = CpuX86::new(unicorn::Mode::MODE_64).expect("failed to instantiate emulator");
    cpu.reg_write(unicorn::RegisterX86::RSP, STACK_TOP)
        .expect("failed to write rsp");
    cpu.reg_write(unicorn::RegisterX86::RBP, STACK_ADDR)
        .expect("failed to write rbp");
    cpu.reg_write(unicorn::RegisterX86::RDI, DATA_ADDR)
        .expect("failed to write rdi");
    cpu.reg_write(unicorn::RegisterX86::RSI, DATA_ADDR)
        .expect("failed to write rsi");
    cpu.reg_write(unicorn::RegisterX86::RIP, CODE_ADDR)
        .expect("failed to write rip");

    cpu.mem_map(CODE_ADDR, usize::try_from(CODE_SIZE).unwrap(), unicorn::Protection::ALL)
        .expect("failed to map code segment");
    cpu.mem_map(DATA_ADDR, usize::try_from(DATA_SIZE).unwrap(), unicorn::Protection::ALL)
        .expect("failed to map data segment");
    cpu.mem_map(STACK_ADDR, usize::try_from(STACK_SIZE).unwrap(), unicorn::Protection::ALL)
        .expect("failed to map stack segment");

    cpu
}

fn keystone_engine() -> Result<keystone::Keystone,keystone::Error> {
    let engine = Keystone::new(Arch::X86, Mode::LITTLE_ENDIAN | Mode::MODE_64)?;

    engine.option(OptionType::SYNTAX, OptionValue::SYNTAX_NASM)?;

    Ok(engine)
}

fn capstone_engine() -> Result<Capstone,capstone::Error> {
    let caps = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(false)
        .build()?;

    Ok(caps)
}

fn sorted_reg_names() -> Vec<&'static str> {
    vec![
        "rax", "rbx", "rcx", "rdx", "end", //
        "rsi", "rdi", "r8", "r9", "end", //
        "r10", "r11", "r12", "r13", "end", //
        "r14", "r15", "end", //
        "rip", "rbp", "rsp", "end", //
        "cs", "ss", "ds", "es", "end", //
        "fs", "gs", "end", "flags", "end", //
    ]
}

fn init_register_map() -> HashMap<&'static str, unicorn::RegisterX86> {
    hashmap! {
        "rax" =>  unicorn::RegisterX86::RAX,
        "rbx" => unicorn::RegisterX86::RBX,
        "rcx" => unicorn::RegisterX86::RCX,
        "rdx" => unicorn::RegisterX86::RDX,
        "rsi" => unicorn::RegisterX86::RSI,
        "rdi" => unicorn::RegisterX86::RDI,
        "r8" => unicorn::RegisterX86::R8,
        "r9" => unicorn::RegisterX86::R9,
        "r10" => unicorn::RegisterX86::R10,
        "r11" => unicorn::RegisterX86::R11,
        "r12" => unicorn::RegisterX86::R12,
        "r13" => unicorn::RegisterX86::R13,
        "r14" => unicorn::RegisterX86::R14,
        "r15" => unicorn::RegisterX86::R15,
        "rip" => unicorn::RegisterX86::RIP,
        "rbp" => unicorn::RegisterX86::RBP,
        "rsp" => unicorn::RegisterX86::RSP,
        "flags" => unicorn::RegisterX86::EFLAGS,
        "cs" => unicorn::RegisterX86::CS,
        "ss" => unicorn::RegisterX86::SS,
        "ds" => unicorn::RegisterX86::DS,
        "es" => unicorn::RegisterX86::ES,
        "fs" => unicorn::RegisterX86::FS,
        "gs" => unicorn::RegisterX86::GS,
    }
}

/*
fn init_register_map2() -> HashMap<&'static str, unicorn::RegisterX86> {
    vec![
        ("rax", unicorn::RegisterX86::RAX),
        ("rbx", unicorn::RegisterX86::RBX),
        ("rcx", unicorn::RegisterX86::RCX),
        ("rdx", unicorn::RegisterX86::RDX),
        ("rsi", unicorn::RegisterX86::RSI),
        ("rdi", unicorn::RegisterX86::RDI),
        ("r8", unicorn::RegisterX86::R8),
        ("r9", unicorn::RegisterX86::R9),
        ("r10", unicorn::RegisterX86::R10),
        ("r11", unicorn::RegisterX86::R11),
        ("r12", unicorn::RegisterX86::R12),
        ("r13", unicorn::RegisterX86::R13),
        ("r14", unicorn::RegisterX86::R14),
        ("r15", unicorn::RegisterX86::R15),
        ("rip", unicorn::RegisterX86::RIP),
        ("rbp", unicorn::RegisterX86::RBP),
        ("rsp", unicorn::RegisterX86::RSP),
        ("flags", unicorn::RegisterX86::EFLAGS),
        ("cs", unicorn::RegisterX86::CS),
        ("ss", unicorn::RegisterX86::SS),
        ("ds", unicorn::RegisterX86::DS),
        ("es", unicorn::RegisterX86::ES),
        ("fs", unicorn::RegisterX86::FS),
        ("gs", unicorn::RegisterX86::GS),
    ]
    .into_iter()
    .collect::<HashMap<_, _>>()
}
*/

fn previous_reg_value_map(emu: &CpuX86) -> HashMap<&'static str, u64> {
    let reg_names = sorted_reg_names();
    let register_map = init_register_map();
    reg_names
        .iter()
        .filter(|&&x| x != "end")
        .map(|&reg_name| {
            (
                reg_name,
                emu.reg_read(*register_map.get(reg_name).unwrap()).unwrap(),
            )
        })
        .collect::<HashMap<_, _>>()
}
