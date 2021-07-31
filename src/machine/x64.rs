use std::convert::TryFrom;
use std::collections::HashMap;
use keystone::*;
use unicorn::unicorn_const::{Arch, Mode, Permission};
use capstone::prelude::*;

use super::interface::Machine;
use maplit::hashmap;

use crate::hexprint::Printer;
use crate::hexprint::BorderStyle;
use crate::machine::interrupt::InterruptX86;


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
    let mut unicorn = unicorn::Unicorn::new(Arch::X86, Mode::MODE_64)
        .expect("failed to initialize unicorn instance");
    let mut cpu = unicorn.borrow();
    cpu.reg_write(unicorn::RegisterX86::RSP as i32, STACK_TOP)
        .expect("failed to write esp");
    cpu.reg_write(unicorn::RegisterX86::RBP as i32, STACK_ADDR)
        .expect("failed to write ebp");
    cpu.reg_write(unicorn::RegisterX86::RDI as i32, DATA_ADDR)
        .expect("failed to write edi");
    cpu.reg_write(unicorn::RegisterX86::RSI as i32, DATA_ADDR)
        .expect("failed to write esi");
    cpu.reg_write(unicorn::RegisterX86::RIP as i32, CODE_ADDR)
        .expect("failed to write eip");

    cpu.mem_map(CODE_ADDR, usize::try_from(CODE_SIZE).unwrap(), Permission::ALL)
        .expect("failed to map code segment");
    cpu.mem_map(DATA_ADDR, usize::try_from(DATA_SIZE).unwrap(), Permission::ALL)
        .expect("failed to map data segment");
    cpu.mem_map(STACK_ADDR, usize::try_from(STACK_SIZE).unwrap(), Permission::ALL)
        .expect("failed to map stack segment");

    let context = cpu.context_alloc().ok();

    let _ = cpu.add_intr_hook(hook_intr).expect("failed to add intr hook");
    let _ = cpu.add_insn_sys_hook(unicorn::InsnSysX86::SYSCALL,
                                  CODE_ADDR,
                                  CODE_ADDR+CODE_SIZE-1,
                                  hook_syscall)
               .expect("failed to add syscall hook");

    let previous_reg_val_map = previous_reg_value_map(&cpu);
    let capstone = capstone_engine().unwrap();
    let keystone = keystone_engine().unwrap();

    Machine {
        register_map: reg_map,
        keystone,
        capstone,
        unicorn,
        sorted_reg_names: reg_names,
        word_size: WORD_SIZE,
        previous_reg_value: previous_reg_val_map,
        sp: unicorn::RegisterX86::RSP,
        ip: unicorn::RegisterX86::RIP,
        flags: unicorn::RegisterX86::EFLAGS,
        previous_inst_addr: vec![CODE_ADDR],
        code_addr: CODE_ADDR,
        code_size: CODE_SIZE,
        data_addr: DATA_ADDR,
        data_size: DATA_SIZE,
        stack_top: STACK_TOP,
        printer: Printer::new(true, BorderStyle::Unicode, false),
        context,
    }
}

fn hook_syscall(engine: unicorn::UnicornHandle) -> () {
    let reg_eip = engine.reg_read(unicorn::RegisterX86::EIP as i32)
        .expect("failed to read eip");
    let reg_eax = engine.reg_read(unicorn::RegisterX86::EAX as i32)
        .expect("failed to read eax");
    println!("SYSCALL #{:#04x} @ {:#010x}", reg_eax, reg_eip);

    if reg_eax == 0x80 {
    }

    ()
}

fn hook_intr(engine: unicorn::UnicornHandle, intno: u32) -> () {
    let reg_eip = engine.reg_read(unicorn::RegisterX86::EIP as i32)
        .expect("failed to read eip");
    let reg_eax = engine.reg_read(unicorn::RegisterX86::EAX as i32)
        .expect("failed to read eax");
    println!("INTERRUPT #{:#04x} '{}' @ {:#010x}",
             intno, InterruptX86{id: intno}, reg_eip);

    if reg_eax == 0x80 {
    }

    ()
}

fn keystone_engine() -> Result<keystone::Keystone,keystone::Error> {
    let engine = Keystone::new(keystone::Arch::X86, keystone::Mode::LITTLE_ENDIAN | keystone::Mode::MODE_64)?;

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
        "rax", "rbx", "rcx", "rdx", "end",
        "rsi", "rdi", "r8",  "r9", "end",
        "r10", "r11", "r12", "r13", "end",
        "r14", "r15", "rbp", "rsp", "end",
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

fn previous_reg_value_map(emu: &unicorn::UnicornHandle) -> HashMap<&'static str, u64> {
    let reg_names = sorted_reg_names();
    let register_map = init_register_map();
    reg_names
        .iter()
        .filter(|&&x| x != "end")
        .map(|&reg_name| {
            (
                reg_name,
                emu.reg_read(*register_map.get(reg_name).unwrap() as i32).unwrap(),
            )
        })
        .collect::<HashMap<_, _>>()
}
