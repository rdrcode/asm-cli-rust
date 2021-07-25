use keystone::*;
use std::collections::HashMap;
use unicorn::{Cpu, CpuX86};
use capstone::prelude::*;

use super::interface::Machine;
use maplit::hashmap;
use std::convert::TryFrom;
use std::fmt;

use crate::hexprint::Printer;
use crate::hexprint::BorderStyle;

const CODE_ADDR: u64  = 0x08048000;
const CODE_SIZE: u64  = 0x00100000;
const DATA_ADDR: u64  = CODE_ADDR + CODE_SIZE;
const DATA_SIZE: u64  = 0x00100000;
const STACK_TOP:  u64 = 0xc0000000;
const STACK_SIZE: u64 = 0x00100000; // 1MByte
const STACK_ADDR: u64 = STACK_TOP - STACK_SIZE;

const WORD_SIZE: usize = 4;


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
        sp: unicorn::RegisterX86::ESP,
        ip: unicorn::RegisterX86::EIP,
        previous_inst_addr: vec![CODE_ADDR],
        code_addr: CODE_ADDR,
        code_size: CODE_SIZE,
        data_addr: DATA_ADDR,
        data_size: DATA_SIZE,
        stack_top: STACK_TOP,
        printer: Printer::new(true, BorderStyle::Unicode, false),
    }
}

pub struct Interrupt {
    id: u32,
}

impl fmt::Display for Interrupt {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self.id {
            0x00 => write!(fmt, "Division by zero"),
            0x01 => write!(fmt, "Single-step interrupt"),
            0x02 => write!(fmt, "NMI"),
            0x03 => write!(fmt, "Breakpoint"),
            0x04 => write!(fmt, "Overflow"),
            0x05 => write!(fmt, "Bound Range Exceeded"),
            0x06 => write!(fmt, "Invalid Opcode"),
            0x07 => write!(fmt, "Coprocessor not available"),
            0x08 => write!(fmt, "Double Fault"),
            0x09 => write!(fmt, "Coprocessor Segment Overrun"),
            0x0a => write!(fmt, "Invalid Task State Segment"),
            0x0b => write!(fmt, "Segment not present"),
            0x0c => write!(fmt, "Stack Segment Fault"),
            0x0d => write!(fmt, "General Protection Fault"),
            0x0e => write!(fmt, "Page Fault"),
            0x0f => write!(fmt, "Reserved"),
            0x10 => write!(fmt, "x87 Floating Point Exception"),
            0x11 => write!(fmt, "Alignment Check"),
            0x12 => write!(fmt, "Machine Check"),
            0x13 => write!(fmt, "SIMD Floating-Point Exception"),
            0x14 => write!(fmt, "Virtualization Exception"),
            0x15 => write!(fmt, "Control Protection Exception"),
            _    => write!(fmt, "Undefined Interrupt"),
        }
    }
}

fn hook_intr(engine: &unicorn::Unicorn, intno: u32) -> () {
    let reg_eip = engine.reg_read(unicorn::RegisterX86::EIP as i32)
        .expect("failed to read eip");
    let reg_eax = engine.reg_read(unicorn::RegisterX86::EAX as i32)
        .expect("failed to read eax");
    println!("INTERRUPT #{:#04x} '{}' @ {:#10x}",
             intno, Interrupt{id: intno}, reg_eip);

    if reg_eax == 0x80 {
    }

    ()
}

fn unicorn_vm() -> CpuX86 {
    let mut cpu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    cpu.reg_write(unicorn::RegisterX86::ESP, STACK_TOP)
        .expect("failed to write esp");
    cpu.reg_write(unicorn::RegisterX86::EBP, STACK_ADDR)
        .expect("failed to write ebp");
    cpu.reg_write(unicorn::RegisterX86::EDI, DATA_ADDR)
        .expect("failed to write edi");
    cpu.reg_write(unicorn::RegisterX86::ESI, DATA_ADDR)
        .expect("failed to write esi");
    cpu.reg_write(unicorn::RegisterX86::EIP, CODE_ADDR)
        .expect("failed to write eip");

    cpu.mem_map(CODE_ADDR, usize::try_from(CODE_SIZE).unwrap(), unicorn::Protection::ALL)
        .expect("failed to map code segment");
    cpu.mem_map(DATA_ADDR, usize::try_from(DATA_SIZE).unwrap(), unicorn::Protection::ALL)
        .expect("failed to map data segment");
    cpu.mem_map(STACK_ADDR, usize::try_from(STACK_SIZE).unwrap(), unicorn::Protection::ALL)
        .expect("failed to map stack segment");

    let regions = cpu
        .mem_regions()
        .expect("failed to retrieve memory mappings");
    println!("Regions: {}", regions.len());

    for region in &regions {
        println!("{:?}", region);
    }

    let _ = cpu
        .add_intr_hook(hook_intr)
        .expect("failed to add intr hook");

    cpu
}

fn keystone_engine() -> Result<keystone::Keystone,keystone::Error> {
    let engine = Keystone::new(Arch::X86, Mode::LITTLE_ENDIAN | Mode::MODE_32)?;

    engine.option(OptionType::SYNTAX, OptionValue::SYNTAX_NASM)?;

    Ok(engine)
}

fn capstone_engine() -> Result<Capstone,capstone::Error> {
    let caps = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode32)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(false)
        .build()?;

    Ok(caps)
}

fn sorted_reg_names() -> Vec<&'static str> {
    vec![
        "eax", "ebx", "ecx", "edx", "end", //
        "esi", "edi", "end", //
        "eip", "ebp", "esp", "end", //
        "flags", "end", //
        "cs", "ss", "ds", "es", "end", //
        "fs", "gs", "end", //
    ]
}

fn init_register_map() -> HashMap<&'static str, unicorn::RegisterX86> {
    hashmap! {
        "eax" => unicorn::RegisterX86::EAX,
        "ebx" => unicorn::RegisterX86::EBX,
        "ecx" => unicorn::RegisterX86::ECX,
        "edx" => unicorn::RegisterX86::EDX,
        "esi" => unicorn::RegisterX86::ESI,
        "edi" => unicorn::RegisterX86::EDI,
        "eip" => unicorn::RegisterX86::EIP,
        "ebp" => unicorn::RegisterX86::EBP,
        "esp" => unicorn::RegisterX86::ESP,
        "flags" => unicorn::RegisterX86::EFLAGS,
        "cs" => unicorn::RegisterX86::CS,
        "ss" => unicorn::RegisterX86::SS,
        "ds" => unicorn::RegisterX86::DS,
        "es" => unicorn::RegisterX86::ES,
        "fs" => unicorn::RegisterX86::FS,
        "gs" => unicorn::RegisterX86::GS,
    }
}

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
