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
use crate::machine::context::Context;

const CODE_ADDR:  u64 = 0x08048000;
const CODE_SIZE:  u64 = 0x00100000;
const DATA_ADDR:  u64 = CODE_ADDR + CODE_SIZE;
const DATA_SIZE:  u64 = 0x00100000;
const STACK_TOP:  u64 = 0xc0000000;
const STACK_SIZE: u64 = 0x00100000; // 1MByte
const STACK_ADDR: u64 = STACK_TOP - STACK_SIZE;

const WORD_SIZE: usize = 4;


pub fn new() -> Machine<'static> {
    let reg_map = init_register_map();
    let reg_names = sorted_reg_names();
    let mut unicorn = unicorn::Unicorn::new(Arch::X86, Mode::MODE_32)
        .expect("failed to initialize unicorn instance");
    let mut cpu = unicorn.borrow();
    cpu.reg_write(unicorn::RegisterX86::ESP as i32, STACK_TOP)
        .expect("failed to write esp");
    cpu.reg_write(unicorn::RegisterX86::EBP as i32, STACK_ADDR)
        .expect("failed to write ebp");
    cpu.reg_write(unicorn::RegisterX86::EDI as i32, DATA_ADDR)
        .expect("failed to write edi");
    cpu.reg_write(unicorn::RegisterX86::ESI as i32, DATA_ADDR)
        .expect("failed to write esi");
    cpu.reg_write(unicorn::RegisterX86::EIP as i32, CODE_ADDR)
        .expect("failed to write eip");

    cpu.mem_map(CODE_ADDR, usize::try_from(CODE_SIZE).unwrap(), Permission::ALL)
        .expect("failed to map code segment");
    cpu.mem_map(DATA_ADDR, usize::try_from(DATA_SIZE).unwrap(), Permission::ALL)
        .expect("failed to map data segment");
    cpu.mem_map(STACK_ADDR, usize::try_from(STACK_SIZE).unwrap(), Permission::ALL)
        .expect("failed to map stack segment");

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
        sp: unicorn::RegisterX86::ESP,
        ip: unicorn::RegisterX86::EIP,
        flags: unicorn::RegisterX86::EFLAGS,
        previous_inst_addr: vec![CODE_ADDR],
        code_addr: CODE_ADDR,
        code_size: CODE_SIZE,
        data_addr: DATA_ADDR,
        data_size: DATA_SIZE,
        stack_addr: STACK_ADDR,
        stack_size: STACK_SIZE,
       printer: Printer::new(true, BorderStyle::Unicode, false),
    }
}

pub fn new_from_context(context: &Context) -> Machine<'static> {
    let reg_map = init_register_map();
    let reg_names = sorted_reg_names();
    let mut unicorn = unicorn::Unicorn::new(Arch::X86, Mode::MODE_32)
        .expect("failed to initialize unicorn instance");
    let mut cpu = unicorn.borrow();
    cpu.reg_write(unicorn::RegisterX86::ESP as i32, context.stack_addr + context.stack_size)
        .expect("failed to write esp");
    cpu.reg_write(unicorn::RegisterX86::EBP as i32, context.stack_addr)
        .expect("failed to write ebp");
    cpu.reg_write(unicorn::RegisterX86::EDI as i32, context.data_addr)
        .expect("failed to write edi");
    cpu.reg_write(unicorn::RegisterX86::ESI as i32, context.data_addr)
        .expect("failed to write esi");
    cpu.reg_write(unicorn::RegisterX86::EIP as i32, context.code_addr)
        .expect("failed to write eip");

    cpu.mem_map(context.code_addr, usize::try_from(context.code_size).unwrap(), Permission::ALL)
        .expect("failed to map code segment");
    cpu.mem_map(context.data_addr, usize::try_from(context.data_size).unwrap(), Permission::ALL)
        .expect("failed to map data segment");
    cpu.mem_map(context.stack_addr, usize::try_from(context.stack_size).unwrap(), Permission::ALL)
        .expect("failed to map stack segment");

    let _ = cpu.add_intr_hook(hook_intr).expect("failed to add intr hook");
    let _ = cpu.add_insn_sys_hook(unicorn::InsnSysX86::SYSCALL,
                                  context.code_addr,
                                  context.code_addr+context.code_size-1,
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
        sp: unicorn::RegisterX86::ESP,
        ip: unicorn::RegisterX86::EIP,
        flags: unicorn::RegisterX86::EFLAGS,
        previous_inst_addr: vec![CODE_ADDR],
        code_addr: context.code_addr,
        code_size: context.code_size,
        data_addr: context.data_addr,
        data_size: context.data_size,
        stack_addr: context.stack_addr,
        stack_size: context.stack_size,
        printer: Printer::new(true, BorderStyle::Unicode, false),
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

//fn init_unicorn_vm(cpu: &unicorn::UnicornHandle) {

    //let regions = cpu
    //    .mem_regions()
    //    .expect("failed to retrieve memory mappings");
    //println!("Regions: {}", regions.len());

    //for region in &regions {
    //    println!("{:?}", region);
    //}

//}

fn keystone_engine() -> Result<keystone::Keystone,keystone::Error> {
    let engine = Keystone::new(keystone::Arch::X86, keystone::Mode::LITTLE_ENDIAN | keystone::Mode::MODE_32)?;

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
        "eax", "ebx", "ecx", "edx", "end",
        "esi", "edi", "ebp", "esp", "end",
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

#[cfg(test)]
mod tests {
    use unicorn::unicorn_const::{uc_error, Arch, HookType, MemType, Mode, Permission, SECOND_SCALE};
    use crate::machine;
    use crate::hexprint::Printer;
    use crate::hexprint::BorderStyle;

    pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
        ::std::slice::from_raw_parts(
            (p as *const T) as *const u8,
            ::std::mem::size_of::<T>(),
        )
    }

    //pub fn save_context(&self) {
    //    if let Some(context) = &self.context {
    //        let bytes: &[u8] = unsafe { Machine::<'a>::any_as_u8_slice(&context) };
    //        println!("{:?}", ::std::mem::size_of::<unicorn::Context>());
    //        println!("{:?}", bytes.len());
    //        println!("{:?}", bytes);
    //    }
    //}

    #[test]
    fn x86_context_save_and_restore() {
        //for mode in vec![Mode::MODE_32, Mode::MODE_64] {
        for mode in vec![Mode::MODE_32] {
            let x86_code: Vec<u8> = vec![
                0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05,
            ];
            let mut unicorn = unicorn::Unicorn::new(Arch::X86, mode)
                .expect("failed to initialize unicorn instance");
            let mut emu = unicorn.borrow();
            assert_eq!(emu.mem_map(0x1000, 0x4000, Permission::ALL), Ok(()));
            assert_eq!(emu.mem_write(0x1000, &x86_code), Ok(()));
            let _ = emu.emu_start(
                0x1000,
                (0x1000 + x86_code.len()) as u64,
                10 * SECOND_SCALE,
                1000,
            );

            /* now, save the context... */
            let context = emu.context_init();
            let context = context.unwrap();

            let bytes: &[u8] = unsafe { any_as_u8_slice(&context) };
            let mut printer = Printer::new(true, BorderStyle::Unicode, false);
            printer.print_all(bytes).unwrap();
            printer.reset();

            /* and create a new emulator, into which we will "restore" that context */
            let mut unicorn2 = unicorn::Unicorn::new(Arch::X86, mode)
                .expect("failed to initialize unicorn instance");
            let emu2 = unicorn2.borrow();
            assert_eq!(emu2.context_restore(&context), Ok(()));
            //for register in X86_REGISTERS.iter() {
            for register in machine::x32::init_register_map().values() {
                println!("Testing register {:?}", register);
                assert_eq!(
                    emu2.reg_read(*register as i32),
                    emu.reg_read(*register as i32)
                );
            }

            let context2 = emu2.context_init();
            let context2 = context2.unwrap();
            let bytes: &[u8] = unsafe { any_as_u8_slice(&context2) };
            printer.print_all(bytes).unwrap();
            printer.reset();
        }
    }
}
