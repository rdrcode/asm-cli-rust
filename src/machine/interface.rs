use ansi_term::Colour::{Blue, Yellow};
use keystone::AsmResult;
use std::convert::TryFrom;
use capstone::prelude::*;
use unicorn::unicorn_const::{Arch, Mode, Permission};
use keystone::*;
use anyhow::Result;
use thiserror::Error;
use indexmap::IndexMap;


use crate::hexprint::Printer;
use crate::hexprint::BorderStyle;
use crate::{emu_start,mem_map,mem_write,mem_read_as_vec,reg_read,reg_write};
use super::cpuarch::{self,CpuArch,Register,x86_32,x86_64};
use super::context::CpuContext;

/// ExecutionError enumerates all possible errors returned by this module
#[derive(Error, Debug)]
pub enum ExecutionError {
    /// Represents an internal error
    #[error("Internal error")]
    InternalError,

    /// Represents a Unicorn engine failure
    #[error("Unicorn engine error")]
    UnicornError,

    /// Represents a Capstone engine failure
    #[error("Capstone engine error")]
    CapstoneError,

    /// Represents a Keystone engine failure
    #[error("Keystone engine error")]
    KeystoneError,
}

pub struct Machine {
    pub keystone: keystone::Keystone,
    pub capstone: Capstone,
    pub unicorn: unicorn::Unicorn,
    pub word_size: usize,
    pub regs_values: IndexMap<Register, u64>,
    pub sp: unicorn::RegisterX86,
    pub ip: unicorn::RegisterX86,
    pub flags: unicorn::RegisterX86,
    pub previous_inst_addr: Vec<u64>,
    pub code_addr: u64,
    pub code_size: u64,
    pub data_addr: u64,
    pub data_size: u64,
    pub stack_addr: u64,
    pub stack_size: u64,
    pub printer: Printer,
}

impl Machine {

    pub fn new(arch: CpuArch) -> Result<Machine> {
        let cpu_context = match arch {
            CpuArch::X86_32 => CpuContext::new()
                                .arch(CpuArch::X86_32)
                                .code_segment(x86_32::CODE_ADDR, x86_32::CODE_SIZE)
                                .data_segment(x86_32::DATA_ADDR, x86_32::DATA_SIZE)
                                .stack_segment(x86_32::STACK_ADDR, x86_32::STACK_SIZE),
            CpuArch::X86_64 => CpuContext::new()
                                .arch(CpuArch::X86_64)
                                .code_segment(x86_64::CODE_ADDR, x86_64::CODE_SIZE)
                                .data_segment(x86_64::DATA_ADDR, x86_64::DATA_SIZE)
                                .stack_segment(x86_64::STACK_ADDR, x86_64::STACK_SIZE),
        }.build();
    
        Machine::new_from_context(&cpu_context)
    }

    pub fn new_from_context(cpu_context: &CpuContext) -> Result<Machine> {
        let mut unicorn = Machine::unicorn_engine(cpu_context.arch)?;
    
        let mut cpu = unicorn.borrow();
    
        // map and load memory
        mem_map!(cpu, cpu_context.code_addr, usize::try_from(cpu_context.code_size).unwrap(), Permission::ALL)?;
        mem_map!(cpu, cpu_context.data_addr, usize::try_from(cpu_context.data_size).unwrap(), Permission::ALL)?;
        mem_map!(cpu, cpu_context.stack_addr, usize::try_from(cpu_context.stack_size).unwrap(), Permission::ALL)?;
    
        for (addr, bytes) in &cpu_context.memory {
            mem_write!(cpu, *addr, bytes)?;
        }
    
        match cpu_context.arch {
            CpuArch::X86_32 => {
                cpu.add_intr_hook(x86_32::hook_intr)
                    .map_err(|err| anyhow::Error::new(ExecutionError::UnicornError)
                        .context(format!("Failure to add interrupt hook: {:?}", err))
                    )?;
        
                cpu.add_insn_sys_hook(unicorn::InsnSysX86::SYSCALL,
                                    cpu_context.code_addr,
                                    cpu_context.code_addr+cpu_context.code_size-1,
                                    x86_32::hook_syscall)
                    .map_err(|err| anyhow::Error::new(ExecutionError::UnicornError)
                        .context(format!("Failure to add syscall hook: {:?}", err))
                    )?;
            },
            CpuArch::X86_64 => {
                cpu.add_intr_hook(x86_64::hook_intr)
                    .map_err(|err| anyhow::Error::new(ExecutionError::UnicornError)
                        .context(format!("Failure to add interrupt hook: {:?}", err))
                    )?;
        
                cpu.add_insn_sys_hook(unicorn::InsnSysX86::SYSCALL,
                                    cpu_context.code_addr,
                                    cpu_context.code_addr+cpu_context.code_size-1,
                                    x86_64::hook_syscall)
                    .map_err(|err| anyhow::Error::new(ExecutionError::UnicornError)
                        .context(format!("Failure to add syscall hook: {:?}", err))
                    )?;
            },
        };
            
        let word_size = match cpu_context.arch {
            CpuArch::X86_32 => x86_32::WORD_SIZE,
            CpuArch::X86_64 => x86_64::WORD_SIZE,
        };
        
        let mut regs_values = IndexMap::new();
        for reg in cpuarch::regs(cpu_context.arch) {
            regs_values.insert(reg, 0u64);
        }
    
        for (reg,val) in cpu_context.regs_values.iter() {
            reg_write!(cpu, *reg, *val)?;
        }
    
        reg_write!(cpu, unicorn::RegisterX86::EIP as i32, cpu_context.code_addr)?;
    
        Ok(Machine {
            keystone: Machine::keystone_engine(cpu_context.arch)?,
            capstone: Machine::capstone_engine(cpu_context.arch)?,
            unicorn,
            word_size,
            regs_values,
            sp: unicorn::RegisterX86::ESP,
            ip: unicorn::RegisterX86::EIP,
            flags: unicorn::RegisterX86::EFLAGS,
            previous_inst_addr: vec![cpu_context.code_addr],
            code_addr: cpu_context.code_addr,
            code_size: cpu_context.code_size,
            data_addr: cpu_context.data_addr,
            data_size: cpu_context.data_size,
            stack_addr: cpu_context.stack_addr,
            stack_size: cpu_context.stack_size,
            printer: Printer::new(true, BorderStyle::Unicode, false),
        })
    }

    pub fn print_version(&self) {
        //let (major, minor) = unicorn::unicorn_version();
        //println!("unicorn version: {}.{}", major, minor);

        //let (major, minor) = keystone::bindings_version();
        //println!("keystone version: {}.{}", major, minor);
    }

    pub fn print_register(&mut self) -> Result<()> {
        let emu = self.unicorn.borrow();
        println!(
            "{}",
            Yellow.paint(format!("{:-^1$}", " cpu context ", 4*(self.word_size*2+8)+3))
        );

        for (index,(reg,prev_value)) in self.regs_values.iter_mut().enumerate() {
            if index > 0 && (index % 4) == 0 {
                println!("");
            }
            let reg_value = reg_read!(emu, reg.0 as i32)?;
            let reg_value_str = match self.word_size {
                4 => format!("0x{:08x}", reg_value),
                8 => format!("0x{:016x}", reg_value),
                _ => unreachable!(),
            };

            if *prev_value != reg_value {
                print!("{:3} : {} ", reg.to_string(), Blue.paint(reg_value_str));
                *prev_value = reg_value;
            } else {
                print!("{:3} : {} ", reg.to_string(), reg_value_str);
            }
        }
        println!("");

        Ok(())
    }

    pub fn asm(&self, str: String, address: u64) -> Result<AsmResult> {
        let result = self.keystone.asm(str, address)
                .map_err(|err| anyhow::Error::new(ExecutionError::KeystoneError)
                    .context(format!("Failure to assemble code: {:?}", err))
                )?;

        Ok(result)
    }

    pub fn execute_instruction(&mut self, byte_arr: Vec<u8>) -> Result<u64> {
        let mut emu = self.unicorn.borrow();
        let reg_ip = self.ip as i32;
        let cur_ip_val = reg_read!(emu, reg_ip)?;
        mem_write!(emu, cur_ip_val, &byte_arr)?;
        emu_start!(emu,
            cur_ip_val,
            cur_ip_val + u64::try_from(byte_arr.len()).unwrap(),
            10 * unicorn::unicorn_const::SECOND_SCALE,
            1000
        )?;

        let new_ip_val = reg_read!(emu,self.ip as i32)?;
        self.previous_inst_addr.push(new_ip_val);
   
        Ok(new_ip_val)
    }

    pub fn print_code(&mut self) -> Result<()> {
        let emu = self.unicorn.borrow();
        println!(
            "{}",
            Yellow.paint(format!("{:-^1$}", " code segment ", 4*(self.word_size*2+8)+3))
        );

        //println!("{:08x?}", self.previous_inst_addr);

        if self.previous_inst_addr.len() >= 2 {
            let s_addr = self.previous_inst_addr.first().unwrap();
            let e_addr = self.previous_inst_addr.last().unwrap();
            let len = e_addr - s_addr;

            let bytes = mem_read_as_vec!(emu, *s_addr, usize::try_from(len).unwrap())?;
            let insns = self
                            .capstone
                            .disasm_count(&bytes[..],
                                            *s_addr,
                                            self.previous_inst_addr.len()-1)
                            .map_err(|err| anyhow::Error::new(ExecutionError::CapstoneError)
                                .context(format!("Failure to disassembe bytes {:?}: {:?}", bytes, err))
                            )?;         
       
            for i in insns.iter() {
                println!("{:08x} {:8} {}",
                            i.address(),
                            i.mnemonic().unwrap(),
                            i.op_str().unwrap());
            }
        }

        Ok(())
    }

    pub fn init_cache(&mut self) -> Result<()> {
        let emu = self.unicorn.borrow();
        let mem_data = mem_read_as_vec!(emu, self.data_addr as u64, 5 * 16)?;

        self.printer.display_offset(self.data_addr);
        self.printer.init_cache(mem_data.as_slice());

        Ok(())
    }

    pub fn print_data(&mut self) -> Result<()> {
        let emu = self.unicorn.borrow();
        //println!(
        //    "{}",
        //    Yellow.paint(format!("{:-^1$}", " data segment ", 4*(self.word_size*2+8)+3))
        //);

        let mem_data = mem_read_as_vec!(emu, self.data_addr as u64, 5 * 16)?;

        self.printer.display_offset(self.data_addr);
        self.printer.print_all(mem_data.as_slice()).unwrap();
        self.printer.reset();

        Ok(())
    }

    pub fn print_stack(&mut self) -> Result<()> {
        let emu = self.unicorn.borrow();
        //println!(
        //    "{}",
        //    Yellow.paint(format!("{:-^1$}", " stack segment ", 4*(self.word_size*2+8)+3))
        //);

        let start_address = self.stack_addr + self.stack_size - u64::try_from(self.word_size).unwrap() * 4 * 8;
        let mem_data = mem_read_as_vec!(emu, start_address as u64, 5 * 16)?;

        self.printer.display_offset(start_address);
        self.printer.print_all(mem_data.as_slice()).unwrap();
        self.printer.reset();

        Ok(())
    }

    pub fn print_flags(&mut self) -> Result<()> {
        let emu = self.unicorn.borrow();
        let flag_bits = vec![
            ('C', 0),
            ('P', 2),
            ('A', 4),
            ('Z', 6),
            ('S', 7),
            ('D', 10),
            ('O', 11),
        ];

        let flag_val = reg_read!(emu, self.flags as i32)?;

        print!("FLAGS 0x{:08x} [ ", flag_val);
        for flag_bit in flag_bits {
            let flag_val = (flag_val >> flag_bit.1) & 1;
            if flag_val == 1 {
                print!("{}F ", flag_bit.0);
            }
            //match flag_val {
            //    0 => print!("{}", flag_bit.0.to_lowercase()),
            //    1 => print!("{}", flag_bit.0),
            //    _ => unreachable!(),
            //}
        }
        println!("]");

        Ok(())
    }

    fn unicorn_engine(arch: CpuArch) -> Result<unicorn::Unicorn> {
        let engine = match arch {
            CpuArch::X86_32 => unicorn::Unicorn::new(Arch::X86, Mode::MODE_32),
            CpuArch::X86_64 => unicorn::Unicorn::new(Arch::X86, Mode::MODE_64),
        }.map_err(|err| anyhow::Error::new(ExecutionError::UnicornError)
            .context(format!("Failure to create new unicorn engine instance: {:?}", err))
        )?;

        Ok(engine)
    }

    fn keystone_engine(arch: CpuArch) -> Result<keystone::Keystone> {
        let engine = match arch {
            CpuArch::X86_32 => Keystone::new(keystone::Arch::X86, keystone::Mode::LITTLE_ENDIAN | keystone::Mode::MODE_32),
            CpuArch::X86_64 => Keystone::new(keystone::Arch::X86, keystone::Mode::LITTLE_ENDIAN | keystone::Mode::MODE_64),
        }.map_err(|err| anyhow::Error::new(ExecutionError::KeystoneError)
                    .context(format!("Failure to create new keystone engine instance: {:?}", err))
        )?;


        engine.option(OptionType::SYNTAX, OptionValue::SYNTAX_NASM)
            .map_err(|err| anyhow::Error::new(ExecutionError::KeystoneError)
                .context(format!("Failure to create new keystone engine instance: {:?}", err))
            )?;

        Ok(engine)
    }
    
    fn capstone_engine(arch: CpuArch) -> Result<Capstone> {
        let engine = match arch {
            CpuArch::X86_32 => Capstone::new()
                                .x86()
                                .mode(arch::x86::ArchMode::Mode32)
                                .syntax(arch::x86::ArchSyntax::Intel),
            CpuArch::X86_64 => Capstone::new()
                                .x86()
                                .mode(arch::x86::ArchMode::Mode64)
                                .syntax(arch::x86::ArchSyntax::Intel),
        }.detail(false).build()
            .map_err(|err| anyhow::Error::new(ExecutionError::CapstoneError)
                .context(format!("Failure to create new capstone engine instance: {:?}", err))
            )?;
    
        Ok(engine)
    }
}
