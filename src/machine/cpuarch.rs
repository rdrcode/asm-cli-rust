use std::fmt;
use std::collections::HashSet;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use clap::arg_enum;
use serde::{Deserialize, Serialize, Serializer};
use serde::de::{Deserializer, Visitor};
use maplit::hashset;
use indexmap::{IndexMap,indexmap};


arg_enum!{
    #[derive(Copy,Clone,Deserialize,Serialize,PartialEq,Eq,Hash,Debug)]
    pub enum CpuArch {
        X86_32,
        X86_64,
    }
}

impl Default for CpuArch {
    fn default() -> CpuArch {
        CpuArch::X86_32
    }
}

fn regs_map() -> IndexMap<Register,(HashSet<CpuArch>,bool)> {
    indexmap![
        Register{0: unicorn::RegisterX86::EAX}      => (hashset!{CpuArch::X86_32},true),
        Register{0: unicorn::RegisterX86::EBX}      => (hashset!{CpuArch::X86_32},true),
        Register{0: unicorn::RegisterX86::ECX}      => (hashset!{CpuArch::X86_32},true),
        Register{0: unicorn::RegisterX86::EDX}      => (hashset!{CpuArch::X86_32},true),
        Register{0: unicorn::RegisterX86::ESI}      => (hashset!{CpuArch::X86_32},true),
        Register{0: unicorn::RegisterX86::EDI}      => (hashset!{CpuArch::X86_32},true),
        Register{0: unicorn::RegisterX86::EIP}      => (hashset!{CpuArch::X86_32},true),
        Register{0: unicorn::RegisterX86::EBP}      => (hashset!{CpuArch::X86_32},true),
        Register{0: unicorn::RegisterX86::ESP}      => (hashset!{CpuArch::X86_32},true),
        Register{0: unicorn::RegisterX86::RAX}      => (hashset!{CpuArch::X86_64},true),
        Register{0: unicorn::RegisterX86::RBX}      => (hashset!{CpuArch::X86_64},true),
        Register{0: unicorn::RegisterX86::RCX}      => (hashset!{CpuArch::X86_64},true),
        Register{0: unicorn::RegisterX86::RDX}      => (hashset!{CpuArch::X86_64},true),
        Register{0: unicorn::RegisterX86::RSI}      => (hashset!{CpuArch::X86_64},true),
        Register{0: unicorn::RegisterX86::RDI}      => (hashset!{CpuArch::X86_64},true),
        Register{0: unicorn::RegisterX86::R8}       => (hashset!{CpuArch::X86_64},true),
        Register{0: unicorn::RegisterX86::R9}       => (hashset!{CpuArch::X86_64},true),
        Register{0: unicorn::RegisterX86::R10}      => (hashset!{CpuArch::X86_64},true),
        Register{0: unicorn::RegisterX86::R11}      => (hashset!{CpuArch::X86_64},true),
        Register{0: unicorn::RegisterX86::R12}      => (hashset!{CpuArch::X86_64},true),
        Register{0: unicorn::RegisterX86::R13}      => (hashset!{CpuArch::X86_64},true),
        Register{0: unicorn::RegisterX86::R14}      => (hashset!{CpuArch::X86_64},true),
        Register{0: unicorn::RegisterX86::R15}      => (hashset!{CpuArch::X86_64},true),
        Register{0: unicorn::RegisterX86::RIP}      => (hashset!{CpuArch::X86_64},true),
        Register{0: unicorn::RegisterX86::RBP}      => (hashset!{CpuArch::X86_64},true),
        Register{0: unicorn::RegisterX86::RSP}      => (hashset!{CpuArch::X86_64},true),
        Register{0: unicorn::RegisterX86::EFLAGS}   => (hashset!{CpuArch::X86_32,CpuArch::X86_64},false),
        Register{0: unicorn::RegisterX86::CS}       => (hashset!{CpuArch::X86_32,CpuArch::X86_64},false),
        Register{0: unicorn::RegisterX86::SS}       => (hashset!{CpuArch::X86_32,CpuArch::X86_64},false),
        Register{0: unicorn::RegisterX86::DS}       => (hashset!{CpuArch::X86_32,CpuArch::X86_64},false),
        Register{0: unicorn::RegisterX86::ES}       => (hashset!{CpuArch::X86_32,CpuArch::X86_64},false),
        Register{0: unicorn::RegisterX86::FS}       => (hashset!{CpuArch::X86_32,CpuArch::X86_64},false),
        Register{0: unicorn::RegisterX86::GS}       => (hashset!{CpuArch::X86_32,CpuArch::X86_64},false),
    ]
}

pub fn all_regs() -> Vec<Register> {
    regs_map().keys().map(|reg| *reg).collect()
}

pub fn regs(arch: CpuArch) -> Vec<Register> {
    regs_map().iter().filter(|(_,(set,flag))| *flag && set.contains(&arch)).map(|(reg,_)| *reg).collect()
}

#[derive(Copy,Clone)]
pub struct Register(pub unicorn::RegisterX86);

impl From<Register> for i32 {
    fn from(reg: Register) -> Self {
        reg.0 as i32
    }
}

impl From<&str> for Register {
    fn from(s: &str) -> Self {
        let mut result = Register{0: unicorn::RegisterX86::INVALID};
        for reg in all_regs() {
            if reg.to_string() == s {
                result = reg;
                break;
            }
        }
        result
    }
}

impl Ord for Register {
    fn cmp(&self, other: &Self) -> Ordering {
        let a: i32 = i32::from(*self);
        let b: i32 = i32::from(*other);
        a.cmp(&b)
    }
}

impl PartialOrd for Register {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Register {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Register{}

impl Hash for Register {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        i32::from(*self).hash(hasher);
    }
}

impl fmt::Debug for Register {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "{:?}", self.0)
    }
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl Serialize for Register {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{:?}", self))
    }
}

impl<'de> serde::de::Deserialize<'de> for Register {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RegisterVisitor;

        impl<'de> Visitor<'de> for RegisterVisitor {
            type Value = Register;

            fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt.write_str("string")
            }

            fn visit_str<E>(self, val: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Register::from(val))
            }
        }

        deserializer.deserialize_any(RegisterVisitor)
    }
}


pub mod x86_32 {
    use std::convert::TryFrom;
    use std::time::SystemTime;
    use chrono::{Local,TimeZone,Offset};
    use super::Register;
    use crate::machine::interface::ExecutionError;
    use crate::machine::interrupt::InterruptX86;
    use crate::machine::cpuarch::CpuArch;
    use crate::{reg_read,reg_write,mem_write,mem_read_as_vec};
    use num_traits::cast::*;

    pub const CODE_ADDR:     u64 = 0x08048000;
    pub const CODE_SIZE:     u64 = 0x00100000;
    pub const DATA_ADDR:     u64 = CODE_ADDR + CODE_SIZE;
    pub const DATA_SIZE:     u64 = 0x00100000;
    pub const STACK_TOP:     u64 = 0xc0000000;
    pub const STACK_SIZE:    u64 = 0x00100000; // 1MByte
    pub const STACK_ADDR:    u64 = STACK_TOP - STACK_SIZE;
    pub const WORD_SIZE:   usize = 4;
    pub const LINUX_SYSCALL: u32 = 0x80;

    #[derive(FromPrimitive, ToPrimitive)]
    enum Syscall {
        Exit          =      1,
        Write         =      4,
        Time          =     13,
        GetTimeOfDay  =     78,
        Unknown       = 0xffff,
    }

    pub fn regs() -> Vec<Register> {
        super::regs_map().iter().filter(|(_,(set,flag))| *flag && set.contains(&CpuArch::X86_32)).map(|(reg,_)| *reg).collect()
    }

    pub fn hook_syscall(engine: unicorn::UnicornHandle) -> () {
        let reg_eip = reg_read!(engine, unicorn::RegisterX86::EIP as i32).unwrap_or(0);
        let reg_eax = reg_read!(engine, unicorn::RegisterX86::EAX as i32).unwrap_or(0);
        println!("SYSCALL: #{:#04x} @ {:#010x}", reg_eax, reg_eip);

        ()
    }
        
    pub fn hook_intr(mut engine: unicorn::UnicornHandle, intno: u32) -> () {
        let reg_eip = reg_read!(engine, unicorn::RegisterX86::EIP as i32).unwrap_or(0);
        let reg_eax = reg_read!(engine, unicorn::RegisterX86::EAX as i32).unwrap_or(0);
        println!("INTERRUPT: #{:#04x} '{}' @ {:#010x}",
                intno, InterruptX86{id: intno}, reg_eip);

        if intno == LINUX_SYSCALL {
            let reg_ebx = reg_read!(engine, unicorn::RegisterX86::EBX as i32).unwrap_or(0);
            match Syscall::from_u64(reg_eax).unwrap_or(Syscall::Unknown) {
                Syscall::Write => {
                    let reg_ecx = reg_read!(engine, unicorn::RegisterX86::ECX as i32).unwrap_or(0);
                    let reg_edx = reg_read!(engine, unicorn::RegisterX86::EDX as i32).unwrap_or(0);
                    if reg_ecx != 0 && reg_edx != 0 {
                        let mem_data = mem_read_as_vec!(engine, reg_ecx, usize::try_from(reg_edx).unwrap_or(0)).unwrap_or(vec![]);
                        println!("SYS_WRITE: fd={}, @0x{:08x}: '{}', size = {}", reg_ebx, reg_ecx, String::from_utf8_lossy(&mem_data), reg_edx);
                    }
                },
                Syscall::Time => {
                    let secs = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                        Ok(d) => d.as_secs(),
                        _     => 0,
                    };
                    let _ = reg_write!(engine, unicorn::RegisterX86::EAX as i32, secs);
                    if reg_ebx != 0 {
                        let bytes = (secs as u32).to_le_bytes();
                        let _ = mem_write!(engine, reg_ebx, &bytes);
                        println!("SYS_TIME: @0x{:08x}: {} (0x{:08x})", reg_ebx, secs, secs);
                    } else {
                        println!("SYS_TIME: eax = {} (0x{:08x})", secs, secs);
                    }
                },
                Syscall::Exit => {
                    println!("SYS_EXIT: error code {}", reg_ebx);
                    let _ = engine.emu_stop();
                },
                Syscall::GetTimeOfDay => {
                    if reg_ebx != 0 {
                        let (secs,subsecs) = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                            Ok(d) => (d.as_secs(),d.subsec_micros()),
                            _     => (0,0),
                        };
                        let bytes = [(secs as u32).to_le_bytes(), (subsecs as u32).to_le_bytes()].concat();
                        let _ = mem_write!(engine, reg_ebx, &bytes);
                    }
                    let reg_ecx = reg_read!(engine, unicorn::RegisterX86::ECX as i32).unwrap_or(0);
                    if reg_ecx != 0 {
                        let tz_offset_min: i32 = Local.timestamp(0, 0).offset().fix().local_minus_utc()/60;
                        let dst: u32 = 0;
                        let bytes = [tz_offset_min.to_le_bytes(), dst.to_le_bytes()].concat();
                        let _ = mem_write!(engine, reg_ecx, &bytes);
                    }
                },
                _ => println!("SYSCALL: unknown id #{}", reg_eax),
            };
        }

        ()
    }
}

pub mod x86_64 {
    use std::convert::TryFrom;
    use std::time::SystemTime;
    use chrono::{Local,TimeZone,Offset};
    use super::Register;
    use crate::machine::interface::ExecutionError;
    use crate::machine::interrupt::InterruptX86;
    use crate::machine::cpuarch::CpuArch;
    use crate::{reg_read,mem_write,mem_read_as_vec};
    use num_traits::cast::*;

    pub const CODE_ADDR: u64 = 0x00400000;
    pub const CODE_SIZE: u64 = 0x00100000;
    pub const DATA_ADDR: u64 = CODE_ADDR + CODE_SIZE;
    pub const DATA_SIZE: u64 = 0x00100000;
    pub const STACK_ADDR: u64 = DATA_ADDR + DATA_SIZE;
    pub const STACK_SIZE: u64 = 0x00100000;
    pub const STACK_TOP:  u64 = STACK_ADDR + STACK_SIZE;
    pub const WORD_SIZE: usize = 8;

    #[derive(FromPrimitive, ToPrimitive)]
    enum Syscall {
        Write         =      1,
        Exit          =     60,
        GetTimeOfDay  =     96,
        Unknown       = 0xffff,
    }

    pub fn regs() -> Vec<Register> {
        super::regs_map().iter().filter(|(_,(set,flag))| *flag && set.contains(&CpuArch::X86_64)).map(|(reg,_)| *reg).collect()
    }

    pub fn hook_syscall(mut engine: unicorn::UnicornHandle) -> () {
        let reg_rip = reg_read!(engine, unicorn::RegisterX86::RIP as i32).unwrap();
        let reg_rax = reg_read!(engine, unicorn::RegisterX86::RAX as i32).unwrap();
        println!("SYSCALL: #{:#04x} @ {:#010x}", reg_rax, reg_rip);

        let reg_rdi = reg_read!(engine, unicorn::RegisterX86::RDI as i32).unwrap_or(0);
        match Syscall::from_u64(reg_rax).unwrap_or(Syscall::Unknown) {
            Syscall::Write => {
                let reg_rsi = reg_read!(engine, unicorn::RegisterX86::RSI as i32).unwrap_or(0);
                let reg_rdx = reg_read!(engine, unicorn::RegisterX86::RDX as i32).unwrap_or(0);
                if reg_rsi != 0 && reg_rdx != 0 {
                    let mem_data = mem_read_as_vec!(engine, reg_rsi, usize::try_from(reg_rdx).unwrap_or(0)).unwrap_or(vec![]);
                    println!("SYS_WRITE: fd={}, @0x{:08x}: '{}', size = {}", reg_rdi, reg_rsi, String::from_utf8_lossy(&mem_data), reg_rdx);
                } else {
                    println!("SYS_WRITE: fd={}, @0x{:08x}, size = {}", reg_rdi, reg_rsi, reg_rdx);
                }
            },
            Syscall::Exit => {
                println!("SYS_EXIT: error code {}", reg_rdi);
                let _ = engine.emu_stop();
            },
            Syscall::GetTimeOfDay => {
                if reg_rdi != 0 {
                    let (secs,subsecs) = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                        Ok(d) => (d.as_secs(),d.subsec_micros()),
                        _     => (0,0),
                    };
                    let bytes = [(secs as u64).to_le_bytes(), (subsecs as u64).to_le_bytes()].concat();
                    let _ = mem_write!(engine, reg_rdi, &bytes);
                }
                let reg_rsi = reg_read!(engine, unicorn::RegisterX86::RSI as i32).unwrap_or(0);
                if reg_rsi != 0 {
                    let tz_offset_min = (Local.timestamp(0, 0).offset().fix().local_minus_utc()/60) as i64;
                    let dst: u64 = 0;
                    let bytes = [tz_offset_min.to_le_bytes(), dst.to_le_bytes()].concat();
                    let _ = mem_write!(engine, reg_rsi, &bytes);
                }
            },
            _ => println!("SYSCALL: unknown id #{}", reg_rax),
        };

        ()
    }
    
    pub fn hook_intr(engine: unicorn::UnicornHandle, intno: u32) -> () {
        let reg_rip = reg_read!(engine, unicorn::RegisterX86::RIP as i32).unwrap_or(0);
        //let reg_rax = reg_read!(engine, unicorn::RegisterX86::RAX as i32).unwrap();
        println!("INTERRUPT: #{:#04x} '{}' @ {:#010x}",
                 intno, InterruptX86{id: intno}, reg_rip);
    
        ()
    }
}

#[cfg(test)]
mod tests {
    use unicorn::unicorn_const::{SECOND_SCALE};
    use anyhow::Result;

    use super::*;
    use crate::machine::interface::Machine;
    use crate::machine::interface::ExecutionError;
    use crate::machine::context::CpuContext;
    use crate::machine::cpuarch::{CpuArch,Register};
    use crate::{emu_start,mem_write,mem_read_as_vec,reg_write,reg_read};


    #[test]
    fn register_to_from_x32() {
        for reg in all_regs() {
            let name = reg.to_string();
            let r = Register::from(name.as_str());
            assert_eq!(reg, r);
        }
    }

    #[test]
    fn test_syscall_write_32() -> Result<()> {
        let cpu_context = CpuContext::new().arch(CpuArch::X86_32).build();
        let mut machine = Machine::new_from_context(&cpu_context)?;
        let mut emu = machine.unicorn.borrow();

        let x86_code: Vec<u8> = vec![
            0x31, 0xc0,                   // xor eax,eax
            0x0f, 0xa2,                   // cpuid
            0x89, 0x1e,                   // mov[esi],ebx
            0x89, 0x56, 0x04,             // mov[esi+4],edx
            0x89, 0x4e, 0x08,             // mov[esi+8],ecx
            0xb8, 0x04, 0x00, 0x00, 0x00, // mov eax,4
            0xbb, 0x01, 0x00, 0x00, 0x00, // mov ebx,1
            0x89, 0xf1,                   // mov ecx,esi
            0xba, 0x0c, 0x00, 0x00, 0x00, // mov edx,0x0c
            0xcd, 0x80,                   // int 0x80
            0x90,                         // nop
            0x90,                         // nop
            0x90,                         // nop
            0x90,                         // nop
        ];

        reg_write!(emu, unicorn::RegisterX86::EIP as i32, machine.code_addr)?;
        let s_addr = machine.code_addr;
        mem_write!(emu, s_addr, &x86_code)?;
        emu_start!(emu, 
            s_addr,
            s_addr + x86_code.len() as u64,
            10 * SECOND_SCALE,
            1000
        )?;

        let reg_eip = reg_read!(emu, unicorn::RegisterX86::EIP as i32)?;
        assert_eq!(s_addr+(x86_code.len() as u64), reg_eip);

        Ok(())
    }

    #[test]
    fn test_syscall_write_64() -> Result<()> {
        let cpu_context = CpuContext::new().arch(CpuArch::X86_64).build();
        let mut machine = Machine::new_from_context(&cpu_context)?;
        let mut emu = machine.unicorn.borrow();

        let x86_code: Vec<u8> = vec![
            0x31, 0xc0,                   // xor eax,eax
            0x0f, 0xa2,                   // cpuid
            0x89, 0x1e,                   // mov[rsi],ebx
            0x89, 0x56, 0x04,             // mov[rsi+4],edx
            0x89, 0x4e, 0x08,             // mov[rsi+8],ecx
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
            0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi,1
            0xba, 0x0c, 0x00, 0x00, 0x00, // mov edx,0x0c
            0x0f, 0x05,                   // syscall
            0x90,                         // nop
            0x90,                         // nop
            0x90,                         // nop
            0x90,                         // nop
        ];

        reg_write!(emu, unicorn::RegisterX86::RIP as i32, machine.code_addr)?;
        let s_addr = machine.code_addr;
        mem_write!(emu, s_addr, &x86_code)?;
        emu_start!(emu, 
            s_addr,
            s_addr + x86_code.len() as u64,
            10 * SECOND_SCALE,
            1000
        )?;

        let reg_rip = reg_read!(emu, unicorn::RegisterX86::RIP as i32)?;
        assert_eq!(s_addr+(x86_code.len() as u64), reg_rip);

        Ok(())
    }

    #[test]
    fn test_syscall_exit_32() -> Result<()> {
        let cpu_context = CpuContext::new().arch(CpuArch::X86_32).build();
        let mut machine = Machine::new_from_context(&cpu_context)?;
        let mut emu = machine.unicorn.borrow();

        let x86_code_1: Vec<u8> = vec![
            0x66, 0xbb, 0x34, 0x12,       // mov bx,0x1234
            0x66, 0xba, 0x39, 0x30,       // mov dx,12345
            0x66, 0x89, 0x17,             // mov [edi],dx
            0x66, 0x89, 0x5f, 0x10,       // mov [edi+16],bx
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
            0xbb, 0x2a, 0x00, 0x00, 0x00, // mov ebx,42
            0x90,                         // nop
        ];
        let x86_code_2: Vec<u8> = vec![
            0xcd, 0x80,                   // int 0x80
            0x90,                         // nop
            0x90,                         // nop
            0x90,                         // nop
            0x90,                         // nop
            0x90,                         // nop
            0x90,                         // nop
            0x90,                         // nop
            0x90,                         // nop
        ];

        reg_write!(emu, unicorn::RegisterX86::EIP as i32, machine.code_addr)?;
        let s_addr = machine.code_addr;
        mem_write!(emu, s_addr, &x86_code_1)?;
        mem_write!(emu, s_addr+(x86_code_1.len() as u64), &x86_code_2)?;
        emu_start!(emu, 
            s_addr,
            s_addr + (x86_code_1.len() + x86_code_2.len()) as u64,
            10 * SECOND_SCALE,
            1000
        )?;

        let reg_eip = reg_read!(emu, unicorn::RegisterX86::EIP as i32)?;
        // EIP points to the instruction after the interrupt instruction,
        // which allocates two bytes
        let int_addr = reg_eip - 2;
        assert_eq!(s_addr+(x86_code_1.len() as u64), int_addr);
        let mem_data = mem_read_as_vec!(emu, int_addr as u64, 2)?;
        assert_eq!(vec![0xcd,0x80], mem_data);

        Ok(())
    }

    #[test]
    fn test_syscall_exit_x64() -> Result<()> {
        let cpu_context = CpuContext::new().arch(CpuArch::X86_64).build();
        let mut machine = Machine::new_from_context(&cpu_context)?;
        let mut emu = machine.unicorn.borrow();

        let x86_code_1: Vec<u8> = vec![
            0x66, 0xbb, 0x34, 0x12,       // mov bx,0x1234
            0x66, 0xba, 0x39, 0x30,       // mov dx,12345
            0x66, 0x89, 0x17,             // mov [edi],dx
            0x66, 0x89, 0x5f, 0x10,       // mov [edi+16],bx
            0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax,60
            0xbf, 0x2a, 0x00, 0x00, 0x00, // mov edi,42
            0x90,                         // nop
        ];
        let x86_code_2: Vec<u8> = vec![
            0x0f, 0x05,                   // syscall
            0x90,                         // nop
            0x90,                         // nop
            0x90,                         // nop
            0x90,                         // nop
            0x90,                         // nop
            0x90,                         // nop
            0x90,                         // nop
            0x90,                         // nop
        ];

        reg_write!(emu, unicorn::RegisterX86::RIP as i32, machine.code_addr)?;
        let s_addr = machine.code_addr;
        mem_write!(emu, s_addr, &x86_code_1)?;
        mem_write!(emu, s_addr+(x86_code_1.len() as u64), &x86_code_2)?;
        emu_start!(emu, 
            s_addr,
            s_addr + (x86_code_1.len() + x86_code_2.len()) as u64,
            10 * SECOND_SCALE,
            1000
        )?;

        let reg_rip = reg_read!(emu, unicorn::RegisterX86::RIP as i32)?;
        // EIP points to the instruction after the syscall instruction,
        // which allocates two bytes
        let int_addr = reg_rip - 2;
        assert_eq!(s_addr+(x86_code_1.len() as u64), int_addr);
        let mem_data = mem_read_as_vec!(emu, int_addr as u64, 2)?;
        assert_eq!(vec![0x0f,0x05], mem_data);

        Ok(())
    }
}