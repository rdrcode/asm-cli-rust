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
    use std::time::SystemTime;
    use super::Register;
    use crate::machine::interface::ExecutionError;
    use crate::machine::interrupt::InterruptX86;
    use crate::machine::cpuarch::CpuArch;
    use crate::{reg_read,reg_write,mem_write};

    pub const CODE_ADDR:  u64 = 0x08048000;
    pub const CODE_SIZE:  u64 = 0x00100000;
    pub const DATA_ADDR:  u64 = CODE_ADDR + CODE_SIZE;
    pub const DATA_SIZE:  u64 = 0x00100000;
    pub const STACK_TOP:  u64 = 0xc0000000;
    pub const STACK_SIZE: u64 = 0x00100000; // 1MByte
    pub const STACK_ADDR: u64 = STACK_TOP - STACK_SIZE;
    pub const WORD_SIZE: usize = 4;

    pub const SYS_WRITE: u64           =   4;
    pub const SYS_TIME: u64            =  13;
    pub const SYS_GETTIMEOFDAY: u64    =  78;

    pub fn regs() -> Vec<Register> {
        super::regs_map().iter().filter(|(_,(set,flag))| *flag && set.contains(&CpuArch::X86_32)).map(|(reg,_)| *reg).collect()
    }

    pub fn hook_syscall(engine: unicorn::UnicornHandle) -> () {
        let reg_eip = reg_read!(engine, unicorn::RegisterX86::EIP as i32).unwrap_or(0);
        let reg_eax = reg_read!(engine, unicorn::RegisterX86::EAX as i32).unwrap_or(0);
        println!("SYSCALL #{:#04x} @ {:#010x}", reg_eax, reg_eip);

        ()
    }
        
    pub fn hook_intr(mut engine: unicorn::UnicornHandle, intno: u32) -> () {
        let reg_eip = reg_read!(engine, unicorn::RegisterX86::EIP as i32).unwrap_or(0);
        let reg_eax = reg_read!(engine, unicorn::RegisterX86::EAX as i32).unwrap_or(0);
        println!("INTERRUPT #{:#04x} '{}' @ {:#010x}",
                intno, InterruptX86{id: intno}, reg_eip);

        if intno == 0x80 {
            match reg_eax {
                SYS_WRITE => {
                    //let reg_ebx = reg_read!(engine, unicorn::RegisterX86::EBX as i32).unwrap();
                },
                SYS_TIME => {
                    let secs = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                        Ok(d) => d.as_secs(),
                        _     => 0,
                    };
                    let _ = reg_write!(engine, unicorn::RegisterX86::EAX as i32, secs);
                },
                SYS_GETTIMEOFDAY => {
                    let (secs,subsecs) = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                        Ok(d) => (d.as_secs(),d.subsec_micros()),
                        _     => (0,0),
                    };
                    let reg_ebx = reg_read!(engine, unicorn::RegisterX86::EBX as i32).unwrap();
                    let bytes = [(secs as u32).to_le_bytes(), (subsecs as u32).to_le_bytes()].concat();
                    let _ = mem_write!(engine, reg_ebx, &bytes);
                },
                _ => {

                },
            };
        }

        ()
    }
}

pub mod x86_64 {
    use super::Register;
    use crate::machine::interface::ExecutionError;
    use crate::machine::interrupt::InterruptX86;
    use crate::machine::cpuarch::CpuArch;
    use crate::reg_read;

    pub const CODE_ADDR: u64 = 0x00400000;
    pub const CODE_SIZE: u64 = 0x00100000;
    pub const DATA_ADDR: u64 = CODE_ADDR + CODE_SIZE;
    pub const DATA_SIZE: u64 = 0x00100000;
    pub const STACK_ADDR: u64 = DATA_ADDR + DATA_SIZE;
    pub const STACK_SIZE: u64 = 0x00100000;
    pub const STACK_TOP:  u64 = STACK_ADDR + STACK_SIZE;
    pub const WORD_SIZE: usize = 8;

    pub const SYS_WRITE: u64           =   1;
    //pub const SYS_TIME: u64            =  13;
    pub const SYS_GETTIMEOFDAY: u64    =  96;

    pub fn regs() -> Vec<Register> {
        super::regs_map().iter().filter(|(_,(set,flag))| *flag && set.contains(&CpuArch::X86_64)).map(|(reg,_)| *reg).collect()
    }

    pub fn hook_syscall(engine: unicorn::UnicornHandle) -> () {
        let reg_rip = reg_read!(engine, unicorn::RegisterX86::RIP as i32).unwrap();
        let reg_rax = reg_read!(engine, unicorn::RegisterX86::RAX as i32).unwrap();
        println!("SYSCALL #{:#04x} @ {:#010x}", reg_rax, reg_rip);
    
        ()
    }
    
    pub fn hook_intr(engine: unicorn::UnicornHandle, intno: u32) -> () {
        let reg_rip = reg_read!(engine, unicorn::RegisterX86::RIP as i32).unwrap();
        let reg_rax = reg_read!(engine, unicorn::RegisterX86::RAX as i32).unwrap();
        println!("INTERRUPT #{:#04x} '{}' @ {:#010x}",
                 intno, InterruptX86{id: intno}, reg_rip);
    
        if intno == 0x80 {
        }
    
        ()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_to_from_x32() {
        for reg in all_regs() {
            let name = reg.to_string();
            let r = Register::from(name.as_str());
            assert_eq!(reg, r);
        }
    }
}