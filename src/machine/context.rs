use std::convert::TryFrom;
use std::io::{Read,Write};
use std::collections::{BTreeMap, HashMap};
use serde::{Deserialize, Serialize, Serializer};
use serde_json;
use itertools::Itertools;
use unicorn::unicorn_const::{MemRegion, Permission};
use anyhow::Result;

use super::interface::Machine;
use super::interface::ExecutionError;
use super::cpuarch::{CpuArch,Register,x86_32,x86_64};
use crate::{mem_regions,mem_map,mem_unmap,mem_read_as_vec,mem_write,reg_read,reg_write};


#[derive(Deserialize,Serialize,PartialEq,Debug)]
pub struct CpuContext {
    pub arch:        CpuArch,
    pub code_addr:   u64,
    pub code_size:   u64,
    pub data_addr:   u64,
    pub data_size:   u64,
    pub stack_addr:  u64,
    pub stack_size:  u64,
    #[serde(serialize_with = "ordered_register_map")]
    pub regs_values: HashMap<Register, u64>,
    #[serde(serialize_with = "ordered_u64_map")]
    pub memory:      HashMap<u64, Vec<u8>>,
}

fn ordered_register_map<S>(value: &HashMap<Register, u64>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let ordered: BTreeMap<_, _> = value.iter().collect();
    ordered.serialize(serializer)
}

fn ordered_u64_map<S>(value: &HashMap<u64, Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let ordered: BTreeMap<_, _> = value.iter().collect();
    ordered.serialize(serializer)
}

impl Default for CpuContext {
    fn default() -> CpuContext {
        CpuContext {
            arch:        CpuArch::X86_32,
            code_addr:   CpuContext::CODE_ADDR,
            code_size:   CpuContext::CODE_SIZE,
            data_addr:   CpuContext::DATA_ADDR,
            data_size:   CpuContext::DATA_SIZE,
            stack_addr:  CpuContext::STACK_ADDR,
            stack_size:  CpuContext::STACK_SIZE,
            regs_values: HashMap::new(),
            memory:      HashMap::new(),
        }
    }
}

impl CpuContext {

    const CODE_ADDR:  u64 = 0x00001000;
    const CODE_SIZE:  u64 = 0x00001000;
    const DATA_ADDR:  u64 = CpuContext::CODE_ADDR + CpuContext::CODE_SIZE;
    const DATA_SIZE:  u64 = 0x00001000;
    const STACK_ADDR: u64 = CpuContext::DATA_ADDR + CpuContext::DATA_SIZE;
    const STACK_SIZE: u64 = 0x00001000;

    pub fn new() -> CpuContextBuilder {
        CpuContextBuilder {
            arch:    CpuArch::X86_32,
            code_addr:   CpuContext::CODE_ADDR,
            code_size:   CpuContext::CODE_SIZE,
            data_addr:   CpuContext::DATA_ADDR,
            data_size:   CpuContext::DATA_SIZE,
            stack_addr:  CpuContext::STACK_ADDR,
            stack_size:  CpuContext::STACK_SIZE,
            regs_values: HashMap::new(),
            memory:      HashMap::new(),
        }
    }

    pub fn new_from_json(json: &str) -> serde_json::Result<CpuContext> {
        Ok(serde_json::from_str::<CpuContext>(json)?)
    }

    pub fn write_to<W: Write>(&self, f: &mut W) -> Result<usize, std::io::Error> {
        if let Ok(json_str) = serde_json::to_string(self) {
            f.write(json_str.as_bytes())
        } else {
            Ok(0)
        }
    }

    pub fn read_from<R: Read>(&mut self, f: &mut R) -> Result<(), std::io::Error> {
        *self = serde_json::from_reader(f)?;
        Ok(())
    }

    fn read_memory(&mut self, emu: &unicorn::UnicornHandle, addr: u64, size: u64) -> Result<()>{
        let mem_data = mem_read_as_vec!(emu, addr as u64, usize::try_from(size).unwrap())?;

        let mut grouped: Vec<(bool,Vec<u8>)> = Vec::new();
        for (key, group) in &mem_data.into_iter().group_by(|x| *x != 0) {
            grouped.push((key, group.collect()));
        }

        let mut addr: usize = usize::try_from(addr).unwrap();
        for (nonzero,bytes) in grouped {
            let len = bytes.len();
            if nonzero {
                println!("R: {:08x}: {:?}", addr, bytes);
                self.memory.insert(u64::try_from(addr).unwrap(), bytes);
            }
            addr = addr + len;
        }

        Ok(())
    }

    pub fn save(&mut self, machine: &mut Machine) -> Result<()> {
        let emu = machine.unicorn.borrow();

        for (&reg,val) in self.regs_values.iter_mut() {
            *val = reg_read!(emu,reg)?;
        }

        self.code_addr = machine.code_addr;
        self.code_size = machine.code_size;
        self.data_addr = machine.data_addr;
        self.data_size = machine.data_size;
        self.stack_addr = machine.stack_addr;
        self.stack_size = machine.stack_size;

        self.read_memory(&emu, self.code_addr, self.code_size)?;
        self.read_memory(&emu, self.data_addr, self.data_size)?;
        self.read_memory(&emu, self.stack_addr, self.stack_size)?;

        Ok(())
    }

    pub fn restore(&self, machine: &mut Machine) -> Result<()> {
        let mut emu = machine.unicorn.borrow();
        let mem_regions: Vec<MemRegion> = mem_regions!(emu)?;
        
        for mem_region in mem_regions {
            let size: usize = usize::try_from(mem_region.end-mem_region.begin+1).unwrap();
            mem_unmap!(emu, mem_region.begin, size)?; 
        }

        machine.code_addr = self.code_addr;
        machine.code_size = self.code_size;
        machine.data_addr = self.data_addr;
        machine.data_size = self.data_size;
        machine.stack_addr = self.stack_addr;
        machine.stack_size = self.stack_size;
        machine.word_size = match self.arch {
            CpuArch::X86_32 => x86_32::WORD_SIZE,
            CpuArch::X86_64 => x86_64::WORD_SIZE,
        };

        mem_map!(emu, self.code_addr, usize::try_from(self.code_size).unwrap(), Permission::ALL)?;
        mem_map!(emu, self.data_addr, usize::try_from(self.data_size).unwrap(), Permission::ALL)?;
        mem_map!(emu, self.stack_addr, usize::try_from(self.stack_size).unwrap(), Permission::ALL)?;

        for (reg,val) in self.regs_values.iter() {
            reg_write!(emu, *reg, *val)?;
        }

        for (addr, bytes) in &self.memory {
            mem_write!(emu, *addr, bytes)?;
        }

        machine.previous_inst_addr.clear();
        machine.previous_inst_addr.push(machine.code_addr);
        Ok(())
    }
}


#[derive(Debug)]
pub struct CpuContextBuilder {
    pub arch:        CpuArch,
    pub code_addr:   u64,
    pub code_size:   u64,
    pub data_addr:   u64,
    pub data_size:   u64,
    pub stack_addr:  u64,
    pub stack_size:  u64,
    pub regs_values: HashMap<Register, u64>,
    pub memory:      HashMap<u64, Vec<u8>>,
}

impl CpuContextBuilder {

    pub fn arch(mut self, arch: CpuArch) -> CpuContextBuilder {
        self.arch = arch;
        self
    }

    pub fn code_segment(mut self, addr: u64, size: u64) -> CpuContextBuilder {
        self.code_addr = addr;
        self.code_size = size;
        self
    }

    pub fn data_segment(mut self, addr: u64, size: u64) -> CpuContextBuilder {
        self.data_addr = addr;
        self.data_size = size;
        self
    }

    pub fn stack_segment(mut self, addr: u64, size: u64) -> CpuContextBuilder {
        self.stack_addr = addr;
        self.stack_size = size;
        self
    }

    pub fn build(self) -> CpuContext {
        let mut cpu_context = CpuContext {
            arch:        self.arch,
            code_addr:   self.code_addr,
            code_size:   self.code_size,
            data_addr:   self.data_addr,
            data_size:   self.data_size,
            stack_addr:  self.stack_addr,
            stack_size:  self.stack_size,
            regs_values: self.regs_values,
            memory:      self.memory,
        };

        match self.arch {
            CpuArch::X86_32 => {
                for reg in x86_32::regs() {
                    cpu_context.regs_values.insert(reg, 0u64);
                }
                cpu_context.regs_values.insert(Register{0: unicorn::RegisterX86::ESP}, self.stack_addr + self.stack_size);
                cpu_context.regs_values.insert(Register{0: unicorn::RegisterX86::EBP}, self.stack_addr);
                cpu_context.regs_values.insert(Register{0: unicorn::RegisterX86::EDI}, self.data_addr);
                cpu_context.regs_values.insert(Register{0: unicorn::RegisterX86::ESI}, self.data_addr);
            },
            CpuArch::X86_64 => {
                for reg in x86_64::regs() {
                    cpu_context.regs_values.insert(reg, 0u64);
                }
                cpu_context.regs_values.insert(Register{0: unicorn::RegisterX86::RSP}, self.stack_addr + self.stack_size);
                cpu_context.regs_values.insert(Register{0: unicorn::RegisterX86::RBP}, self.stack_addr);
                cpu_context.regs_values.insert(Register{0: unicorn::RegisterX86::RDI}, self.data_addr);
                cpu_context.regs_values.insert(Register{0: unicorn::RegisterX86::RSI}, self.data_addr);
            },
        }

        cpu_context
    }

}


#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::BufWriter;
    use std::path::Path;
    use std::io::Cursor;
    use unicorn::unicorn_const::{SECOND_SCALE};
    use maplit::hashmap;
    use anyhow::Result;

    use super::*;
    use crate::machine::interface::Machine;
    use crate::machine::cpuarch::{CpuArch,Register};
    use crate::{emu_start,mem_write,reg_write};


    const CPUCONTEXT_JSON_X32_A: &str = "{\
        \"arch\":\"X86_32\",\
        \"code_addr\":4096,\
        \"code_size\":4096,\
        \"data_addr\":8192,\
        \"data_size\":4096,\
        \"stack_addr\":12288,\
        \"stack_size\":4096,\
        \"regs_values\":{\
            \"EAX\":255,\
            \"EBP\":12288,\
            \"EBX\":4660,\
            \"ECX\":0,\
            \"EDI\":8192,\
            \"EDX\":12345,\
            \"EIP\":4113,\
            \"ESI\":8192,\
            \"ESP\":16384},\
        \"memory\":{\
            \"4096\":[176,255,102,187,52,18,102,186,57,48,102,137,23,102,137,95,16],\
            \"8192\":[57,48],\
            \"8208\":[52,18]\
    }}";

    const CPUCONTEXT_JSON_X64_A: &str = "{\
            \"arch\":\"X86_64\",\
            \"code_addr\":4096,\
            \"code_size\":4096,\
            \"data_addr\":8192,\
            \"data_size\":4096,\
            \"stack_addr\":12288,\
            \"stack_size\":4096,\
            \"regs_values\":{\
                \"RAX\":255,\
                \"RBP\":12288,\
                \"RBX\":4660,\
                \"RCX\":0,\
                \"RDI\":8192,\
                \"RDX\":12345,\
                \"RIP\":4113,\
                \"RSI\":8192,\
                \"RSP\":16384,\
                \"R8\":0,\
                \"R9\":0,\
                \"R10\":0,\
                \"R11\":0,\
                \"R12\":0,\
                \"R13\":0,\
                \"R14\":0,\
                \"R15\":0},\
            \"memory\":{\
                \"4096\":[176,255,102,187,52,18,102,186,57,48,102,137,23,102,137,95,16],\
                \"8192\":[57,48],\
                \"8208\":[52,18]\
    }}";

    const CPUCONTEXT_JSON_X32_B: &str = "{\
        \"arch\":\"X86_32\",\
        \"code_addr\":65536,\
        \"code_size\":8192,\
        \"data_addr\":73728,\
        \"data_size\":8192,\
        \"stack_addr\":81920,\
        \"stack_size\":8192,\
        \"regs_values\":{\
            \"EAX\":255,\
            \"EBP\":81920,\
            \"EBX\":4660,\
            \"ECX\":0,\
            \"EDI\":73728,\
            \"EDX\":12345,\
            \"EIP\":65553,\
            \"ESI\":73728,\
            \"ESP\":90112},\
            \"memory\":{\"65536\":[176,255,102,187,52,18,102,186,57,48,102,137,23,102,137,95,16],\
            \"73728\":[57,48],\
            \"73744\":[52,18]\
    }}";

    const CPUCONTEXT_JSON_X64_B: &str = "{\
        \"arch\":\"X86_64\",\
        \"code_addr\":65536,\
        \"code_size\":8192,\
        \"data_addr\":73728,\
        \"data_size\":8192,\
        \"stack_addr\":81920,\
        \"stack_size\":8192,\
        \"regs_values\":{\
            \"RAX\":255,\
            \"RBP\":81920,\
            \"RBX\":4660,\
            \"RCX\":0,\
            \"RDI\":73728,\
            \"RDX\":12345,\
            \"RIP\":65553,\
            \"RSI\":73728,\
            \"RSP\":90112,\
            \"R8\":0,\
            \"R9\":0,\
            \"R10\":0,\
            \"R11\":0,\
            \"R12\":0,\
            \"R13\":0,\
            \"R14\":0,\
            \"R15\":0},\
            \"memory\":{\"65536\":[176,255,102,187,52,18,102,186,57,48,102,137,23,102,137,95,16],\
            \"73728\":[57,48],\
            \"73744\":[52,18]\
    }}";

    fn run_code_x32(machine: &mut Machine) -> Result<()> {
        let mut emu = machine.unicorn.borrow();

        let x86_code: Vec<u8> = vec![
            0xb0, 0xff,                // mov al,0xff
            0x66, 0xbb, 0x34, 0x12,    // mov bx,0x1234
            0x66, 0xba, 0x39, 0x30,    // mov dx,12345
            0x66, 0x89, 0x17,          // mov [edi],dx
            0x66, 0x89, 0x5f, 0x10,    // mov [edi+16],bx
        ];

        reg_write!(emu, unicorn::RegisterX86::EIP as i32, machine.code_addr)?;
        let s_addr = machine.code_addr;
        mem_write!(emu, s_addr, &x86_code)?;
        emu_start!(emu, 
            s_addr,
            s_addr + (x86_code.len() as u64),
            10 * SECOND_SCALE,
            1000
        )?;

        Ok(())
    }

    fn run_code_x64(machine: &mut Machine) -> Result<()> {
        let mut emu = machine.unicorn.borrow();

        let x86_code: Vec<u8> = vec![
            0xb0, 0xff,                // mov al,0xff
            0x66, 0xbb, 0x34, 0x12,    // mov bx,0x1234
            0x66, 0xba, 0x39, 0x30,    // mov dx,12345
            0x66, 0x89, 0x17,          // mov [rdi],dx
            0x66, 0x89, 0x5f, 0x10,    // mov [rdi+16],bx
        ];

        reg_write!(emu, unicorn::RegisterX86::RIP as i32, machine.code_addr)?;
        let s_addr = machine.code_addr;
        mem_write!(emu, s_addr, &x86_code)?;
        emu_start!(emu, 
            s_addr,
            s_addr + (x86_code.len() as u64),
            10 * SECOND_SCALE,
            1000
        )?;

        Ok(())
    }

    fn create_cpu_context_x32_a() -> CpuContext {
        let regs_values: HashMap<Register, u64> = [ 
            (unicorn::RegisterX86::EAX,   255),
            (unicorn::RegisterX86::EBP, 12288),
            (unicorn::RegisterX86::EBX,  4660),
            (unicorn::RegisterX86::ECX,     0),
            (unicorn::RegisterX86::EDI,  8192),
            (unicorn::RegisterX86::EDX, 12345),
            (unicorn::RegisterX86::EIP,  4113),
            (unicorn::RegisterX86::ESI,  8192),
            (unicorn::RegisterX86::ESP, 16384),
        ].iter().map(|(reg,val)| { (Register {0: *reg}, *val) }).collect::<HashMap<_, _>>();

        let memory: HashMap<u64, Vec<u8>> = hashmap![
            4096 => vec![176,255,102,187,52,18,102,186,57,48,102,137,23,102,137,95,16],
            8192 => vec![57,48],
            8208 => vec![52,18],
        ];

        CpuContext {
            arch:       CpuArch::X86_32,
            code_addr:  0x01000,
            code_size:  0x01000,
            data_addr:  0x02000,
            data_size:  0x01000,
            stack_addr: 0x03000,
            stack_size: 0x01000,
            regs_values,
            memory,
        }
    }

    fn create_cpu_context_x64_a() -> CpuContext {
        let regs_values: HashMap<Register, u64> = [ 
            (unicorn::RegisterX86::RAX,   255),
            (unicorn::RegisterX86::RBP, 12288),
            (unicorn::RegisterX86::RBX,  4660),
            (unicorn::RegisterX86::RCX,     0),
            (unicorn::RegisterX86::RDI,  8192),
            (unicorn::RegisterX86::RDX, 12345),
            (unicorn::RegisterX86::RIP,  4113),
            (unicorn::RegisterX86::RSI,  8192),
            (unicorn::RegisterX86::RSP, 16384),
            (unicorn::RegisterX86::R8,      0),
            (unicorn::RegisterX86::R9,      0),
            (unicorn::RegisterX86::R10,     0),
            (unicorn::RegisterX86::R11,     0),
            (unicorn::RegisterX86::R12,     0),
            (unicorn::RegisterX86::R13,     0),
            (unicorn::RegisterX86::R14,     0),
            (unicorn::RegisterX86::R15,     0),
        ].iter().map(|(reg,val)| { (Register {0: *reg}, *val) }).collect::<HashMap<_, _>>();

        let memory: HashMap<u64, Vec<u8>> = hashmap![
            4096 => vec![176,255,102,187,52,18,102,186,57,48,102,137,23,102,137,95,16],
            8192 => vec![57,48],
            8208 => vec![52,18],
        ];

        CpuContext {
            arch:       CpuArch::X86_64,
            code_addr:  0x01000,
            code_size:  0x01000,
            data_addr:  0x02000,
            data_size:  0x01000,
            stack_addr: 0x03000,
            stack_size: 0x01000,
            regs_values,
            memory,
        }
    }

    #[test]
    fn test_cpu_context_x32() -> Result<()> {
        let mut cpu_context = CpuContext::new().arch(CpuArch::X86_32).build();
        let mut machine = Machine::new_from_context(&cpu_context)?;
        assert_eq!(run_code_x32(&mut machine).is_ok(), true);
        cpu_context.save(&mut machine)?;
        
        // Serialize it to a JSON string.
        let result = serde_json::to_string(&cpu_context);
        assert_eq!(result.is_ok(), true);
        if let Ok(json) = result {
            assert_eq!(CPUCONTEXT_JSON_X32_A, json);
            let new_cpu_context = serde_json::from_str::<CpuContext>(&json);
            assert_eq!(new_cpu_context.is_ok(), true);
            assert_eq!(cpu_context, new_cpu_context.unwrap());
        }

        Ok(())
    }

    #[test]
    fn test_cpu_context_x64() -> Result<()> {
        let mut cpu_context = CpuContext::new().arch(CpuArch::X86_64).build();
        let mut machine = Machine::new_from_context(&cpu_context)?;
        assert_eq!(run_code_x64(&mut machine).is_ok(), true);
        cpu_context.save(&mut machine)?;
        
        // Serialize it to a JSON string.
        let result = serde_json::to_string(&cpu_context);
        assert_eq!(result.is_ok(), true);
        if let Ok(json) = result {
            assert_eq!(CPUCONTEXT_JSON_X64_A, json);
            let new_cpu_context = serde_json::from_str::<CpuContext>(&json);
            assert_eq!(new_cpu_context.is_ok(), true);
            assert_eq!(cpu_context, new_cpu_context.unwrap());
        }

        Ok(())
    }

    #[test]
    fn test_serialize_cpu_context_x32() {
        let cpu_context = create_cpu_context_x32_a();
        let json = serde_json::to_string(&cpu_context);
        assert_eq!(json.is_ok(), true);
        assert_eq!(CPUCONTEXT_JSON_X32_A, json.unwrap());
    }

    #[test]
    fn test_serialize_cpu_context_x64() {
        let cpu_context = create_cpu_context_x64_a();
        let json = serde_json::to_string(&cpu_context);
        assert_eq!(json.is_ok(), true);
        assert_eq!(CPUCONTEXT_JSON_X64_A, json.unwrap());
    }

    #[test]
    fn test_deserialize_context_x32() {
        let expected_cpu_context = create_cpu_context_x32_a();
        let cpu_context = serde_json::from_str::<CpuContext>(CPUCONTEXT_JSON_X32_A);
        assert_eq!(cpu_context.is_ok(), true);
        assert_eq!(expected_cpu_context, cpu_context.unwrap());

        let cpu_context = CpuContext::new_from_json(CPUCONTEXT_JSON_X32_A);
        assert_eq!(cpu_context.is_ok(), true);
        assert_eq!(expected_cpu_context, cpu_context.unwrap());
    }

    #[test]
    fn test_deserialize_context_x64() {
        let expected_cpu_context = create_cpu_context_x64_a();
        let cpu_context = serde_json::from_str::<CpuContext>(CPUCONTEXT_JSON_X64_A);
        assert_eq!(cpu_context.is_ok(), true);
        assert_eq!(expected_cpu_context, cpu_context.unwrap());

        let cpu_context = CpuContext::new_from_json(CPUCONTEXT_JSON_X64_A);
        assert_eq!(cpu_context.is_ok(), true);
        assert_eq!(expected_cpu_context, cpu_context.unwrap());
    }

    #[test]
    fn test_save_restore_cpu_context_x32() -> Result<()> {
        let cpu_context1 = CpuContext::new_from_json(CPUCONTEXT_JSON_X32_A).unwrap();
        let mut machine = Machine::new(CpuArch::X86_32).unwrap();
        assert_eq!(cpu_context1.restore(&mut machine).is_ok(), true);

        // expected to fail because the default context has no registers defined
        let mut cpu_context2 = CpuContext::default();
        cpu_context2.save(&mut machine)?;
        assert_ne!(cpu_context1, cpu_context2);

        let mut cpu_context3 = CpuContext::new().arch(CpuArch::X86_32).build();
        cpu_context3.save(&mut machine)?;
        assert_eq!(cpu_context1, cpu_context3);

        let mut buf: Cursor<Vec<u8>> = Cursor::new(Vec::<u8>::new());
        let result = cpu_context3.write_to(&mut buf);
        assert_eq!(result.is_ok(), true);
        let json = buf.into_inner().iter().map(|&c| c as char).collect::<String>();
        assert_eq!(CPUCONTEXT_JSON_X32_A, json);

        Ok(())
    }

    #[test]
    fn test_save_restore_cpu_context_x64() -> Result<()> {
        let cpu_context1 = CpuContext::new_from_json(CPUCONTEXT_JSON_X64_A).unwrap();
        let mut machine = Machine::new(CpuArch::X86_64).unwrap();
        assert_eq!(cpu_context1.restore(&mut machine).is_ok(), true);

        // expected to fail because the default context has no registers defined
        let mut cpu_context2 = CpuContext::default();
        cpu_context2.save(&mut machine)?;
        assert_ne!(cpu_context1, cpu_context2);

        let mut cpu_context3 = CpuContext::new().arch(CpuArch::X86_64).build();
        cpu_context3.save(&mut machine)?;
        assert_eq!(cpu_context1, cpu_context3);

        let mut buf: Cursor<Vec<u8>> = Cursor::new(Vec::<u8>::new());
        let result = cpu_context3.write_to(&mut buf);
        assert_eq!(result.is_ok(), true);
        let json = buf.into_inner().iter().map(|&c| c as char).collect::<String>();
        assert_eq!(CPUCONTEXT_JSON_X64_A, json);

        Ok(())
    }

    #[test]
    fn test_save_cpu_context_x32() -> Result<()> {
        let mut cpu_context = CpuContext::new().arch(CpuArch::X86_32).build();
        let mut machine = Machine::new_from_context(&cpu_context).unwrap();
        assert_eq!(run_code_x64(&mut machine).is_ok(), true);
        cpu_context.save(&mut machine)?;

        let expected_cpu_context = create_cpu_context_x32_a();
        assert_eq!(cpu_context, expected_cpu_context);

        Ok(())
    }

    #[test]
    fn test_save_cpu_context_x64() -> Result<()> {
        let mut cpu_context = CpuContext::new().arch(CpuArch::X86_64).build();
        let mut machine = Machine::new_from_context(&cpu_context).unwrap();
        assert_eq!(run_code_x64(&mut machine).is_ok(), true);
        cpu_context.save(&mut machine)?;

        let expected_cpu_context = create_cpu_context_x64_a();
        assert_eq!(cpu_context, expected_cpu_context);

        Ok(())
    }

    #[test]
    fn test_restore_cpu_context_x32() {
        let cpu_context = CpuContext::new_from_json(CPUCONTEXT_JSON_X32_B).unwrap();
        let mut machine = Machine::new(CpuArch::X86_32).unwrap();
        assert_eq!(cpu_context.restore(&mut machine).is_ok(), true);

        assert_eq!(machine.code_addr, 0x10000);
        assert_eq!(machine.code_size, 0x02000);
        assert_eq!(machine.data_addr, 0x12000);
        assert_eq!(machine.data_size, 0x02000);
        assert_eq!(machine.stack_addr, 0x14000);
        assert_eq!(machine.stack_size, 0x02000);

        assert_eq!(machine.previous_inst_addr.len(), 1);
        assert_eq!(*machine.previous_inst_addr.first().unwrap(), machine.code_addr);
    }

    #[test]
    fn test_restore_cpu_context_x64() {
        let cpu_context = CpuContext::new_from_json(CPUCONTEXT_JSON_X64_B).unwrap();
        let mut machine = Machine::new(CpuArch::X86_64).unwrap();
        assert_eq!(cpu_context.restore(&mut machine).is_ok(), true);

        assert_eq!(machine.code_addr, 0x10000);
        assert_eq!(machine.code_size, 0x02000);
        assert_eq!(machine.data_addr, 0x12000);
        assert_eq!(machine.data_size, 0x02000);
        assert_eq!(machine.stack_addr, 0x14000);
        assert_eq!(machine.stack_size, 0x02000);

        assert_eq!(machine.previous_inst_addr.len(), 1);
        assert_eq!(*machine.previous_inst_addr.first().unwrap(), machine.code_addr);
    }

    #[test]
    fn test_read_write_cpu_context_x32() {
        let mut cpu_context = CpuContext::new().arch(CpuArch::X86_32).build();
        let mut bytes = CPUCONTEXT_JSON_X32_A.as_bytes();
        let result = cpu_context.read_from(&mut bytes);
        assert_eq!(result.is_ok(), true);

        let mut buf: Cursor<Vec<u8>> = Cursor::new(Vec::<u8>::new());
        let result = cpu_context.write_to(&mut buf);
        assert_eq!(result.is_ok(), true);
        let json = buf.into_inner().iter().map(|&c| c as char).collect::<String>();
        assert_eq!(CPUCONTEXT_JSON_X32_A, json);
    }

    #[test]
    fn test_read_write_cpu_context_x64() {
        let mut cpu_context = CpuContext::new().arch(CpuArch::X86_64).build();
        let mut bytes = CPUCONTEXT_JSON_X64_A.as_bytes();
        let result = cpu_context.read_from(&mut bytes);
        assert_eq!(result.is_ok(), true);

        let mut buf: Cursor<Vec<u8>> = Cursor::new(Vec::<u8>::new());
        let result = cpu_context.write_to(&mut buf);
        assert_eq!(result.is_ok(), true);
        let json = buf.into_inner().iter().map(|&c| c as char).collect::<String>();
        assert_eq!(CPUCONTEXT_JSON_X64_A, json);
    }

    #[test]
    fn test_write_to_file_x32() {
        let path = Path::new("./tmp_32.txt");
        let file = File::create(path);
        assert_eq!(file.is_ok(), true);
        let mut file = BufWriter::new(file.unwrap());
        let mut cpu_context = CpuContext::new().arch(CpuArch::X86_32).build();
        let mut bytes = CPUCONTEXT_JSON_X32_A.as_bytes();
        let result = cpu_context.read_from(&mut bytes);
        assert_eq!(result.is_ok(), true);
        let result = cpu_context.write_to(&mut file);
        assert_eq!(result.is_ok(), true);
    }

    #[test]
    fn test_write_to_file_x64() {
        let path = Path::new("./tmp_64.txt");
        let file = File::create(path);
        assert_eq!(file.is_ok(), true);
        let mut file = BufWriter::new(file.unwrap());
        let mut cpu_context = CpuContext::new().arch(CpuArch::X86_64).build();
        let mut bytes = CPUCONTEXT_JSON_X64_A.as_bytes();
        let result = cpu_context.read_from(&mut bytes);
        assert_eq!(result.is_ok(), true);
        let result = cpu_context.write_to(&mut file);
        assert_eq!(result.is_ok(), true);
    }
}