use std::fmt;
use std::convert::TryFrom;
use std::io::{Read,Write};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use serde::{Deserialize, Serialize, Serializer};
use serde::de::{Deserializer, Visitor};
use itertools::Itertools;


#[derive(Copy,Clone)]
pub struct Register(unicorn::RegisterX86);


#[derive(Deserialize,Serialize,PartialEq,Debug)]
pub struct Context {
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

impl Context {

    const CODE_ADDR:  u64 = 0x00001000;
    const CODE_SIZE:  u64 = 0x00001000;
    const DATA_ADDR:  u64 = Context::CODE_ADDR + Context::CODE_SIZE;
    const DATA_SIZE:  u64 = 0x00001000;
    const STACK_ADDR: u64 = Context::DATA_ADDR + Context::DATA_SIZE;
    const STACK_SIZE: u64 = 0x00001000;

    pub fn new_x86_32() -> Self {
        let regs_values: HashMap<Register, u64> = Context::regs_x86_32()
        .iter()
        .map(|reg| {(*reg, 0 as u64)})
        .collect();

        Context {
            code_addr:  Context::CODE_ADDR,
            code_size:  Context::CODE_SIZE,
            data_addr:  Context::DATA_ADDR,
            data_size:  Context::DATA_SIZE,
            stack_addr: Context::STACK_ADDR,
            stack_size: Context::STACK_SIZE,
            regs_values,
            memory:     HashMap::new(),
        }
    }

    pub fn code_segment(&mut self, addr: u64, size: u64) -> &Self {
        self.code_addr = addr;
        self.code_size = size;
        self
    }

    pub fn data_segment(&mut self, addr: u64, size: u64) -> &Self {
        self.data_addr = addr;
        self.data_size = size;
        self
    }

    pub fn stack_segment(&mut self, addr: u64, size: u64) -> &Self {
        self.stack_addr = addr;
        self.stack_size = size;
        self
    }

    pub fn write_to<W: Write>(&self, f: &mut W) -> Result<usize, std::io::Error> {
        if let Ok(json_str) = serde_json::to_string(self) {
            f.write(json_str.as_bytes())
        } else {
            Ok(0)
        }
    }

    pub fn read_from<R: Read>(&mut self, f: &mut R) -> Result<(), std::io::Error> {
        let context: Context = serde_json::from_reader(f)?;
        *self = context;
        Ok(())
    }

    pub fn regs_x86_32() -> Vec<Register> {
        [
            unicorn::RegisterX86::EAX,
            unicorn::RegisterX86::EBX,
            unicorn::RegisterX86::ECX,
            unicorn::RegisterX86::EDX,
            unicorn::RegisterX86::ESI,
            unicorn::RegisterX86::EDI,
            unicorn::RegisterX86::EIP,
            unicorn::RegisterX86::EBP,
            unicorn::RegisterX86::ESP,
            //unicorn::RegisterX86::EFLAGS,
            //unicorn::RegisterX86::CS,
            //unicorn::RegisterX86::SS,
            //unicorn::RegisterX86::DS,
            //unicorn::RegisterX86::ES,
            //unicorn::RegisterX86::FS,
            //unicorn::RegisterX86::GS,
        ].iter().map(|reg| { Register {0: *reg} }).collect()
    }

    fn read_memory(&mut self, emu: &unicorn::UnicornHandle, addr: u64, size: u64) {
        let mem_data = emu
            .mem_read_as_vec(addr as u64, usize::try_from(size).unwrap())
            .unwrap();

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
    }

    pub fn save(&mut self, emu: &unicorn::UnicornHandle) {
        for (&reg,val) in self.regs_values.iter_mut() {
            *val = emu.reg_read(reg).unwrap();
        }

        self.read_memory(emu, self.code_addr, self.code_size);
        self.read_memory(emu, self.data_addr, self.data_size);
        self.read_memory(emu, self.stack_addr, self.stack_size);
    }

    pub fn restore(&self, emu: &mut unicorn::UnicornHandle) {
        for (reg,val) in self.regs_values.iter() {
            println!("{:?}: {:?}", *reg, *val);
            emu.reg_write(*reg, *val).unwrap();
        }

        for (addr, bytes) in &self.memory {
            println!("W: {:08x}: {:?}", *addr, bytes);
            emu.mem_write(*addr, bytes).unwrap();
        }
    }
}

impl From<Register> for i32 {
    fn from(reg: Register) -> Self {
        reg.0 as i32
    }
}

impl From<&str> for Register {
    fn from(s: &str) -> Self {
        let mut result = Register{0: unicorn::RegisterX86::INVALID};
        for reg in Context::regs_x86_32() {
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


#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::BufWriter;
    use std::path::Path;
    use std::io::Cursor;
    use super::*;
    use crate::machine;
    use unicorn::unicorn_const::{SECOND_SCALE};

    const CONTEXT_JSON: &str = "{\
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

//        \"CS\":0,\
//        \"DS\":0,\
//        \"EFLAGS\":0,\
//        \"ES\":0,\
//        \"FS\":0,\
//        \"GS\":0},\
//        \"SS\":0},\

    #[test]
    fn serialize_context_x32() {
        let mut context = Context::new_x86_32();
        let mut machine = machine::x32::new_from_context(&context);
        let mut emu = machine.unicorn.borrow();

        let x86_code: Vec<u8> = vec![
            0xb0, 0xff,                // mov al,0xff
            0x66, 0xbb, 0x34, 0x12,    // mov bx,0x1234
            0x66, 0xba, 0x39, 0x30,    // mov dx,12345
            0x66, 0x89, 0x17,          // mov [edi],dx
            0x66, 0x89, 0x5f, 0x10,    // mov [edi+16],bx
        ];
        assert_eq!(emu.mem_write(context.code_addr, &x86_code), Ok(()));
        let result = emu.emu_start(
            context.code_addr,
            context.code_addr + (x86_code.len() as u64),
            10 * SECOND_SCALE,
            1000,
        );
        assert_eq!(result, Ok(()));
        context.save(&emu);

        // Serialize it to a JSON string.
        let result = serde_json::to_string(&context);
        assert_eq!(result.is_ok(), true);
        if let Ok(json) = result {
            println!("SERIALIZED: '{:?}'", json);
            assert_eq!(CONTEXT_JSON, json);
            let new_context = serde_json::from_str::<Context>(&json);
            assert_eq!(new_context.is_ok(), true);
            assert_eq!(context, new_context.unwrap());
        }
    }

    #[test]
    fn test_save_restore_context_x32() {
        let mut context1 = Context::new_x86_32();
        let mut bytes = CONTEXT_JSON.as_bytes();
        let result = context1.read_from(&mut bytes);
        let mut machine = machine::x32::new_from_context(&context1);
        let mut emu = machine.unicorn.borrow();


        assert_eq!(result.is_ok(), true);
        context1.restore(&mut emu);

        let mut context2 = Context::new_x86_32();
        context2.save(&emu);
        assert_eq!(context1, context2);

        let mut buf: Cursor<Vec<u8>> = Cursor::new(Vec::<u8>::new());
        let result = context2.write_to(&mut buf);
        assert_eq!(result.is_ok(), true);
        let json = buf.into_inner().iter().map(|&c| c as char).collect::<String>();
        assert_eq!(CONTEXT_JSON, json);
    }

    #[test]
    fn test_read_write_context_x32() {
        let mut context = Context::new_x86_32();
        let mut bytes = CONTEXT_JSON.as_bytes();
        let result = context.read_from(&mut bytes);
        assert_eq!(result.is_ok(), true);

        let mut buf: Cursor<Vec<u8>> = Cursor::new(Vec::<u8>::new());
        let result = context.write_to(&mut buf);
        assert_eq!(result.is_ok(), true);
        let json = buf.into_inner().iter().map(|&c| c as char).collect::<String>();
        assert_eq!(CONTEXT_JSON, json);
    }

    #[test]
    fn test_write_to_file_x32() {
        let path = Path::new("./tmp.txt");
        let file = File::create(path);
        assert_eq!(file.is_ok(), true);
        let mut file = BufWriter::new(file.unwrap());
        let mut context = Context::new_x86_32();
        let mut bytes = CONTEXT_JSON.as_bytes();
        let result = context.read_from(&mut bytes);
        assert_eq!(result.is_ok(), true);
        let result = context.write_to(&mut file);
        assert_eq!(result.is_ok(), true);
    }

    #[test]
    fn register_to_from_x32() {
        for reg in Context::regs_x86_32() {
            let name = reg.to_string();
            let r = Register::from(name.as_str());
            assert_eq!(reg, r);
        }
    }
}