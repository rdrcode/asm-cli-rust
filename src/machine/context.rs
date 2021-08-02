use std::collections::HashMap;
use serde::{Deserialize, Serialize};
//use serde_json::Result;


#[derive(Serialize, Deserialize, Debug)]
pub struct Context {
    pub code_addr:   u64,
    pub code_size:   u64,
    pub data_addr:   u64,
    pub data_size:   u64,
    pub stack_addr:  u64,
    pub stack_size:  u64,
    pub regs_values: HashMap<String, u64>,

    #[serde(skip)]
    pub regs_map:    HashMap<String, unicorn::RegisterX86>,
}

impl Context {

    pub fn save(&mut self, emu: &unicorn::UnicornHandle) {
        let regs: Vec<_> = self.regs_values.keys().map(|s| s.to_string()).collect();
        for reg in regs {
            let p = self.regs_values.get_mut(&reg).unwrap();
            *p = emu.reg_read(*self.regs_map.get(&reg).unwrap() as i32).unwrap();
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    //use serde_json::Result;
    use crate::machine;
    use std::collections::HashMap;
    use maplit::hashmap;
    use unicorn::unicorn_const::{SECOND_SCALE};


    const CODE_ADDR:  u64 = 0x08048000;
    const CODE_SIZE:  u64 = 0x00001000;
    const DATA_ADDR:  u64 = CODE_ADDR + CODE_SIZE;
    const DATA_SIZE:  u64 = 0x00001000;
    const STACK_ADDR: u64 = 0x0c000000;
    const STACK_SIZE: u64 = 0x00001000;

    #[test]
    fn serialize_context_x32() {
        let regs_map: HashMap<String, unicorn::RegisterX86> = hashmap! {
                "eax".to_owned() => unicorn::RegisterX86::EAX,
                "ebx".to_owned() => unicorn::RegisterX86::EBX,
                "ecx".to_owned() => unicorn::RegisterX86::ECX,
                "edx".to_owned() => unicorn::RegisterX86::EDX,
                "esi".to_owned() => unicorn::RegisterX86::ESI,
                "edi".to_owned() => unicorn::RegisterX86::EDI,
                "eip".to_owned() => unicorn::RegisterX86::EIP,
                "ebp".to_owned() => unicorn::RegisterX86::EBP,
                "esp".to_owned() => unicorn::RegisterX86::ESP,
                "flags".to_owned() => unicorn::RegisterX86::EFLAGS,
                "cs".to_owned() => unicorn::RegisterX86::CS,
                "ss".to_owned() => unicorn::RegisterX86::SS,
                "ds".to_owned() => unicorn::RegisterX86::DS,
                "es".to_owned() => unicorn::RegisterX86::ES,
                "fs".to_owned() => unicorn::RegisterX86::FS,
                "gs".to_owned() => unicorn::RegisterX86::GS,
        };

        let regs_values: HashMap<String, u64> = regs_map
            .iter()
            .map(|(reg_name,_id)| {(reg_name.to_string(), 0)})
            .collect::<HashMap<_, _>>();
       
        let mut context = Context {
            code_addr: CODE_ADDR,
            code_size: CODE_SIZE,
            data_addr: DATA_ADDR,
            data_size: DATA_SIZE,
            stack_addr: STACK_ADDR,
            stack_size: STACK_SIZE,
            regs_map,
            regs_values,
        };

        let mut machine = machine::x32::new_from_context(&context);
        let mut emu = machine.unicorn.borrow();

        let x86_code: Vec<u8> = vec![
            0xb0, 0xff,                // mov al,0xff
            0x66, 0xbb, 0x34, 0x12,    // mov bx,0x1234
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
        if let Ok(result) = result {
            println!("{}", result);
        }
    }

}