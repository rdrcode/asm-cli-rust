use ansi_term::Colour::{Blue, Purple, Yellow};
use keystone::{AsmResult, Error};
use std::collections::HashMap;
use std::convert::TryFrom;
use capstone::prelude::*;

use crate::hexprint::Printer;


pub struct Machine<'a> {
    pub register_map: HashMap<&'a str, unicorn::RegisterX86>,
    pub keystone: keystone::Keystone,
    pub capstone: Capstone,
    pub unicorn: unicorn::Unicorn,
    pub sorted_reg_names: Vec<&'a str>,
    pub word_size: usize,
    pub previous_reg_value: HashMap<&'a str, u64>,
    pub sp: unicorn::RegisterX86,
    pub ip: unicorn::RegisterX86,
    pub flags: unicorn::RegisterX86,
    pub previous_inst_addr: Vec<u64>,
    pub code_addr: u64,
    pub code_size: u64,
    pub data_addr: u64,
    pub data_size: u64,
    pub stack_top: u64,
    pub printer: Printer,
    pub context: Option<unicorn::Context>,
}

impl<'a> Machine<'a> {

    pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
        ::std::slice::from_raw_parts(
            (p as *const T) as *const u8,
            ::std::mem::size_of::<T>(),
        )
    }

    pub fn save_context(&self) {
        if let Some(context) = &self.context {
            let bytes: &[u8] = unsafe { Machine::<'a>::any_as_u8_slice(&context) };
            println!("{:?}", ::std::mem::size_of::<unicorn::Context>());
            println!("{:?}", bytes.len());
            println!("{:?}", bytes);
        }
    }

    pub fn print_version(&self) {
        //let (major, minor) = unicorn::unicorn_version();
        //println!("unicorn version: {}.{}", major, minor);

        //let (major, minor) = keystone::bindings_version();
        //println!("keystone version: {}.{}", major, minor);
    }

    pub fn print_register(&mut self) {
        let emu = self.unicorn.borrow();
        println!(
            "{}",
            Yellow.paint("----------------- cpu context -----------------")
        );

        for &reg_name in &self.sorted_reg_names {
            if reg_name == "end" {
                println!();
                continue;
            }

            let &uc_reg = self.register_map.get(reg_name).unwrap();
            let reg_val = emu.reg_read(uc_reg as i32).unwrap();
            let previous_reg_val = *self.previous_reg_value.get(reg_name).unwrap();
            let reg_val_str: String;
            match self.word_size {
                4 => reg_val_str = format!("0x{:08x}", reg_val),
                8 => reg_val_str = format!("0x{:016x}", reg_val),
                _ => unreachable!(),
            }

            if previous_reg_val != reg_val {
                print!("{:3} : {} ", reg_name, Blue.paint(reg_val_str));
                self.previous_reg_value.insert(reg_name, reg_val);
            } else {
                print!("{:3} : {} ", reg_name, reg_val_str);
            }
        }
    }

    pub fn asm(&self, str: String, address: u64) -> Result<AsmResult, Error> {
        return self.keystone.asm(str, address);
    }

    pub fn execute_instruction(&mut self, byte_arr: Vec<u8>) -> Result<u64,unicorn::unicorn_const::uc_error> {
        let mut emu = self.unicorn.borrow();
        let cur_ip_val = emu.reg_read(self.ip as i32).unwrap();
        let _ = emu.mem_write(cur_ip_val, &byte_arr);
        let result = emu.emu_start(
            cur_ip_val,
            cur_ip_val + u64::try_from(byte_arr.len()).unwrap(),
            10 * unicorn::unicorn_const::SECOND_SCALE,
            1000,
        );
        let new_ip_val = emu.reg_read(self.ip as i32).unwrap();
        self.previous_inst_addr.push(new_ip_val);

        match result {
            Ok(_) => Ok(new_ip_val),
            Err(e) => Err(e),
        }
    }

    pub fn print_code(&mut self) {
        let emu = self.unicorn.borrow();
        println!(
            "{}",
            Purple.paint("----------------- code segment -----------------")
        );
        println!("{:08x?}", self.previous_inst_addr);

        if self.previous_inst_addr.len() >= 2 {
            let s_addr = self.previous_inst_addr.first().unwrap();
            let e_addr = self.previous_inst_addr.last().unwrap();
            let len = e_addr - s_addr;

            if let Ok(v) = emu.mem_read_as_vec(*s_addr, usize::try_from(len).unwrap()) {
                //let mut bytes: &[u8];
                let insns = self
                                .capstone
                                .disasm_count(&v[..],
                                              *s_addr,
                                              self.previous_inst_addr.len()-1).unwrap();
                for i in insns.iter() {
                    println!("{:08x} {:8} {}",
                             i.address(),
                             i.mnemonic().unwrap(),
                             i.op_str().unwrap());
                }
            }
        }

    }

    pub fn init_cache(&mut self) {
        let emu = self.unicorn.borrow();
        let mem_data = emu
            .mem_read_as_vec(self.data_addr as u64, 5 * 16)
            .unwrap();

        self.printer.display_offset(self.data_addr);
        self.printer.init_cache(mem_data.as_slice());
    }

    pub fn print_data(&mut self) {
        let emu = self.unicorn.borrow();
        println!(
            "{}",
            Purple.paint("----------------- data segment -----------------")
        );
        let mem_data = emu
            .mem_read_as_vec(self.data_addr as u64, 5 * 16)
            .unwrap();

        self.printer.display_offset(self.data_addr);
        self.printer.print_all(mem_data.as_slice()).unwrap();
        self.printer.reset();
    }

    pub fn print_stack(&mut self) {
        let emu = self.unicorn.borrow();
        println!(
            "{}",
            Purple.paint("----------------- stack segment -----------------")
        );

        let start_address = self.stack_top - u64::try_from(self.word_size).unwrap() * 4 * 8;
        let mem_data = emu
            .mem_read_as_vec(start_address as u64, 5 * 16)
            .unwrap();

        self.printer.display_offset(start_address);
        self.printer.print_all(mem_data.as_slice()).unwrap();
        self.printer.reset();
    }

    pub fn print_flags(&mut self) {
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

        let flag_val = emu.reg_read(self.flags as i32).unwrap();
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
    }
}
