use std::str;
use std::fmt;
use std::fmt::Debug;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use rustyline::config::EditMode;
use rustyline::config::Builder;
use ansi_term::Colour::Red;
use ansi_term::Colour::Green;
use ansi_term::Colour::Yellow;
use clap::{Arg, App, arg_enum, value_t};

pub mod hexprint;
pub mod squeezer;
pub mod machine;
pub mod parser;


use machine::interface::Machine;
use parser::Parser;


arg_enum!{
    #[derive(Debug)]
    pub enum Arch {
        X32,
        X64,
    }
}


fn run_interactive<T>(mut m: Machine, parser: Parser<T>)
where
    T:
        Clone +
        num_traits::Num +
        fmt::Debug +
        fmt::LowerHex
{
    m.print_version();
    m.init_cache();
    m.print_register();
    m.print_data();
    m.print_stack();

    let editor_config = Builder::new().edit_mode(EditMode::Vi).build();
    let mut rl = Editor::<()>::with_config(editor_config);
    if rl.load_history("history.txt").is_err() {
        println!("Note: No previous history.");
    }
    loop {
        let input = rl.readline(Green.paint(">> ").to_string().as_str());
        match input {
            Ok(line) => {
                let command = parser.parse_cmd(&line);
                if command.is_none() {
                    let parsed_line = parser.parse_asm(&line).unwrap();
                    let result = m.asm(parsed_line.to_string(), 0);
                    match result {
                        Ok(r) => {
                            println!("{} : {} {} :{}",
                                Yellow.paint("mnemonic"),
                                line.trim(),
                                Yellow.paint("hex"),
                                r.bytes.iter().map(|x| format!(" {:02x}", x)).collect::<String>()
                            );
                            let result = m.execute_instruction(r.bytes);
                            if let Err(e) = result {
                                println!("{}: failed to execute instruction, '{}'",
                                    Red.paint("ERROR"), e.msg());
                            } else {
                                m.print_code();
                                m.print_register();
                                m.print_data();
                                m.print_stack();
                            }
                        }
                        Err(e) => println!("{}: failed to assemble, '{}'",
                                      Red.paint("ERROR"), e.msg()),
                    }
                } else {
                }
                rl.add_history_entry(line.as_str());
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
    if rl.save_history("history.txt").is_err() {
        println!("Note: Cannot write to history file.");
    }
}

fn run_batch<T>(mut m: Machine, parser: Parser<T>, inst_vec: Vec<String>)
where
    T:
        Clone +
        num_traits::Num +
        fmt::Debug +
        fmt::LowerHex
{
    for inst in inst_vec {
        if let Ok(inst) = parser.parse_asm(&inst) {
            let result = m.asm(inst.to_string(), 0);
            match result {
                Ok(r) => {
                    println!("{} : {} {} : {}",
                        Yellow.paint("mnemonic"),
                        inst.trim(),
                        Yellow.paint("hex"),
                        r
                    );
                    let result = m.execute_instruction(r.bytes);
                    if let Err(e) = result {
                        println!("{}: failed to execute instruction, '{}'",
                            Red.paint("ERROR"), e.msg());
                    }
                    m.print_register();
                }
                Err(e) => {
                    println!("{}: failed to assemble, '{}'",
                              Red.paint("ERROR"), e.msg());
                    break;
                },
            }
        } else {
            println!("{}: cannot parse integer", Red.paint("ERROR"));
            break;
        }
    }
}


fn main() {
    let args = App::new("rudi")
        .version("0.1.0")
        .author("Ralf R. <rdrcode@gmx.eu>")
        .about("RUst Debugger Interactive")
        .arg(Arg::with_name("arch")
            .short("m")
            .long("arch")
            .takes_value(true)
            .required(true)
            .help("machine architecure"))
        .arg(Arg::with_name("batch")
            .short("b")
            .long("batch")
            .takes_value(true)
            .required(false)
            .help("batch instruction sequence"))
        .get_matches();

    let arch = value_t!(args, "arch", Arch).unwrap_or_else(|e| e.exit());

    if let Some(inst_str) = args.value_of("batch") {
        let inst_vec = inst_str.split(';')
                         .into_iter()
                         .map(|s| s.to_lowercase())
                         .collect::<Vec<String>>();
        match arch {
            Arch::X32 => run_batch(machine::x32::new(), Parser::<u32>::new(), inst_vec),
            Arch::X64 => run_batch(machine::x64::new(), Parser::<u64>::new(), inst_vec),
        };
    } else {
        match arch {
            Arch::X32 => run_interactive(machine::x32::new(), Parser::<u32>::new()),
            Arch::X64 => run_interactive(machine::x64::new(), Parser::<u64>::new()),
        };
    }

}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;
    use unicorn::{Cpu, CpuX86};
    use std::convert::TryFrom;


    #[test]
    fn x86_intr_callback() {
        #[derive(PartialEq, Debug)]
        struct IntrExpectation(u32);
        let expect = IntrExpectation(0x80);
        let intr_cell = Rc::new(RefCell::new(IntrExpectation(0)));

        let callback_intr = intr_cell.clone();
        let callback = move |_: &unicorn::Unicorn, intno: u32| {
            *callback_intr.borrow_mut() = IntrExpectation(intno);
        };

        let x86_code32: Vec<u8> = vec![0xcd, 0x80]; // INT 0x80;

        let mut emu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
        assert_eq!(
            emu.mem_map(0x1000, 0x4000, unicorn::Protection::ALL),
            Ok(())
        );
        assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));

        let hook = emu
            .add_intr_hook(callback)
            .expect("failed to add intr hook");

        assert_eq!(
            emu.emu_start(
                0x1000,
                0x1000 + x86_code32.len() as u64,
                10 * unicorn::SECOND_SCALE,
                1000
            ),
            Ok(())
        );
        assert_eq!(expect, *intr_cell.borrow());
        assert_eq!(emu.remove_hook(hook), Ok(()));
    }

    #[test]
    fn x86_intr_hook() {
        const INTR_ID:   u8 =   0x80;
        const INTR_EAX: u32 = 0x1234;
        #[derive(PartialEq, Debug)]
        struct IntrExpectation(u8, u32);
        let expect = IntrExpectation(INTR_ID, INTR_EAX);
        let intr_cell = Rc::new(RefCell::new(IntrExpectation(0, 0)));

        let callback_intr = intr_cell.clone();
        let callback = move |engine: &unicorn::Unicorn, intno: u32| {
            let reg_eax: u32 = u32::try_from(engine.reg_read(unicorn::RegisterX86::EAX as i32).unwrap()).unwrap();
            *callback_intr.borrow_mut() = IntrExpectation(intno as u8, reg_eax);
        };

        let x86_code32: Vec<u8> = vec![0xcd, INTR_ID]; // INT 0x80;

        let mut emu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
        assert_eq!(
            emu.mem_map(0x1000, 0x4000, unicorn::Protection::ALL),
            Ok(())
        );
        assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));

        let hook = emu
            .add_intr_hook(callback)
            .expect("failed to add intr hook");

        emu.reg_write(unicorn::RegisterX86::EAX, INTR_EAX.into())
            .expect("failed to write eax");
        assert_eq!(Ok(INTR_EAX), u32::try_from(emu.reg_read(unicorn::RegisterX86::EAX).unwrap()));

        assert_eq!(
            emu.emu_start(
                0x1000,
                0x1000 + x86_code32.len() as u64,
                10 * unicorn::SECOND_SCALE,
                1000
            ),
            Ok(())
        );
        assert_eq!(expect, *intr_cell.borrow());
        assert_eq!(emu.remove_hook(hook), Ok(()));
    }
}
