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
        fmt::LowerHex +
        parser::TwosComplement
{

    m.print_version();
    m.init_cache();
    m.print_register();
    m.print_flags();
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
                    match parser.parse_asm(&line) {
                        Ok(parsed_line) => {
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
                                        println!("{}: failed to execute instruction, '{:?}'",
                                            Red.paint("ERROR"), e);
                                    } else {
                                        m.print_code();
                                        m.print_register();
                                        m.print_flags();
                                        m.print_data();
                                        m.print_stack();
                                    }
                                }
                                Err(e) => println!("{}: failed to assemble, '{:?}'",
                                              Red.paint("ERROR"), e),
                            }
                        },
                        Err(e) => println!("{}: failed to assemble, '{:?}'",
                                      Red.paint("ERROR"), e),
                    };
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
        fmt::LowerHex +
        parser::TwosComplement
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
                        println!("{}: failed to execute instruction, '{:?}'",
                            Red.paint("ERROR"), e);
                    }
                    m.print_register();
                }
                Err(e) => {
                    println!("{}: failed to assemble, '{:?}'",
                              Red.paint("ERROR"), e);
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
