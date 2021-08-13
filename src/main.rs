use std::str;
use std::fmt::Debug;
use std::path::PathBuf;
use std::fs::File;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use rustyline::config::EditMode;
use rustyline::config::Builder;
use ansi_term::Colour::Red;
use ansi_term::Colour::Green;
use ansi_term::Colour::Yellow;
use structopt::StructOpt;
use anyhow::{Context, Result};

pub mod hexprint;
pub mod squeezer;
pub mod machine;
pub mod parser;
pub mod lexer;

use machine::interface::Machine;
use machine::context::CpuContext;
use machine::cpuarch::CpuArch;
use parser::Parser;
use parser::Command;
use parser::ParseError;
use crate::lexer::Token;
//use crate::ok_or_error;


#[derive(Debug, StructOpt)]
#[structopt(name = "rudi", about = "rudi- RUst Debugger Interactive")]
struct Options {
    /// Execute instructions in batch execution mode
    #[structopt(short, long)]
    batch: Option<String>,

    /// File from which to read initial cpu context
    #[structopt(short, long, parse(from_os_str))]
    context: Option<PathBuf>,

    /// File where to save cpu context before exit 
    #[structopt(short, long, parse(from_os_str))]
    save: Option<PathBuf>,
    
    /// Select processor architecture
    #[structopt(long, possible_values = &CpuArch::variants(), case_insensitive = true, default_value = "X86_32")]
    arch: CpuArch,
}


fn command_define(parser: &mut Parser, params: &Vec<Token>) -> anyhow::Result<()> {
    if params.len() == 0 {
        for (name, value) in parser.constants() {
            println!("{:20} {:#10x} {:12}", name, value, value);
        }
    }
    Ok(())
}

fn command_eval(parser: &mut Parser, params: &Vec<Token>) -> anyhow::Result<()> {
    if params.len() == 1 {
        let value = &params[0];
        match value {
            Token::Integer(value) => {
                let index = parser.add_value(*value);
                println!("${} => {}", index, value);
            },
            _  => return Err(anyhow::Error::new(ParseError::ParameterError)),
        }
    } else {
        return Err(anyhow::Error::new(ParseError::ParameterError));
    }
    Ok(())
}


fn execute_asm(m: &mut Machine, parser: &mut Parser, line: &str) -> anyhow::Result<()> {
    let parsed_line = parser.parse_asm(&line)?;
    let code = m.asm(parsed_line.to_string(), 0)?;
    println!("{} : {} {} :{}",
        Yellow.paint("mnemonic"),
        line.trim(),
        Yellow.paint("hex"),
        code.bytes.iter().map(|x| format!(" {:02x}", x)).collect::<String>()
    );
    m.execute_instruction(code.bytes)?;
    m.print_code()?;
    m.print_register()?;
    m.print_flags()?;
    m.print_data()?;
    m.print_stack()?;

    Ok(())
}

fn run_interactive(m: &mut Machine, parser: &mut Parser) -> anyhow::Result<()> {
    m.print_version();
    m.init_cache()?;
    m.print_register()?;
    m.print_flags()?;
    m.print_data()?;
    m.print_stack()?;

    let editor_config = Builder::new().edit_mode(EditMode::Vi).build();
    let mut rl = Editor::<()>::with_config(editor_config);
    if rl.load_history("history.txt").is_err() {
        println!("Note: No previous history.");
    }
    loop {
        let input = rl.readline(Green.paint(">> ").to_string().as_str());
        match input {
            Ok(line) => {
                let result: Result<()> = match parser.parse_cmd(&line) {
                    Some(Ok((command,params))) => {
                        match command {
                            Command::Quit      => { break; },
                            Command::Eval      => command_eval(parser, &params),
                            Command::Define    => command_define(parser, &params),
                            _                  => { Ok(())}, 
                        }
                    },
                    Some(Err(err)) => {
                        Err(anyhow::Error::new(ParseError::ParameterError).context(format!("{:?}", err)))
                    },
                    None => {
                        execute_asm(m, parser, &line)
                    },
                };
                ok_or_error!(result);
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
                eprintln!("{}: '{:?}'", Red.paint("ERROR"), err);
                break;
            }
        }
    }
    if rl.save_history("history.txt").is_err() {
        println!("Note: Cannot write to history file.");
    }

    Ok(())
}

fn run_batch(m: &mut Machine, parser: &Parser, inst_vec: Vec<String>) -> anyhow::Result<()> {
    for inst in inst_vec {
        let inst = parser.parse_asm(&inst)?;
        let code = m.asm(inst.to_string(), 0)?;
        
        println!("{} : {} {} : {}",
            Yellow.paint("mnemonic"),
            inst.trim(),
            Yellow.paint("hex"),
            code.bytes.iter().map(|x| format!(" {:02x}", x)).collect::<String>()
        );
        
        m.execute_instruction(code.bytes)?;
        m.print_register()?;
    }

    Ok(())
}

fn run(options: &Options) -> anyhow::Result<()> {
    let save_file = match &options.save {
        Some(path) => Some(File::create(path)?),
        None       => None,
    };

    let mut cpu_context = match &options.context {
        Some(path) => {
            let mut file = File::open(path)
                .with_context(|| format!("ERROR: Cannot read from context file"))?;
            let mut cpu_context = CpuContext::new().arch(options.arch).build();
            cpu_context.read_from(&mut file)
                .with_context(|| format!("ERROR: Cannot read from context file"))?;

            cpu_context
        },
        _ => CpuContext::new().arch(options.arch).build(),
    };

    let mut machine = match options.arch {
        CpuArch::X86_32 => Machine::new_from_context(&cpu_context)?, 
        CpuArch::X86_64 => Machine::new_from_context(&cpu_context)?, 
    };

    let mut parser = Parser::new();

    if let Some(inst_str) = &options.batch {
        let inst_vec = inst_str.split(';')
                          .into_iter()
                          .map(|s| s.to_lowercase())
                          .collect::<Vec<String>>();
        run_batch(&mut machine, &mut parser, inst_vec)?;
    } else {
        run_interactive(&mut machine, &mut parser)?;
    }

    if let Some(mut file) = save_file {
        cpu_context.save(&mut machine)?;
        cpu_context.write_to(&mut file)
            .with_context(|| format!("ERROR: Cannot write to context save file"))?;
    };

    Ok(())
}

fn main() {
    let options = Options::from_args();
    ok_or_error!(run(&options));
}