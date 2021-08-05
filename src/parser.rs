extern crate num_traits;

use std::str;
use std::fmt;
use std::fmt::Debug;
use std::collections::HashMap;
use std::collections::HashSet;
use regex::RegexSet;
use thiserror::Error;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use crate::machine::context::Register;


pub trait TwosComplement {
    fn twos_complement(&self) -> Self;
}

impl TwosComplement for u32 {
    fn twos_complement(&self) -> Self {
        (!self).wrapping_add(1)
    }
}

impl TwosComplement for u64 {
    fn twos_complement(&self) -> Self {
        (!self).wrapping_add(1)
    }
}


/// ParseError enumerates all possible errors returned by this library.
#[derive(Error, Debug, PartialEq)]
pub enum ParseError {
//pub enum ParseError<T: Debug + Num> {
    /// Represents an empty source.
    #[error("Input contains no data")]
    EmptySource,

    /// Represents a failure to read from an undefined constant.
    #[error("Undefined constant error")]
    UndefinedConstError,

    /// Represents a general command error.
    #[error("Command error")]
    CommandError,

    /// Represents an unknown command.
    #[error("Unknown command error")]
    UnknownCommandError,

    /// Represents a general parameter error.
    #[error("Parameter error")]
    ParameterError,

    /// Represents a failure to parse an integer constant.
    #[error("Parse integer error")]
    ParseIntError,

    #[error("Range error")]
    RangeError,
    //ParseIntError { err: std::num::ParseIntError },
    //ParseIntError { err: <T as Num>::FromStrRadixErr },

    // Represents all other cases of `std::io::Error`.
    //#[error(transparent)]
    //IOError(#[from] std::io::Error),
}


#[derive(Copy,Clone,PartialEq,Debug,EnumIter)]
pub enum Command {
    Quit,
    Exit,
    Help,
    Save,
    Restore,
    History,
    Set,
    Print,
}


impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, ".{:?}", self)
    }
}

#[derive(Clone,PartialEq,Debug)]
pub enum Parameter<T> {
    Register(Register),
    Integer(T),
    Identifier(String),
    Assign,
}

#[derive(Debug)]
pub struct Parser<T> {
    constants:  HashMap<String,T>,
    commands:   HashMap<String,Command>,
    regexset:   RegexSet,
    delim:      HashSet<u8>,
    values:     Vec<T>,
    reg_names:  HashSet<Register>,
}


impl<T> Parser<T>
where
    T:
        Clone +
        num_traits::Num +
        fmt::Debug +
        fmt::LowerHex +
        TwosComplement
{

    pub fn new() -> Self {
        Parser{
            constants: HashMap::new(),
            commands: Command::iter()
                .map(|cmd| { (cmd.to_string().to_lowercase(), cmd) })
                .collect::<HashMap<_, _>>(),
            regexset: RegexSet::new(&[
                // The regexes ignore out-of-range digits in binary and
                // octal constant. Such errors will be handled by the
                // string to integer conversion
                // Single digit numbers without prefix or suffix are not
                // matched as int and herefore not converted to hex prefix
                // (0x) representation for better readability
                r"^\$[a-zA-Z][0-9a-zA-Z_]*$",       //  0
                r"^0x[0-9a-fA-F]+$",                //  1
                r"^0o[0-9]+$",                      //  2
                r"^0b[0-9]+$",                      //  3
                r"^0d\d+$",                         //  4
                r"^[0-9]+o$",                       //  5
                r"^[0-9]+b$",                       //  6
                r"^\d+d$",                          //  7
                r"^\d\d+$",                         //  8 (exclude single digit numbers)
                r"^\$\d+$",                         //  9
                r"^\$_+$",                          // 10
                r"^\d+$",                           // 11 single digit numbers
                r"^[a-zA-Z][0-9a-zA-Z_\.]*$",       // 12 Identifier
                r"^_+[0-9a-zA-Z]+[0-9a-zA-Z_]*$",   // 13 Identifier
                r#"^".+"$"#,                        // 14 Identifier
                r"^-\d+$",                          // 15 negative decimal integer
                r"^\+\d+$",                         // 16 positive decimal integer
            ]).unwrap(),
            delim: "[]()+-*/%&^|<>, ".as_bytes()
                                     .iter()
                                     .cloned()
                                     .collect(),
            values: Vec::<T>::new(),
            reg_names: HashSet::new(),
        }
    }

    fn from_constant(&self, src: &str) -> Result<T,ParseError> {
        self.constants.get(src).cloned().ok_or(ParseError::UndefinedConstError)
    }

    fn from_str_radix(src: &str, radix: u32) -> Result<T,ParseError> {
    //where T: num_traits::Num<FromStrRadixErr = std::num::ParseIntError> {
        //T::from_str_radix(src, radix).map_err(|e| ParseError::ParseIntError{err: e})
        T::from_str_radix(src, radix).map_err(|_| ParseError::ParseIntError)
    }

    pub fn add_value(&mut self, value: T) {
        self.values.push(value);
    }

    pub fn get_value(&self, index: usize) -> Result<T,ParseError> {
        if index < self.values.len() {
            match self.values.get(index) {
                Some(value) => Ok(value.clone()),
                None        => Err(ParseError::RangeError),
            }
        } else {
            Err(ParseError::RangeError)
        }
    }

    pub fn define_constant(&mut self, name: &str, value: T) {
        self.constants.insert(name.to_owned(), value);
    }

    pub fn parse_cmd(&self, input: &str) -> Option<Result<(Command,Vec<Parameter<T>>),ParseError>> {
        let input = input.trim();
        if input.len() == 0 {
            return None;
        }
        let v: Vec<&str> = input.split(' ').collect();
        if !v.is_empty() {
            let m: Vec<_> = self.commands.iter()
                .filter(|(k,_)| k.starts_with(v[0]))
                .map(|(_,v)| { v })
                .collect::<Vec<_>>();
            match m.len() {
                0 => {
                    if v[0].starts_with(".") {
                        Some(Err(ParseError::UnknownCommandError))
                    } else {
                        None
                    }
                },
                1 => {
                    let mut parameters = vec![];
                    for p in v.iter().skip(1) {
                        let result = self.parse_parameter(p);
                        if result.is_err() {
                            return Some(Err(ParseError::ParameterError));
                        }
                        parameters.push(result.unwrap());
                    }
                    Some(Ok((*m[0],parameters)))
                },
                _ => Some(Err(ParseError::CommandError))
            }
        } else {
            None
        }
    }

    fn map_int(v: Result<T,ParseError>) -> Result<Parameter<T>,ParseError> {
        if v.is_ok() {
            Ok(Parameter::Integer(v.unwrap()))
        } else {
            Err(ParseError::ParameterError)
        }
    }

    pub fn parse_parameter(&self, input: &str) -> Result<Parameter<T>,ParseError> {
        if let Some(reg) = self.reg_names.get(&Register::from(input.to_uppercase().as_str())) {
            return Ok(Parameter::Register(*reg));
        } 
        let matches: Vec<_> = self.regexset.matches(input).into_iter().collect();
        if matches.is_empty() {
            Err(ParseError::ParameterError)
        } else {
            let result = match matches[0] {
                0     => Parser::map_int(self.from_constant(&input[1..])),
                1     => Parser::map_int(Parser::from_str_radix(&input[2..], 16)),
                2     => Parser::map_int(Parser::from_str_radix(&input[2..],  8)),
                3     => Parser::map_int(Parser::from_str_radix(&input[2..],  2)),
                4     => Parser::map_int(Parser::from_str_radix(&input[2..], 10)),
                5     => Parser::map_int(Parser::from_str_radix(&input[..input.len()-1], 8)),
                6     => Parser::map_int(Parser::from_str_radix(&input[..input.len()-1], 2)),
                7     => Parser::map_int(Parser::from_str_radix(&input[..input.len()-1], 10)),
                8|11  => Parser::map_int(Parser::from_str_radix(input, 10)),
                9     => {
                    let index = u32::from_str_radix(&input[1..], 10);
                    if index.is_err() {
                        return Err(ParseError::ParameterError);
                    }
                    Parser::map_int(self.get_value(index.unwrap() as usize))
                },
                10    => {
                    match self.values.last() {
                        Some(value) => Ok(Parameter::Integer(value.clone())),
                        None        => return Err(ParseError::ParameterError),
                    }
                },
                12|13 => Ok(Parameter::Identifier(input.to_string())),
                14    => Ok(Parameter::Identifier(input[1..input.len()-1].to_string())),
                15    => {
                    let abs: T = Parser::from_str_radix(&input[1..], 10)
                                .map_err(|_e| ParseError::ParameterError)?;
                    
                    Ok(Parameter::Integer(abs.twos_complement()))
                },
                16    => Parser::map_int(Parser::from_str_radix(&input[1..], 10)),
                _     => return Err(ParseError::ParameterError),
            };
            result
        }
    }

    pub fn parse_int(&self, input: &str) -> Option<Result<T,ParseError>> {
        let matches: Vec<_> = self.regexset.matches(input).into_iter().collect();
        if matches.is_empty() {
            None
        } else {
            let result = match matches[0] {
                0  => self.from_constant(&input[1..]),
                1  => Parser::from_str_radix(&input[2..], 16),
                2  => Parser::from_str_radix(&input[2..],  8),
                3  => Parser::from_str_radix(&input[2..],  2),
                4  => Parser::from_str_radix(&input[2..], 10),
                5  => Parser::from_str_radix(&input[..input.len()-1], 8),
                6  => Parser::from_str_radix(&input[..input.len()-1], 2),
                7  => Parser::from_str_radix(&input[..input.len()-1], 10),
                8  => Parser::from_str_radix(input, 10),
                9  => {
                    let index = u32::from_str_radix(&input[1..], 10);
                    if index.is_err() {
                        return Some(Err(ParseError::ParseIntError));
                    }
                    self.get_value(index.unwrap() as usize)
                },
                10 => {
                    match self.values.last() {
                        Some(value) => Ok(value.clone()),
                        None        => return Some(Err(ParseError::RangeError)),
                    }
                },
                _  => return None,
            };
            Some(result)
        }
    }

    pub fn parse_asm(&self, input: &str) -> Result<String,ParseError> {
        let indices: Vec<_> = input.as_bytes()
                                   .iter()
                                   .enumerate()
                                   .filter(|(_,v)| self.delim.contains(v))
                                   .map(|(i,_)| i)
                                   .collect();
        let mut tokens: Vec<_> = vec!();
        let mut start = 0;
        for end in indices {
            let slice = &input[start..end];
            if slice.len() > 0 {
                if let Some(result) = self.parse_int(slice) {
                    tokens.push(format!("{:#04x}", result?).to_string());
                } else {
                    tokens.push(slice.to_string());
                }
            }
            tokens.push(input[end..=end].to_string());
            start = end+1;
        }
        let slice = &input[start..];
        if slice.len() > 0 {
            if slice.len() > 0 {
                if let Some(result) = self.parse_int(slice) {
                    tokens.push(format!("{:#04x}", result?).to_string());
                } else {
                    tokens.push(slice.to_string());
                }
            }
        }

        Ok(tokens.join(""))
    }

    pub fn set_reg_names(&mut self, regs: &Vec<Register>) {
        for reg in regs {
            self.reg_names.insert(*reg);
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::context::Context;

    #[test]
    fn test_value_history() {
        let mut parser = Parser::<u32>::new();

        assert_eq!(parser.get_value(0), Err(ParseError::RangeError));
        assert_eq!(parser.parse_int("$0"), Some(Err(ParseError::RangeError)));
        assert_eq!(parser.parse_int("$_"), Some(Err(ParseError::RangeError)));

        parser.add_value(42);
        assert_eq!(parser.get_value(0), Ok(42));
        assert_eq!(parser.get_value(1), Err(ParseError::RangeError));
        assert_eq!(parser.parse_int("$0"), Some(Ok(42)));
        assert_eq!(parser.parse_int("$1"), Some(Err(ParseError::RangeError)));
        assert_eq!(parser.parse_int("$_"), Some(Ok(42)));

        parser.add_value(10);
        assert_eq!(parser.get_value(0), Ok(42));
        assert_eq!(parser.get_value(1), Ok(10));
        assert_eq!(parser.get_value(2), Err(ParseError::RangeError));
        assert_eq!(parser.parse_int("$0"), Some(Ok(42)));
        assert_eq!(parser.parse_int("$1"), Some(Ok(10)));
        assert_eq!(parser.parse_int("$2"), Some(Err(ParseError::RangeError)));
        assert_eq!(parser.parse_int("$_"), Some(Ok(10)));
    }

    #[test]
    fn test_constants() {
        let mut parser = Parser::<u32>::new();

        assert_eq!(parser.parse_int("$num"), Some(Err(ParseError::UndefinedConstError)));
        parser.define_constant("num", 1234);
        assert_eq!(parser.parse_int("$num"), Some(Ok(1234)));
        parser.define_constant("num", 0xffff);
        assert_eq!(parser.parse_int("$num"), Some(Ok(0xffff)));
        parser.define_constant("l_10", 0xabcd);
        assert_eq!(parser.parse_int("$l_10"), Some(Ok(0xabcd)));
    }

    #[test]
    fn test_parse_int_dec() {
        let parser = Parser::<u32>::new();

        let pairs: Vec<(&str, Result<u32,ParseError>)> = vec![
            ("100",          Ok(100)),
            ("65535",        Ok(65535)),
            ("0d0",          Ok(0)),
            ("0d100",        Ok(100)),
            ("0d65535",      Ok(65535)),
            ("0d",           Ok(0)),
            ("100d",         Ok(100)),
            ("65535d",       Ok(65535)),
        ];

        for pair in pairs {
            assert_eq!(parser.parse_int(pair.0), Some(pair.1));
        }
    }

    #[test]
    fn test_parse_int_bin() {
        let parser = Parser::<u32>::new();

        let pairs: Vec<(&str, Result<u32,ParseError>)> = vec![
            ("0b",           Ok(0)),
            ("1b",           Ok(1)),
            ("0b0",          Ok(0)),
            ("0b1",          Ok(1)),
            ("0b11111111",   Ok(255)),
            ("11111111b",    Ok(255)),
        ];

        for pair in pairs {
            assert_eq!(parser.parse_int(pair.0), Some(pair.1));
        }
    }

    #[test]
    fn test_parse_int_hex() {
        let parser = Parser::<u32>::new();

        let pairs: Vec<(&str, Result<u32,ParseError>)> = vec![
            ("0x0",          Ok(0)),
            ("0x00",         Ok(0)),
            ("0xff",         Ok(255)),
            ("0x100",        Ok(256)),
            ("0xffff",       Ok(65535)),
            ("0x10000",      Ok(65536)),
            ("0xffffffff",   Ok(0xffffffff)),
        ];

        for pair in pairs {
            assert_eq!(parser.parse_int(pair.0), Some(pair.1));
        }
    }

    #[test]
    fn test_parse_int_oct() {
        let parser = Parser::<u32>::new();

        let pairs: Vec<(&str, Result<u32,ParseError>)> = vec![
            ("0o0",          Ok(0)),
            ("0o1",          Ok(1)),
        ];

        for pair in pairs {
            assert_eq!(parser.parse_int(pair.0), Some(pair.1));
        }
    }

    #[test]
    fn test_parse_int_misc() {
        let parser = Parser::<u32>::new();

        let pairs: Vec<(&str, Option<Result<u32,ParseError>>)> = vec![
            ("0",            None),
            ("0d10x",        None),
            ("0x1000000gf",  None),
            ("0x100000000",  Some(Err(ParseError::ParseIntError))),
            ("0b2",          Some(Err(ParseError::ParseIntError))),
            ("0o8",          Some(Err(ParseError::ParseIntError))),
        ];

        for pair in pairs {
            assert_eq!(parser.parse_int(pair.0), pair.1);
        }
    }

    #[test]
    fn test_parse_asm() {
        let mut parser = Parser::<u32>::new();
        parser.define_constant("offset", 0x10000);

        let pairs: Vec<(&str, Result<String,ParseError>)> = vec![
            ("mov eax,1000",                 Ok("mov eax,0x3e8".to_string())),
            ("mov al,'a'",                   Ok("mov al,'a'".to_string())),
            ("add ebx,0d1000",               Ok("add ebx,0x3e8".to_string())),
            ("lea edi,[2*ebx+eax+10000]",    Ok("lea edi,[2*ebx+eax+0x2710]".to_string())),
            ("lea esi,[8*eax+$offset]",      Ok("lea esi,[8*eax+0x10000]".to_string())),
        ];

        for pair in pairs {
            assert_eq!(parser.parse_asm(pair.0), pair.1);
        }
    }

    #[test]
    fn test_parse_cmd() {
        let mut parser = Parser::<u32>::new();
        assert_eq!(parser.parse_cmd("").is_none(), true);
        assert_eq!(parser.parse_cmd("no command").is_none(), true);
        assert_eq!(parser.parse_cmd("mov eax,1000").is_none(), true);

        parser.set_reg_names(&Context::regs_x86_32());
        parser.define_constant("offset", 0x10000);

        let pairs: Vec<(&str, Result<(Command,Vec<Parameter<u32>>),ParseError>)> = vec![
            (".help",                 Ok((Command::Help,vec![]))),
            (" .help",                Ok((Command::Help,vec![]))),
            (".help ",                Ok((Command::Help,vec![]))),
            (".save filename",        Ok((Command::Save,vec![Parameter::Identifier("filename".to_string())]))),
            (".save filename.txt",    Ok((Command::Save,vec![Parameter::Identifier("filename.txt".to_string())]))),
            (".save \"context.txt\"", Ok((Command::Save,vec![Parameter::Identifier("context.txt".to_string())]))),
            (".print eax",            Ok((Command::Print,vec![Parameter::Register(Register::from("EAX"))]))),
            (".print eax ebx ecx",    Ok((Command::Print,vec![
                                        Parameter::Register(Register::from("EAX")),
                                        Parameter::Register(Register::from("EBX")),
                                        Parameter::Register(Register::from("ECX")),
                                      ]))),
            (".print $offset",        Ok((Command::Print,vec![Parameter::Integer(0x10000)]))),
            (".set label 0x1000",     Ok((Command::Set,vec![
                                        Parameter::Identifier("label".to_string()),
                                        Parameter::Integer(0x1000),
                                      ]))),
            //(".print $num",           Ok((Command::Print,vec![Parameter::Integer(0x10000)]))),
        ];

        for pair in pairs {
            assert_eq!(parser.parse_cmd(pair.0), Some(pair.1));
        }
    }

    #[test]
    fn test_parse_parameter() {
        let mut parser = Parser::<u32>::new();

        parser.set_reg_names(&Context::regs_x86_32());
        parser.define_constant("offset", 0x10000);

        let pairs: Vec<(&str, Result<Parameter<u32>,ParseError>)> = vec![
            ("filename",              Ok(Parameter::Identifier("filename".to_string()))),
            ("filename.txt",          Ok(Parameter::Identifier("filename.txt".to_string()))),
            ("\"context.txt\"",       Ok(Parameter::Identifier("context.txt".to_string()))),
            ("eax",                   Ok(Parameter::Register(Register::from("EAX")))),
            ("$offset",               Ok(Parameter::Integer(0x10000))),
            ("label",                 Ok(Parameter::Identifier("label".to_string()))),
            ("0x1000",                Ok(Parameter::Integer(0x1000))),
            ("-1",                    Ok(Parameter::Integer(0xffffffff))),
            ("-1000",                 Ok(Parameter::Integer(0xfffffc18))),
            ("-0",                    Ok(Parameter::Integer(0x00000000))),
            ("-2147483648",           Ok(Parameter::Integer(0x80000000))),
            ("+1",                    Ok(Parameter::Integer(0x00000001))),
            ("+1000",                 Ok(Parameter::Integer(0x000003e8))),
            ("+0",                    Ok(Parameter::Integer(0x00000000))),
            ("+2147483647",           Ok(Parameter::Integer(0x7fffffff))),
            ("0xfffffffff",           Err(ParseError::ParameterError)),
            ("$num",                  Err(ParseError::ParameterError)),
        ];

        for pair in pairs {
            assert_eq!(parser.parse_parameter(pair.0), pair.1);
        }
    }

}
