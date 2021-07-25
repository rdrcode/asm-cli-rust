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


/// ParseError enumerates all possible errors returned by this library.
#[derive(Error, Debug)]
pub enum ParseError {
//pub enum ParseError<T: Debug + Num> {
    /// Represents an empty source.
    #[error("Input contains no data")]
    EmptySource,

    /// Represents a failure to read from an undefined constant.
    #[error("Undefined constant error")]
    UndefinedConstError,

    /// Represents a failure to define an already defined constant.
    #[error("Duplicate constant error")]
    DuplicateConstError,

    /// Represents a failure to parse an integer constant.
    #[error("Parse integer error")]
    ParseIntError,
    //ParseIntError { err: std::num::ParseIntError },
    //ParseIntError { err: <T as Num>::FromStrRadixErr },

    // Represents all other cases of `std::io::Error`.
    //#[error(transparent)]
    //IOError(#[from] std::io::Error),
}


#[derive(Debug,EnumIter)]
pub enum Command {
    Quit,
    Exit,
    Help,
    History,
    Set,
    Print,
}


impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, ".{:?}", self)
    }
}


#[derive(Debug)]
pub struct Parser<T> {
    constants:  HashMap<String,T>,
    commands:   HashMap<String,Command>,
    regexset:   RegexSet,
    delim:      HashSet<u8>,
}


impl<T> Parser<T>
where
    T:
        Clone +
        num_traits::Num +
        fmt::Debug +
        fmt::LowerHex
{

    pub fn new() -> Self {
        Parser{
            constants: HashMap::new(),
            commands: Command::iter()
                .map(|cmd| { (cmd.to_string().to_lowercase(), cmd) })
                .collect::<HashMap<_, _>>(),
            regexset: RegexSet::new(&[
                r"^\$[a-zA-Z][0-9a-zA-Z_]*$", // 0
                r"^0x[0-9a-fA-F]+$",          // 1
                r"^0o[0-7]+$",                // 2
                r"^0b[01]+$",                 // 3
                r"^0d\d+$",                   // 4
                r"^[0-7]+o$",                 // 5
                r"^[01]+b$",                  // 6
                r"^\d+d$",                    // 7
                r"^\d+$",                     // 8
            ]).unwrap(),
            delim: "[]()+-*/%&^|<>, ".as_bytes()
                                     .iter()
                                     .cloned()
                                     .collect(),
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


    //pub fn parse_cmd(&self, input: &str) -> Option<Result<Command,ParseError>> {
    pub fn parse_cmd(&self, input: &str) -> Option<&Command> {
        let v: Vec<&str> = input.split(' ').collect();
        if !v.is_empty() {
            let command = self.commands.get(v[0]);
            return command;
        }
        None
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
                _  => Parser::from_str_radix(input, 16),
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

}
