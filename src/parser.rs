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


#[derive(Debug,EnumIter)]
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


#[derive(Debug)]
pub struct Parser<T> {
    constants:  HashMap<String,T>,
    commands:   HashMap<String,Command>,
    regexset:   RegexSet,
    delim:      HashSet<u8>,
    values:     Vec<T>,
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
                // The regexes ignore out-of-range digits in binary and
                // octal constant. Such errors will be handled by the
                // string to integer conversion
                r"^\$[a-zA-Z][0-9a-zA-Z_]*$", //  0
                r"^0x[0-9a-fA-F]+$",          //  1
                r"^0o[0-9]+$",                //  2
                r"^0b[0-9]+$",                //  3
                r"^0d\d+$",                   //  4
                r"^[0-9]+o$",                 //  5
                r"^[0-9]+b$",                 //  6
                r"^\d+d$",                    //  7
                r"^\d+$",                     //  8
                r"^\$\d+$",                   //  9
                r"^\$_+$",                    // 10
            ]).unwrap(),
            delim: "[]()+-*/%&^|<>, ".as_bytes()
                                     .iter()
                                     .cloned()
                                     .collect(),
            values: Vec::<T>::new(),
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


    pub fn parse_cmd(&self, input: &str) -> Option<Result<&Command,ParseError>> {
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
                1 => Some(Ok(m[0])),
                _ => Some(Err(ParseError::CommandError))
            }
        } else {
            None
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

}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_history() {
        let mut parser = Parser::<u32>::new();

        let value = parser.get_value(0);
        assert_eq!(Err(ParseError::RangeError), value);

        parser.add_value(42);
        let value = parser.get_value(0);
        assert_eq!(Ok(42), value);
        let value = parser.get_value(1);
        assert_eq!(Err(ParseError::RangeError), value);

        parser.add_value(10);
        let value = parser.get_value(0);
        assert_eq!(Ok(42), value);
        let value = parser.get_value(1);
        assert_eq!(Ok(10), value);
        let value = parser.get_value(2);
        assert_eq!(Err(ParseError::RangeError), value);

        let result = parser.parse_int("$0");
        assert_eq!(Some(Ok(42)), result);

        let result = parser.parse_int("$1");
        assert_eq!(Some(Ok(10)), result);

        let result = parser.parse_int("$3");
        assert_eq!(Some(Err(ParseError::RangeError)), result);

        let result = parser.parse_int("$_");
        assert_eq!(Some(Ok(10)), result);
    }

    #[test]
    fn test_parse_int_dec() {
        let parser = Parser::<u32>::new();

        let pairs: Vec<(&str, Result<u32,ParseError>)> = vec![
            ("0",            Ok(0)),
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
            let result = parser.parse_int(pair.0);
            assert_eq!(Some(pair.1), result);
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
            let result = parser.parse_int(pair.0);
            assert_eq!(Some(pair.1), result);
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
            let result = parser.parse_int(pair.0);
            assert_eq!(Some(pair.1), result);
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
            let result = parser.parse_int(pair.0);
            assert_eq!(Some(pair.1), result);
        }
    }

    #[test]
    fn test_parse_int_err() {
        let parser = Parser::<u32>::new();

        let pairs: Vec<(&str, Option<Result<u32,ParseError>>)> = vec![
            ("0d10x",        None),
            ("0x1000000gf",  None),
            ("0x100000000",  Some(Err(ParseError::ParseIntError))),
            ("0b2",          Some(Err(ParseError::ParseIntError))),
            ("0o8",          Some(Err(ParseError::ParseIntError))),
        ];

        for pair in pairs {
            let result = parser.parse_int(pair.0);
            assert_eq!(pair.1, result);
        }
    }
}
