extern crate num_traits;

use std::str;
use std::fmt;
use std::fmt::Debug;
use std::collections::HashMap;
use std::collections::HashSet;
use thiserror::Error;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use crate::machine::cpuarch::Register;
use crate::lexer::Lexer;
use crate::lexer::Token;
use crate::lexer::Opcode;


/// ParseError enumerates all possible errors returned by this library.
#[derive(Error, Debug, PartialEq)]
pub enum ParseError {
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

    #[error("Expression error")]
    ExpressionError,

    #[error("Stack error")]
    StackError,
}


#[derive(Copy,Clone,PartialEq,Debug,EnumIter)]
pub enum Command {
    Quit,
    Help,
    Save,
    Restore,
    Define,
    Print,
    Eval,
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
pub struct Parser {
    constants:  HashMap<String,i64>,
    commands:   HashMap<String,Command>,
    values:     Vec<i64>,
    reg_names:  HashSet<Register>,
}


impl Parser {

    pub fn new() -> Self {
        Parser{
            constants: HashMap::new(),
            commands: Command::iter()
                .map(|cmd| { (cmd.to_string().to_lowercase(), cmd) })
                .collect::<HashMap<_, _>>(),
            values: Vec::<i64>::new(),
            reg_names: HashSet::new(),
        }
    }

    fn from_constant(&self, src: &str) -> Result<i64,ParseError> {
        self.constants.get(src).cloned().ok_or(ParseError::UndefinedConstError)
    }

    pub fn add_value(&mut self, value: i64) -> usize {
        self.values.push(value);
        self.values.len()-1
    }

    pub fn get_value(&self, index: Option<usize>) -> Result<i64,ParseError> {
        if !self.values.is_empty() {
            let index = index.unwrap_or(self.values.len()-1);
            if index < self.values.len() {
                match self.values.get(index) {
                    Some(value) => Ok(value.clone()),
                    None        => Err(ParseError::RangeError),
                }
            } else {
                Err(ParseError::RangeError)
            }
        } else {
            Err(ParseError::RangeError)
        }
    }

    pub fn constants(&self) -> std::collections::hash_map::Iter<'_, String, i64> {
        self.constants.iter()
    }

    pub fn define_constant(&mut self, name: &str, value: i64) {
        self.constants.insert(name.to_owned(), value);
    }

    fn evaluate_expression(&self, tokens: Vec<Token>) -> Result<i64,ParseError>{
        let mut stack: Vec<i64> = Vec::new();
        for token in tokens.iter() {
            match token {
                Token::Integer(value) => stack.push(*value),
                Token::Operator(op) => {
                    if let Some(a) = stack.pop() {
                        if let Some(b) = stack.pop() {
                            let result = match op {
                                Opcode::Add => b + a,
                                Opcode::Sub => b - a,
                                Opcode::Mul => b * a,
                                Opcode::Div => b / a,
                                Opcode::And => b & a,
                                Opcode::Or  => b | a,
                            };
                            stack.push(result);
                        } else {
                            return Err(ParseError::StackError);
                        }
                    } else {
                        return Err(ParseError::StackError);
                    }
                },
                _ => return Err(ParseError::ExpressionError),
            }
        }
        
        stack.pop().ok_or(ParseError::ExpressionError)
    }

    fn resolve_tokens(&self, tokens: &[Token]) -> Result<Vec<Token>,ParseError> {
        let mut resolved_tokens: Vec<Token> = vec![];
        for token in tokens {
            match token {
                Token::Constant(s) => {
                    resolved_tokens.push(self.from_constant(&s).map(|v| Token::Integer(v))?);
                },
                Token::ValueHistory(idx) => {
                    if let Ok(value) = self.get_value(*idx) {
                        resolved_tokens.push(Token::Integer(value));
                    } else {
                        return Err(ParseError::RangeError);
                    }
                },
                Token::Identifier(s) => {
                    if let Some(reg) = self.reg_names.get(&Register::from(s.to_uppercase().as_str())) {
                    }
                    resolved_tokens.push(token.clone());
                },
                _ => {
                    resolved_tokens.push(token.clone());
                }
            }
        }

        Ok(resolved_tokens)
    }

    pub fn parse_cmd(&mut self, input: &str) -> Option<Result<(Command,Vec<Token>),ParseError>> {
        let scanned = Lexer::scan_line(input);
        let mut result = None;
        if let Ok(tokens) = scanned {
            if !tokens.1.is_empty() {
                match &tokens.1[0] {
                    Token::Identifier(s) => {
                        result = match s.as_str() {
                            "h" => Some(Ok((Command::Help, vec![]))),
                            "p" => Some(self.resolve_tokens(&tokens.1[1..]).map(|v| (Command::Print, v))),
                            "e" => {
                                if let Ok(resolved_tokens) = self.resolve_tokens(&tokens.1[1..]) {
                                    Some(self.evaluate_expression(resolved_tokens).map(|v| (Command::Eval, vec![Token::Integer(v)])))
                                } else {
                                    Some(Err(ParseError::ParameterError))
                                }
                            },
                            "s" => Some(Ok((Command::Save, tokens.1[1..].to_vec()))),
                            "r" => Some(Ok((Command::Restore, tokens.1[1..].to_vec()))),
                            "d" => {
                                if tokens.1.len() <= 1 {
                                    Some(Ok((Command::Define, vec![])))    
                                } else if tokens.1.len() == 2 {
                                    Some(Ok((Command::Define, tokens.1[1..=1].to_vec())))
                                } else {
                                    match &tokens.1[1] {
                                        Token::Identifier(s) => {
                                            if let Ok(resolved_tokens) = self.resolve_tokens(&tokens.1[2..]) {
                                                let mut v: Vec<Token> = vec![tokens.1[1].clone()];
                                                if let Ok(value) = self.evaluate_expression(resolved_tokens) {
                                                    v.push(Token::Integer(value));
                                                    self.define_constant(s, value);
                                                    Some(Ok((Command::Define, v)))
                                                } else {
                                                    Some(Err(ParseError::ParameterError))
                                                }
                                            } else {
                                                Some(Err(ParseError::ParameterError))
                                            }
                                        },
                                        _ => Some(Err(ParseError::ParameterError)),
                                    }
                                }
                            },
                            "q" => Some(Ok((Command::Quit, vec![]))),
                            _   => None,
                        };
                    },
                    _ => {},
                }
            }
        };

        result
    }

    pub fn parse_asm(&self, input: &str) -> Result<String,ParseError> {
        let scanned = Lexer::scan_line(input);
        let mut output: Vec<String> = vec![];
        let mut separate: bool = false;
        if let Ok(tokens) = scanned {
            if let Ok(resolved_tokens) = self.resolve_tokens(&tokens.1) {
                for token in resolved_tokens {
                    match token {
                        Token::Integer(v) => {
                            if separate {
                                output.push(format!(" "));
                            }
                            separate = true;
                            if v > 9 {
                                output.push(format!("{:#04x}", v));
                            } else {
                                output.push(format!("{}", v));
                            }
                        },
                        Token::Other(ch) => {
                            separate = false;
                            output.push(ch.to_string());
                        },
                        Token::Operator(op) => {
                            separate = false;
                            output.push(op.to_string());
                        },
                        Token::Char(ch) => {
                            if separate {
                                output.push(format!(" "));
                            }
                            separate = true;
                            output.push(format!("'{}'", ch));
                        },
                        Token::Identifier(s) => {
                            if separate {
                                output.push(format!(" "));
                            }
                            separate = true;
                            output.push(format!("{}", s));
                        },
                        _ => {
                        }
                    }
                }
            } else {
                return Err(ParseError::ExpressionError);
            }
        } else {
            return Err(ParseError::ExpressionError);
        }

        Ok(output.join(""))
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
    use crate::machine::cpuarch::x86_32;

    #[test]
    fn test_value_history() {
        let mut parser = Parser::new();

        assert_eq!(parser.get_value(Some(0)), Err(ParseError::RangeError));
        assert_eq!(parser.get_value(None), Err(ParseError::RangeError));

        parser.add_value(42);
        assert_eq!(parser.get_value(None), Ok(42));
        assert_eq!(parser.get_value(Some(0)), Ok(42));
        assert_eq!(parser.get_value(Some(1)), Err(ParseError::RangeError));

        parser.add_value(10);
        assert_eq!(parser.get_value(Some(0)), Ok(42));
        assert_eq!(parser.get_value(None), Ok(10));
        assert_eq!(parser.get_value(Some(1)), Ok(10));
        assert_eq!(parser.get_value(Some(2)), Err(ParseError::RangeError));
    }

    #[test]
    fn test_resolve_token() {
        let mut parser = Parser::new();

        assert_eq!(parser.resolve_tokens(&vec![Token::ValueHistory(Some(0))]), Err(ParseError::RangeError));
        assert_eq!(parser.resolve_tokens(&vec![Token::ValueHistory(None)]), Err(ParseError::RangeError));

        parser.add_value(42);
        assert_eq!(parser.resolve_tokens(&vec![Token::ValueHistory(Some(0))]), Ok(vec![Token::Integer(42)]));
        assert_eq!(parser.resolve_tokens(&vec![Token::ValueHistory(Some(1))]), Err(ParseError::RangeError));
        assert_eq!(parser.resolve_tokens(&vec![Token::ValueHistory(None)]), Ok(vec![Token::Integer(42)]));

        parser.add_value(10);
        assert_eq!(parser.resolve_tokens(&vec![Token::ValueHistory(Some(0))]), Ok(vec![Token::Integer(42)]));
        assert_eq!(parser.resolve_tokens(&vec![Token::ValueHistory(Some(1))]), Ok(vec![Token::Integer(10)]));
        assert_eq!(parser.resolve_tokens(&vec![Token::ValueHistory(Some(2))]), Err(ParseError::RangeError));
        assert_eq!(parser.resolve_tokens(&vec![Token::ValueHistory(None)]), Ok(vec![Token::Integer(10)]));
    }

    #[test]
    fn test_constants() {
        let mut parser = Parser::new();

        assert_eq!(parser.resolve_tokens(&vec![Token::Constant("num".to_string())]), Err(ParseError::UndefinedConstError));
        parser.define_constant("num", 1234);
        assert_eq!(parser.resolve_tokens(&vec![Token::Constant("num".to_string())]), Ok(vec![Token::Integer(1234)]));
        parser.define_constant("num", 0xffff);
        assert_eq!(parser.resolve_tokens(&vec![Token::Constant("num".to_string())]), Ok(vec![Token::Integer(0xffff)]));
        parser.define_constant("l_10", 0xabcd);
        assert_eq!(parser.resolve_tokens(&vec![Token::Constant("l_10".to_string())]), Ok(vec![Token::Integer(0xabcd)]));
    }
    
    // #[test]
    // fn test_parse_int_misc() {
    //     let parser = Parser::new();

    //     let pairs: Vec<(&str, Option<Result<i64,ParseError>>)> = vec![
    //         ("0",            None),
    //         ("0d10x",        None),
    //         ("0x1000000gf",  None),
    //         //("0x100000000",  Some(Err(ParseError::ParseIntError))),
    //         ("0b2",          Some(Err(ParseError::ParseIntError))),
    //         ("0o8",          Some(Err(ParseError::ParseIntError))),
    //     ];

    //     for pair in pairs {
    //         assert_eq!(parser.parse_int(pair.0), pair.1);
    //     }
    // }

    #[test]
    fn test_parse_asm() {
        let mut parser = Parser::new();
        parser.define_constant("offset", 0x10000);

        let pairs: Vec<(&str, Result<String,ParseError>)> = vec![
            ("mov eax,1000",                 Ok("mov eax,0x3e8".to_string())),
            ("mov al,'a'",                   Ok("mov al,'a'".to_string())),
            ("add ebx,1000",                 Ok("add ebx,0x3e8".to_string())),
            ("add ecx,10",                   Ok("add ecx,0x0a".to_string())),
            ("add ebp,8",                    Ok("add ebp,8".to_string())),
            ("add ecx,0b1111_1111",          Ok("add ecx,0xff".to_string())),
            ("lea edi,[2*ebx+eax+10000]",    Ok("lea edi,[2*ebx+eax+0x2710]".to_string())),
            ("lea esi,[8*eax+$offset]",      Ok("lea esi,[8*eax+0x10000]".to_string())),
        ];

        for pair in pairs {
            assert_eq!(parser.parse_asm(pair.0), pair.1);
        }
    }

    #[test]
    fn test_parse_cmd() {
        let mut parser = Parser::new();
        assert_eq!(parser.parse_cmd("").is_none(), true);
        assert_eq!(parser.parse_cmd("no command").is_none(), true);
        assert_eq!(parser.parse_cmd("mov eax,1000").is_none(), true);

        parser.set_reg_names(&x86_32::regs());
        parser.define_constant("offset", 0x10000);

        let pairs: Vec<(&str, Result<(Command,Vec<Token>),ParseError>)> = vec![
            ("h",                   Ok((Command::Help,vec![]))),
            (" h",                  Ok((Command::Help,vec![]))),
            ("h  ",                 Ok((Command::Help,vec![]))),
            ("s filename",          Ok((Command::Save,vec![Token::Identifier("filename".to_string())]))),
            ("s filename2.txt",     Ok((Command::Save,vec![Token::Identifier("filename2.txt".to_string())]))),
            ("s \"context.txt\"",   Ok((Command::Save,vec![Token::Identifier("context.txt".to_string())]))),
    //         (".print eax",            Ok((Command::Print,vec![Parameter::Register(Register::from("EAX"))]))),
    //         (".print eax ebx ecx",    Ok((Command::Print,vec![
    //                                     Parameter::Register(Register::from("EAX")),
    //                                     Parameter::Register(Register::from("EBX")),
    //                                     Parameter::Register(Register::from("ECX")),
    //                                   ]))),
            ("p 0xabba",            Ok((Command::Print,vec![Token::Integer(0xabba)]))),
            ("p $offset",           Ok((Command::Print,vec![Token::Integer(0x10000)]))),
            ("e 5 7 +",             Ok((Command::Eval,vec![Token::Integer(12)]))),
            ("e _5 7 +",            Ok((Command::Eval,vec![Token::Integer(2)]))),
            ("e $offset 0x100 4 *+", Ok((Command::Eval,vec![Token::Integer(0x10400)]))),
            ("d label",             Ok((Command::Define,vec![Token::Identifier("label".to_string())]))),
            ("d label 0x1000",      Ok((Command::Define,vec![
                                        Token::Identifier("label".to_string()),
                                        Token::Integer(0x1000),
                                    ]))),
            ("e $label 0x100 0xff ++", Ok((Command::Eval,vec![Token::Integer(0x11ff)]))),
                                    //         //(".print $num",           Ok((Command::Print,vec![Parameter::Integer(0x10000)]))),
        ];

        for pair in pairs {
            assert_eq!(parser.parse_cmd(pair.0), Some(pair.1));
        }
    }

}
