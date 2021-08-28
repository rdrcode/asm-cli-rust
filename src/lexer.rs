extern crate nom;
use std::fmt;
use std::str;
use nom::{
    IResult,
    branch::alt,
    multi::{many0,many1},
    combinator::{map_res,map,recognize,complete,opt},
    sequence::{preceded,terminated,delimited,pair},
    character::complete::{char,one_of,none_of,digit1},
    bytes::complete::{tag,take_while},
};


#[derive(Debug, PartialEq, Clone)]
pub enum Token {
    Operator(Opcode),
    Integer(i64),
    Identifier(String),
    Register(String),
    Constant(String),
    ValueHistory(Option<usize>),
    Char(char),
    Other(char),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Opcode {
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Opcode::Add => write!(f, "+"),
            Opcode::Sub => write!(f, "-"),
            Opcode::Mul => write!(f, "*"),
            Opcode::Div => write!(f, "/"),
            Opcode::And => write!(f, "&"),
            Opcode::Or  => write!(f, "|"),
        }
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &*self {
            Token::Operator(code) => write!(f, "{}", code),
            Token::Integer(v) => write!(f, "{}", v),
            Token::Identifier(s) => write!(f, "{}", s.to_string()),
            Token::Register(s) => write!(f, "{}", s.to_string()),
            Token::Constant(s) => write!(f, "{}", s.to_string()),
            Token::ValueHistory(idx) => write!(f, "{:?}", idx),
            Token::Char(ch) => write!(f, "'{}'", ch),
            Token::Other(ch) => write!(f, "{}", ch),
        }
    }
}

#[derive(Debug)]
pub struct Lexer {}


impl Lexer {

    fn scan_integer_bin(input: &str) -> IResult<&str, Token> {
        preceded(
            alt((tag("0b"),tag("0B"))),
            map_res(
                recognize(
                    many1(
                        complete(terminated(one_of("01"), many0(char('_'))))
                    )
                ),
                |out: &str| i64::from_str_radix(&str::replace(&out, "_", ""), 2).map(|v| Token::Integer(v))
            )
        )(input)
    }

    fn scan_integer_oct(input: &str) -> IResult<&str, Token> {
        preceded(
            alt((tag("0o"),tag("0O"))),
            map_res(
                recognize(
                    many1(
                        complete(terminated(one_of("01234567"), many0(char('_'))))
                    )
                ),
                |out: &str| i64::from_str_radix(&str::replace(&out, "_", ""), 8).map(|v| Token::Integer(v))
            )
        )(input)
    }

    fn scan_integer_hex(input: &str) -> IResult<&str, Token> {
        preceded(
            alt((tag("0x"),tag("0X"))),
            map_res(
                recognize(
                    many1(
                        complete(terminated(one_of("0123456789abcdefABCDEF"), many0(char('_'))))
                    )
                ),
                |out: &str| i64::from_str_radix(&str::replace(&out, "_", ""), 16).map(|v| Token::Integer(v))
            )
        )(input)
    }

    fn scan_integer_dec_neg(input: &str) -> IResult<&str, Token> {
        preceded(
            pair(char('_'),opt(alt((tag("0d"),tag("0D"))))),
            map_res(
                recognize(
                    many1(
                        complete(terminated(one_of("0123456789"), many0(char('_'))))
                    )
                ),
                |out: &str| i64::from_str_radix(&str::replace(&out, "_", ""), 10).map(|v| Token::Integer(-v))
        ))(input)
    }

    fn scan_integer_dec(input: &str) -> IResult<&str, Token> {
        preceded(
            opt(alt((tag("0d"),tag("0D")))),
            map_res(recognize(
                many1(
                    complete(terminated(one_of("0123456789"), many0(char('_'))))
                )),
                |out: &str| i64::from_str_radix(&str::replace(&out, "_", ""), 10).map(|v| Token::Integer(v))
            )
        )(input)
    }

    fn scan_value_history(input: &str) -> IResult<&str, Token> {
        preceded(
            char('$'),
            alt((
                map(char('$'), |_| Token::ValueHistory(None)),
                map_res(recognize(digit1), |out: &str| usize::from_str_radix(out, 10).map(|v| Token::ValueHistory(Some(v))))
            ))
        )(input)
    }

    fn scan_operator(input: &str) -> IResult<&str, Token> {
        alt((
            map(char('+'), |_| Token::Operator(Opcode::Add)),
            map(char('-'), |_| Token::Operator(Opcode::Sub)),
            map(char('*'), |_| Token::Operator(Opcode::Mul)),
            map(char('/'), |_| Token::Operator(Opcode::Div)),
            map(char('&'), |_| Token::Operator(Opcode::And)),
            map(char('|'), |_| Token::Operator(Opcode::Or)),
        ))(input)
    }

    fn scan_escaped_char(input: &str) -> IResult<&str, Token> {
        let (rest, s) = delimited(
            char('\''),
            none_of("\'"),
            char('\'')
        )(input)?;
        Ok((rest, Token::Char(s)))
    }

    fn scan_escaped_literal(input: &str) -> IResult<&str, &str> {
        let (rest, s) = delimited(
            char('"'),
            recognize(many0(none_of("\""))),
            char('"')
        )(input)?;
        Ok((rest, s))
    }

    fn scan_literal(input: &str) -> IResult<&str, &str> {
        let (rest, s) = recognize(pair(
            one_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"),
            many0(one_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789._"))
        ))(input)?;
        Ok((rest, s))
    }

    fn scan_identifier(input: &str) -> IResult<&str, Token> {
        map(alt((Lexer::scan_literal, Lexer::scan_escaped_literal)), |s: &str| Token::Identifier(s.to_string()))(input)
    }
    
    fn scan_constant(input: &str) -> IResult<&str, Token> {
        map(preceded(
            char('$'),
            Lexer::scan_literal
            ),
            |s: &str| Token::Constant(s.to_string())
        )(input)
    }

    fn scan_register(input: &str) -> IResult<&str, Token> {
        map(preceded(
            char('%'),
            Lexer::scan_literal
            ),
            |s: &str| Token::Register(s.to_string())
        )(input)
    }

    fn skip_spaces(input: &str) -> IResult<&str, &str> {
        let chars = " \t\r\n";
        take_while(move |ch| chars.contains(ch))(input)
    }
    
    fn scan_other(input: &str) -> IResult<&str, Token> {
        alt((
            map(char('['), |ch| Token::Other(ch)),
            map(char(']'), |ch| Token::Other(ch)),
            map(char('('), |ch| Token::Other(ch)),
            map(char(')'), |ch| Token::Other(ch)),
            map(char(','), |ch| Token::Other(ch)),
        ))(input)
    }
    
    pub fn scan_line(input: &str) -> IResult<&str, Vec<Token>> {
        many0(preceded(
            Lexer::skip_spaces,
            alt((
                Lexer::scan_operator,
                Lexer::scan_integer_hex,
                Lexer::scan_integer_bin,
                Lexer::scan_integer_oct,
                Lexer::scan_integer_dec,
                Lexer::scan_integer_dec_neg,
                Lexer::scan_constant,
                Lexer::scan_identifier,
                Lexer::scan_register,
                Lexer::scan_value_history,
                Lexer::scan_escaped_char,
                Lexer::scan_other,
            )),
        ))(input)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_line() {
        assert_eq!(Lexer::scan_line("3 3 +"), Ok(("", vec![Token::Integer(3), Token::Integer(3), Token::Operator(Opcode::Add)])));
        assert_eq!(Lexer::scan_line("p 0x10"), Ok(("", vec![Token::Identifier("p".to_string()), Token::Integer(0x10)])));
    }

    #[test]
    fn test_value_history() {
        assert_eq!(Lexer::scan_value_history("$$"), Ok(("", Token::ValueHistory(None))));
        assert_eq!(Lexer::scan_value_history("$0"), Ok(("", Token::ValueHistory(Some(0)))));
        assert_eq!(Lexer::scan_value_history("$10"), Ok(("", Token::ValueHistory(Some(10)))));
    }

    #[test]
    fn test_parse_int_bin() {
        let pairs: Vec<(&str, Token)> = vec![
            ("0b0",          Token::Integer(0)),
            ("0b1",          Token::Integer(1)),
            ("0b11111111",   Token::Integer(255)),
            ("0b1111_1111",  Token::Integer(255)),
            ("0B11111111",   Token::Integer(255)),
        ];

        for pair in pairs {
            assert_eq!(Lexer::scan_integer_bin(pair.0), Ok(("", pair.1)));
        }
    }

    #[test]
    fn test_parse_int_hex() {
        let pairs: Vec<(&str, Token)> = vec![
            ("0x0",          Token::Integer(0)),
            ("0x00",         Token::Integer(0)),
            ("0xff",         Token::Integer(255)),
            ("0x100",        Token::Integer(256)),
            ("0xffff",       Token::Integer(65535)),
            ("0x10000",      Token::Integer(65536)),
            ("0xffffffff",   Token::Integer(0xffffffff)),
            ("0Xffffffff",   Token::Integer(0xffffffff)),
            ("0xffff_ffff",  Token::Integer(0xffffffff)),
        ];

        for pair in pairs {
            assert_eq!(Lexer::scan_integer_hex(pair.0), Ok(("", pair.1)));
        }
    }

    #[test]
    fn test_parse_int_oct() {
        let pairs: Vec<(&str, Token)> = vec![
            ("0o0",          Token::Integer(0)),
            ("0o1",          Token::Integer(1)),
            ("0O1",          Token::Integer(1)),
            ("0o777_777",    Token::Integer(0b111_111_111_111_111_111)),
        ];

        for pair in pairs {
            assert_eq!(Lexer::scan_integer_oct(pair.0), Ok(("", pair.1)));
        }
    }

    #[test]
    fn test_scan_int_dec() {
        let pairs: Vec<(&str, Token)> = vec![
            ("100",          Token::Integer(100)),
            ("65535",        Token::Integer(65535)),
            ("1_000_000",    Token::Integer(1000000)),
            ("0d0",          Token::Integer(0)),
            ("0d100",        Token::Integer(100)),
            ("0d65535",      Token::Integer(65535)),
            ("0D100",        Token::Integer(100)),
            ("0D65535",      Token::Integer(65535)),
        ];

        for pair in pairs {
            assert_eq!(Lexer::scan_integer_dec(pair.0), Ok(("", pair.1)));
        }
    }

    #[test]
    fn test_scan_int_dec_neg() {
        let pairs: Vec<(&str, Token)> = vec![
            ("_100",          Token::Integer(-100)),
            ("_65535",        Token::Integer(-65535)),
            ("_1_000_000",    Token::Integer(-1000000)),
            ("_0d0",          Token::Integer(0)),
            ("_0d100",        Token::Integer(-100)),
            ("_0d65535",      Token::Integer(-65535)),
            ("_0D100",        Token::Integer(-100)),
            ("_0D65535",      Token::Integer(-65535)),
        ];

        for pair in pairs {
            assert_eq!(Lexer::scan_integer_dec_neg(pair.0), Ok(("", pair.1)));
        }
    }
}