use std::io::{self, Read, Write};
use std::str;
use std::collections::HashMap;

use ansi_term::Color;
use ansi_term::Color::Fixed;

use crate::squeezer::{SqueezeAction, Squeezer};

const BUFFER_SIZE: usize = 256;

const COLOR_NULL: Color = Fixed(242); // grey
const COLOR_OFFSET: Color = Fixed(242); // grey
const COLOR_ASCII_PRINTABLE: Color = Color::Cyan;
const COLOR_ASCII_WHITESPACE: Color = Color::Green;
const COLOR_ASCII_OTHER: Color = Color::Purple;
const COLOR_NONASCII: Color = Color::Yellow;

pub enum ByteCategory {
    Null,
    AsciiPrintable,
    AsciiWhitespace,
    AsciiOther,
    NonAscii,
}

#[derive(Copy, Clone)]
struct Byte(u8);

impl Byte {
    fn category(self) -> ByteCategory {
        if self.0 == 0x00 {
            ByteCategory::Null
        } else if self.0.is_ascii_graphic() {
            ByteCategory::AsciiPrintable
        } else if self.0.is_ascii_whitespace() {
            ByteCategory::AsciiWhitespace
        } else if self.0.is_ascii() {
            ByteCategory::AsciiOther
        } else {
            ByteCategory::NonAscii
        }
    }

    fn color(self) -> &'static Color {
        use ByteCategory::*;

        match self.category() {
            Null => &COLOR_NULL,
            AsciiPrintable => &COLOR_ASCII_PRINTABLE,
            AsciiWhitespace => &COLOR_ASCII_WHITESPACE,
            AsciiOther => &COLOR_ASCII_OTHER,
            NonAscii => &COLOR_NONASCII,
        }
    }

    fn as_char(self) -> char {
        use ByteCategory::*;

        match self.category() {
            Null => '⌀',
            AsciiPrintable => self.0 as char,
            AsciiWhitespace if self.0 == 0x20 => ' ',
            AsciiWhitespace => '_',
            AsciiOther => '•',
            NonAscii => '×',
        }
    }
}

struct BorderElements {
    left_corner: char,
    horizontal_line: char,
    column_separator: char,
    right_corner: char,
}

pub enum BorderStyle {
    Unicode,
    Ascii,
    None,
}

impl BorderStyle {
    fn header_elems(&self) -> Option<BorderElements> {
        match self {
            BorderStyle::Unicode => Some(BorderElements {
                left_corner: '┌',
                horizontal_line: '─',
                column_separator: '┬',
                right_corner: '┐',
            }),
            BorderStyle::Ascii => Some(BorderElements {
                left_corner: '+',
                horizontal_line: '-',
                column_separator: '+',
                right_corner: '+',
            }),
            BorderStyle::None => None,
        }
    }

    fn footer_elems(&self) -> Option<BorderElements> {
        match self {
            BorderStyle::Unicode => Some(BorderElements {
                left_corner: '└',
                horizontal_line: '─',
                column_separator: '┴',
                right_corner: '┘',
            }),
            BorderStyle::Ascii => Some(BorderElements {
                left_corner: '+',
                horizontal_line: '-',
                column_separator: '+',
                right_corner: '+',
            }),
            BorderStyle::None => None,
        }
    }

    fn outer_sep(&self) -> char {
        match self {
            BorderStyle::Unicode => '│',
            BorderStyle::Ascii => '|',
            BorderStyle::None => ' ',
        }
    }

    fn inner_sep(&self) -> char {
        match self {
            BorderStyle::Unicode => '┊',
            BorderStyle::Ascii => '|',
            BorderStyle::None => ' ',
        }
    }
}

pub struct Printer {
    idx: u64,
    /// The raw bytes used as input for the current line.
    raw_line: Vec<String>,
    /// The buffered line built with each byte, ready to print to writer.
    buffer_line: Vec<u8>,
    writer: Vec<u8>,
    show_color: bool,
    border_style: BorderStyle,
    header_was_printed: bool,
    byte_hex_table: Vec<String>,
    byte_hex_bold_table: Vec<String>,
    byte_char_table: Vec<String>,
    byte_char_bold_table: Vec<String>,
    squeezer: Squeezer,
    display_offset: u64,
    memcache: HashMap<u64,u8>,
}

impl Printer {
    pub fn new(
        show_color: bool,
        border_style: BorderStyle,
        use_squeeze: bool,
    ) -> Printer {
        Printer {
            idx: 1,
            raw_line: vec![],
            buffer_line: vec![],
            writer: Vec::new(),
            show_color,
            border_style,
            header_was_printed: false,
            byte_hex_table: (0u8..=u8::max_value())
                .map(|i| {
                    let byte_hex = format!("{:02x} ", i);
                    if show_color {
                        Byte(i).color().paint(byte_hex).to_string()
                    } else {
                        byte_hex
                    }
                })
                .collect(),
            byte_hex_bold_table: (0u8..=u8::max_value())
                .map(|i| {
                    let byte_hex = format!("{:02x} ", i);
                    if show_color {
                        Byte(i).color().bold().paint(byte_hex).to_string()
                    } else {
                        byte_hex
                    }
                })
                .collect(),
            byte_char_table: (0u8..=u8::max_value())
                .map(|i| {
                    let byte_char = format!("{}", Byte(i).as_char());
                    if show_color {
                        Byte(i).color().paint(byte_char).to_string()
                    } else {
                        byte_char
                    }
                })
                .collect(),
            byte_char_bold_table: (0u8..=u8::max_value())
                .map(|i| {
                    let byte_char = format!("{}", Byte(i).as_char());
                    if show_color {
                        Byte(i).color().bold().paint(byte_char).to_string()
                    } else {
                        byte_char
                    }
                })
                .collect(),
            squeezer: Squeezer::new(use_squeeze),
            display_offset: 0,
            memcache: HashMap::<u64,u8>::new(),
        }
    }

    pub fn display_offset(&mut self, display_offset: u64) -> &mut Self {
        self.display_offset = display_offset;
        self
    }

    pub fn header(&mut self) {
        if let Some(border_elements) = self.border_style.header_elems() {
            let h = border_elements.horizontal_line;
            let h8 = h.to_string().repeat(8);
            let h25 = h.to_string().repeat(25);

            writeln!(
                self.writer,
                "{l}{h8}{c}{h25}{c}{h25}{c}{h8}{c}{h8}{r}",
                l = border_elements.left_corner,
                c = border_elements.column_separator,
                r = border_elements.right_corner,
                h8 = h8,
                h25 = h25
            )
            .ok();
        }
    }

    pub fn footer(&mut self) {
        if let Some(border_elements) = self.border_style.footer_elems() {
            let h = border_elements.horizontal_line;
            let h8 = h.to_string().repeat(8);
            let h25 = h.to_string().repeat(25);

            writeln!(
                self.writer,
                "{l}{h8}{c}{h25}{c}{h25}{c}{h8}{c}{h8}{r}",
                l = border_elements.left_corner,
                c = border_elements.column_separator,
                r = border_elements.right_corner,
                h8 = h8,
                h25 = h25
            )
            .ok();
        }
    }

    fn print_position_indicator(&mut self) {
        if !self.header_was_printed {
            self.header();
            self.header_was_printed = true;
        }

        let style = COLOR_OFFSET.normal();
        let byte_index = format!("{:08x}", self.idx - 1 + self.display_offset);
        let formatted_string = if self.show_color {
            format!("{}", style.paint(byte_index))
        } else {
            byte_index
        };
        let _ = write!(
            &mut self.buffer_line,
            "{}{}{} ",
            self.border_style.outer_sep(),
            formatted_string,
            self.border_style.outer_sep()
        );
    }

    pub fn print_byte(&mut self, b: u8) -> io::Result<()> {
        if self.idx % 16 == 1 {
            self.print_position_indicator();
        }

        let address = self.idx - 1 + self.display_offset;
        match self.memcache.get(&address) {
            Some(value) => {
                if *value == b {
                    write!(&mut self.buffer_line, "{}", self.byte_hex_table[b as usize])?;
                    self.raw_line.push(self.byte_char_table[b as usize].clone());
                } else {
                    write!(&mut self.buffer_line, "{}", self.byte_hex_bold_table[b as usize])?;
                    self.raw_line.push(self.byte_char_bold_table[b as usize].clone());
                }
            },
            _           => {
                write!(&mut self.buffer_line, "{}", self.byte_hex_bold_table[b as usize])?;
                self.raw_line.push(self.byte_char_bold_table[b as usize].clone());
            },
        }
        self.memcache.insert(address, b);

        self.squeezer.process(b, self.idx);

        match self.idx % 16 {
            8 => {
                let _ = write!(&mut self.buffer_line, "{} ", self.border_style.inner_sep());
            }
            0 => {
                self.print_textline()?;
            }
            _ => {}
        }

        self.idx += 1;

        Ok(())
    }

    pub fn print_textline(&mut self) -> io::Result<()> {
        let len = self.raw_line.len();

        if len == 0 {
            if self.squeezer.active() {
                self.print_position_indicator();
                let _ = writeln!(
                    &mut self.buffer_line,
                    "{0:1$}{4}{0:2$}{5}{0:3$}{4}{0:3$}{5}",
                    "",
                    24,
                    25,
                    8,
                    self.border_style.inner_sep(),
                    self.border_style.outer_sep(),
                );
                self.writer.write_all(&self.buffer_line)?;
            }
            return Ok(());
        }

        let squeeze_action = self.squeezer.action();

        if squeeze_action != SqueezeAction::Delete {
            if len < 8 {
                let _ = write!(
                    &mut self.buffer_line,
                    "{0:1$}{3}{0:2$}{4}",
                    "",
                    3 * (8 - len),
                    1 + 3 * 8,
                    self.border_style.inner_sep(),
                    self.border_style.outer_sep(),
                );
            } else {
                let _ = write!(
                    &mut self.buffer_line,
                    "{0:1$}{2}",
                    "",
                    3 * (16 - len),
                    self.border_style.outer_sep()
                );
            }

            let mut idx = 1;
            for s in self.raw_line.iter() {
                let _ = write!(
                    &mut self.buffer_line,
                    "{}",
                    //self.byte_char_table[b as usize]
                    s
                );

                if idx == 8 {
                    let _ = write!(&mut self.buffer_line, "{}", self.border_style.inner_sep());
                }

                idx += 1;
            }

            if len < 8 {
                let _ = writeln!(
                    &mut self.buffer_line,
                    "{0:1$}{3}{0:2$}{4}",
                    "",
                    8 - len,
                    8,
                    self.border_style.inner_sep(),
                    self.border_style.outer_sep(),
                );
            } else {
                let _ = writeln!(
                    &mut self.buffer_line,
                    "{0:1$}{2}",
                    "",
                    16 - len,
                    self.border_style.outer_sep()
                );
            }
        }

        match squeeze_action {
            SqueezeAction::Print => {
                self.buffer_line.clear();
                let style = COLOR_OFFSET.normal();
                let asterisk = if self.show_color {
                    format!("{}", style.paint("*"))
                } else {
                    String::from("*")
                };
                let _ = writeln!(
                    &mut self.buffer_line,
                    "{5}{0}{1:2$}{5}{1:3$}{6}{1:3$}{5}{1:4$}{6}{1:4$}{5}",
                    asterisk,
                    "",
                    7,
                    25,
                    8,
                    self.border_style.outer_sep(),
                    self.border_style.inner_sep(),
                );
            }
            SqueezeAction::Delete => self.buffer_line.clear(),
            SqueezeAction::Ignore => (),
        }

        self.writer.write_all(&self.buffer_line)?;

        self.raw_line.clear();
        self.buffer_line.clear();

        self.squeezer.advance();

        Ok(())
    }

    pub fn header_was_printed(&self) -> bool {
        self.header_was_printed
    }

    /// Loop through the given `Reader`, printing until the `Reader` buffer
    /// is exhausted.
    pub fn print_all<Reader: Read>(
        &mut self,
        mut reader: Reader,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut buffer = [0; BUFFER_SIZE];
        'mainloop: loop {
            let size = reader.read(&mut buffer)?;
            if size == 0 {
                break;
            }

            for b in &buffer[..size] {
                let res = self.print_byte(*b);

                if res.is_err() {
                    // Broken pipe
                    break 'mainloop;
                }
            }
        }

        // Finish last line
        self.print_textline().ok();

        if !self.header_was_printed() {
            self.header();
            writeln!(
                self.writer,
                "│        │ No content to print     │                         │        │        │"
            )
            .ok();
        }
        self.footer();

        let s: &str = str::from_utf8(&self.writer).unwrap();
        println!("{}", s);

        Ok(())
    }

    pub fn init_cache(&mut self, mem: &[u8]) {
        let mut address = self.display_offset;
        for b in mem {
            self.memcache.insert(address, *b);
            address = address + 1;
        }
    }

    pub fn reset(&mut self) {
        //self.writer.flush();
        self.writer.clear();
        self.idx = 1;
        self.header_was_printed = false;
    }
}

//#[cfg(test)]
//mod tests {
//    use std::io;
//    use std::str;
//
//    use super::*;
//
//    fn assert_print_all_output<Reader: Read>(input: Reader, expected_string: String) -> () {
//        let mut output = vec![];
//        let mut printer = Printer::new(&mut output, false, BorderStyle::Unicode, true);
//
//        printer.print_all(input).unwrap();
//
//        let actual_string: &str = str::from_utf8(&output).unwrap();
//        assert_eq!(actual_string, expected_string)
//    }
//
//    #[test]
//    fn empty_file_passes() {
//        let input = io::empty();
//        let expected_string = "\
//┌────────┬─────────────────────────┬─────────────────────────┬────────┬────────┐
//│        │ No content to print     │                         │        │        │
//└────────┴─────────────────────────┴─────────────────────────┴────────┴────────┘
//"
//        .to_owned();
//        assert_print_all_output(input, expected_string);
//    }
//
//    #[test]
//    fn short_input_passes() {
//        let input = io::Cursor::new(b"spam");
//        let expected_string = "\
//┌────────┬─────────────────────────┬─────────────────────────┬────────┬────────┐
//│00000000│ 73 70 61 6d             ┊                         │spam    ┊        │
//└────────┴─────────────────────────┴─────────────────────────┴────────┴────────┘
//"
//        .to_owned();
//        assert_print_all_output(input, expected_string);
//    }
//
//    #[test]
//    fn display_offset() {
//        let input = io::Cursor::new(b"spamspamspamspamspam");
//        let expected_string = "\
//┌────────┬─────────────────────────┬─────────────────────────┬────────┬────────┐
//│deadbeef│ 73 70 61 6d 73 70 61 6d ┊ 73 70 61 6d 73 70 61 6d │spamspam┊spamspam│
//│deadbeff│ 73 70 61 6d             ┊                         │spam    ┊        │
//└────────┴─────────────────────────┴─────────────────────────┴────────┴────────┘
//"
//        .to_owned();
//
//        let mut output = vec![];
//        let mut printer: Printer<Vec<u8>> =
//            Printer::new(&mut output, false, BorderStyle::Unicode, true);
//        printer.display_offset(0xdeadbeef);
//
//        printer.print_all(input).unwrap();
//
//        let actual_string: &str = str::from_utf8(&output).unwrap();
//        assert_eq!(actual_string, expected_string)
//    }
//}
